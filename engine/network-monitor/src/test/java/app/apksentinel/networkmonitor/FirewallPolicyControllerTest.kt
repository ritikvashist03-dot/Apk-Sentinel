package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallPolicyControllerTest {
    @Test
    fun uidScopedRuleConvertsOnlyWhenExplicitlyComposedAndMatchesExactUid() {
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), clock = clock(1_000L))
        assertEquals(
            FirewallPolicyMutationCode.APPLIED,
            controller.upsert(FirewallPolicyRuleDraft(
                id = "browser",
                action = FirewallPolicyAction.BLOCK,
                appUids = setOf(10_123),
                destinationCidrs = setOf("198.51.100.0/24"),
            )).code,
        )

        val translated = controller.snapshot().single()
        assertEquals("policy.browser", translated.id)
        assertEquals(setOf(10_123), translated.appUids)
        val engine = FirewallRuleEngine(controller) { "directive" }
        val matches = engine.evaluate(
            FirewallEvaluationContext(packet("198.51.100.4"), AppAttribution.Known("com.example.browser", 10_123)),
            atMillis = 1_000L,
            forwarderCanEnforceRules = true,
        )
        val otherUid = engine.evaluate(
            FirewallEvaluationContext(packet("198.51.100.4"), AppAttribution.Known("com.example.browser", 10_124)),
            atMillis = 1_000L,
            forwarderCanEnforceRules = true,
        )

        assertTrue(matches.requestsBlock)
        assertTrue(RuleCriterion.APP_UID in matches.matchedCriteria)
        assertFalse(otherUid.requestsBlock)
        assertEquals(FirewallDecisionReason.DEFAULT_ALLOW_NO_MATCHING_RULE, otherUid.reason)
    }

    @Test
    fun persistedCodecRoundTripLoadsAValidatedRuleWithoutPlaintextStoreAssumptions() {
        val store = InMemoryFirewallPolicySecureStore()
        val original = FirewallPolicyController(store, clock = clock(2_000L))
        original.upsert(FirewallPolicyRuleDraft(
            id = "dns",
            action = FirewallPolicyAction.BLOCK,
            appPackageNames = setOf("com.example.browser"),
            domainNames = setOf("Tracker.Example."),
            protocols = setOf(TransportProtocol.TCP),
            destinationPortRange = 443..443,
        ))

        val restored = FirewallPolicyController(store, clock = clock(2_500L)).current()
        val rule = restored.rules.single()
        assertEquals("dns", rule.id)
        assertEquals(setOf("tracker.example"), rule.domainNames)
        assertTrue(FirewallPolicyUnsupportedScope.DOMAIN_DESTINATION_UNAVAILABLE in rule.unsupportedScopes)
        assertEquals(FirewallPolicySaveState.SAVED, restored.saveState)
        assertEquals(FirewallPolicyActivity.UNSUPPORTED_SCOPE, restored.statuses.single().activity)
        assertTrue(FirewallPolicyController(store, clock = clock(2_500L)).snapshot().isEmpty())
    }

    @Test
    fun domainRuleActivatesOnlyWithAuthenticatedPacketBoundCapability() {
        val controller = FirewallPolicyController(
            InMemoryFirewallPolicySecureStore(),
            clock = clock(2_000L),
            domainDestinationCapability = AuthenticatedDomainDestinationCapability { domains ->
                domains == setOf("tracker.example")
            },
        )
        assertEquals(
            FirewallPolicyMutationCode.APPLIED,
            controller.upsert(
                FirewallPolicyRuleDraft(
                    "dns",
                    FirewallPolicyAction.BLOCK,
                    appPackageNames = setOf("com.example.browser"),
                    domainNames = setOf("tracker.example"),
                ),
            ).code,
        )

        assertEquals(FirewallPolicyActivity.ACTIVE, controller.current().statuses.single().activity)
        assertEquals(listOf("policy.dns"), controller.snapshot().map(FirewallRule::id))
    }

    @Test
    fun validationRejectsMalformedUtf8BidiAndUnboundedScopeInput() {
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), clock = clock(1L))
        val result = controller.upsert(FirewallPolicyRuleDraft(
            id = "bad\u202Eid",
            action = FirewallPolicyAction.BLOCK,
            appPackageNames = setOf("com.example.app"),
            domainNames = setOf("bad\u202Edomain.example"),
            destinationCidrs = (0 until 33).map { "198.51.100.$it/32" }.toSet(),
        ))

        assertEquals(FirewallPolicyMutationCode.VALIDATION_FAILED, result.code)
        assertTrue(FirewallPolicyValidationCode.INVALID_ID in result.validation)
        assertTrue(FirewallPolicyValidationCode.INVALID_DOMAIN in result.validation)
        assertTrue(FirewallPolicyValidationCode.TOO_MANY_VALUES in result.validation)
        assertTrue(controller.snapshot().isEmpty())
    }

    @Test
    fun temporaryAllowFailsClosedOnClockRollbackButTemporaryBlockIsRetained() {
        val time = MutableClock(10_000L)
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), time)
        controller.upsert(FirewallPolicyRuleDraft(
            id = "allow-temporary",
            action = FirewallPolicyAction.ALLOW,
            appUids = setOf(10_123),
            expiresAtMillis = 20_000L,
        ))
        controller.upsert(FirewallPolicyRuleDraft(
            id = "block-temporary",
            action = FirewallPolicyAction.BLOCK,
            appUids = setOf(10_124),
            expiresAtMillis = 20_000L,
        ))
        time.millis = 9_999L

        val byId = controller.current().statuses.associateBy(FirewallPolicyRuleStatus::ruleId)
        assertFalse(byId.getValue("allow-temporary").active)
        assertEquals(FirewallPolicyActivity.TEMPORARY_ALLOW_CLOCK_LIMITATION, byId.getValue("allow-temporary").activity)
        assertTrue(byId.getValue("block-temporary").active)
        assertEquals(FirewallPolicyActivity.ACTIVE_BLOCK_RETAINED_WITH_UNTRUSTED_CLOCK, byId.getValue("block-temporary").activity)
        assertEquals(listOf("policy.block-temporary"), controller.snapshot().map(FirewallRule::id))
    }

    @Test
    fun broadAndSystemCriticalBlocksRemainVisibleButDoNotSilentlyActivate() {
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), clock = clock(1_000L))
        controller.upsert(FirewallPolicyRuleDraft(id = "broad", action = FirewallPolicyAction.BLOCK))
        controller.upsert(FirewallPolicyRuleDraft(id = "system", action = FirewallPolicyAction.BLOCK, appUids = setOf(1_000)))

        val status = controller.current().statuses.associateBy(FirewallPolicyRuleStatus::ruleId)
        assertEquals(FirewallPolicyActivity.BROAD_BLOCK_SAFETY_LIMITATION, status.getValue("broad").activity)
        assertTrue(FirewallPolicyLimitation.BROAD_BLOCK_REQUIRES_CAPTIVE_PORTAL_AND_SYSTEM_CRITICAL_CLASSIFICATION in status.getValue("broad").limitations)
        assertEquals(FirewallPolicyActivity.SYSTEM_CRITICAL_SCOPE_LIMITATION, status.getValue("system").activity)
        assertTrue(FirewallPolicyLimitation.SYSTEM_CRITICAL_UID_REQUIRES_HOST_CLASSIFICATION in status.getValue("system").limitations)
        assertTrue(controller.snapshot().isEmpty())
    }

    @Test
    fun onlyMatchingForwarderConfirmationIncrementsHitState() {
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), clock = clock(4_000L))
        controller.upsert(FirewallPolicyRuleDraft("block", FirewallPolicyAction.BLOCK, appUids = setOf(10_123)))
        val decision = FirewallDecision(
            directiveId = "d1",
            requestedAction = FirewallAction.BLOCK,
            matchedRuleId = "policy.block",
            reason = FirewallDecisionReason.MATCHED_BLOCK_RULE,
            enforcement = FirewallEnforcementState.PENDING_FORWARDER_CONFIRMATION,
        )

        assertEquals(
            FirewallPolicyHitCode.NOT_A_CONFIRMED_MATCH,
            controller.recordConfirmedOutcome(decision, FirewallEnforcementResult("d1", FirewallEnforcementOutcome.FAILED, "x")).code,
        )
        assertEquals(
            FirewallPolicyHitCode.RECORDED,
            controller.recordConfirmedOutcome(decision, FirewallEnforcementResult("d1", FirewallEnforcementOutcome.BLOCKED, "x")).code,
        )
        val status = controller.current().statuses.single()
        assertEquals(1L, status.confirmedHitCount)
        assertEquals(4_000L, status.lastConfirmedHitAtMillis)
    }

    @Test
    fun undoIsRevisionBoundAndEmergencyReleaseDoesNotDestroySavedRules() {
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), clock = clock(5_000L), tokenSource = { "token-${System.nanoTime()}" })
        val create = controller.upsert(FirewallPolicyRuleDraft("rule", FirewallPolicyAction.BLOCK, appUids = setOf(10_123)))
        val disable = controller.disableAll()
        val stale = controller.undo(requireNotNull(create.undoToken))
        assertEquals(FirewallPolicyMutationCode.UNDO_STALE, stale.code)
        assertNotNull(disable.undoToken)

        assertEquals(FirewallPolicyMutationCode.APPLIED, controller.emergencyRelease().code)
        val duringRelease = controller.current()
        assertTrue(duringRelease.emergencyReleaseActive)
        assertEquals(1, duringRelease.rules.size)
        assertTrue(controller.snapshot().isEmpty())
        assertEquals(FirewallPolicyMutationCode.APPLIED, controller.clearEmergencyRelease().code)
        assertFalse(controller.current().emergencyReleaseActive)
    }

    @Test
    fun unsupportedImportedScopeIsSavedForDisclosureButNeverConverted() {
        val controller = FirewallPolicyController(InMemoryFirewallPolicySecureStore(), clock = clock(6_000L))
        val result = controller.upsert(FirewallPolicyRuleDraft(
            id = "country",
            action = FirewallPolicyAction.BLOCK,
            appUids = setOf(10_123),
            unsupportedScopes = setOf(FirewallPolicyUnsupportedScope.COUNTRY),
        ))

        assertEquals(FirewallPolicyMutationCode.APPLIED, result.code)
        assertEquals(FirewallPolicyActivity.UNSUPPORTED_SCOPE, controller.current().statuses.single().activity)
        assertNull(controller.snapshot().singleOrNull())
    }

    private fun packet(destination: String): PacketMetadata = PacketMetadata(
        ipVersion = IpVersion.IPV4,
        ipProtocolNumber = 6,
        transportProtocol = TransportProtocol.TCP,
        source = NetworkEndpoint("192.0.2.1", 40_000),
        destination = NetworkEndpoint(destination, 443),
        declaredIpPacketBytes = 40,
        capturedPacketBytes = 40,
    )

    private fun clock(millis: Long): FirewallPolicyClock = FirewallPolicyClock { FirewallPolicyClockReading.Available(millis) }

    private class MutableClock(var millis: Long) : FirewallPolicyClock {
        override fun read(): FirewallPolicyClockReading = FirewallPolicyClockReading.Available(millis)
    }
}
