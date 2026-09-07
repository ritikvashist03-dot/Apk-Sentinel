package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallRuleEngineTest {
    @Test
    fun blockRuleReportsPendingUntilForwarderConfirmsIt() {
        val rule = FirewallRule(
            id = "block-browser-https",
            action = FirewallAction.BLOCK,
            priority = 10,
            appPackageNames = setOf("com.example.browser"),
            destinationCidrs = setOf(requireNotNull(IpCidr.parse("198.51.100.0/24"))),
            protocols = setOf(TransportProtocol.TCP),
            destinationPortRange = 443..443,
        )
        val engine = FirewallRuleEngine(InMemoryFirewallRuleProvider(listOf(rule))) { "directive-1" }

        val decision = engine.evaluate(
            context = FirewallEvaluationContext(
                metadata = tcpMetadata(destination = "198.51.100.42", port = 443),
                attribution = AppAttribution.Known("com.example.browser"),
            ),
            atMillis = 100L,
            forwarderCanEnforceRules = true,
        )

        assertTrue(decision.requestsBlock)
        assertEquals("block-browser-https", decision.matchedRuleId)
        assertEquals(FirewallDecisionReason.MATCHED_BLOCK_RULE, decision.reason)
        assertEquals(FirewallEnforcementState.PENDING_FORWARDER_CONFIRMATION, decision.enforcement)
        assertTrue(RuleCriterion.APP in decision.matchedCriteria)
        assertTrue(RuleCriterion.DESTINATION_CIDR in decision.matchedCriteria)
        assertTrue(RuleCriterion.DESTINATION_PORT in decision.matchedCriteria)
    }

    @Test
    fun higherPriorityAllowMakesRuleConflictVisible() {
        val blockAll = FirewallRule(id = "block-all", action = FirewallAction.BLOCK, priority = 1)
        val allowBrowser = FirewallRule(
            id = "allow-browser",
            action = FirewallAction.ALLOW,
            priority = 2,
            appPackageNames = setOf("com.example.browser"),
        )
        val engine = FirewallRuleEngine(InMemoryFirewallRuleProvider(listOf(blockAll, allowBrowser))) { "directive-2" }

        val decision = engine.evaluate(
            FirewallEvaluationContext(tcpMetadata(), AppAttribution.Known("com.example.browser")),
            atMillis = 100L,
            forwarderCanEnforceRules = true,
        )

        assertEquals(FirewallAction.ALLOW, decision.requestedAction)
        assertEquals(FirewallDecisionReason.MATCHED_ALLOW_RULE, decision.reason)
        assertEquals(FirewallEnforcementState.NOT_APPLICABLE, decision.enforcement)
        assertEquals(listOf("block-all"), decision.competingRuleIds)
    }

    @Test
    fun domainRuleDoesNotPretendItCanUseHashedDefaultDnsData() {
        val domainRule = FirewallRule(
            id = "block-domain",
            action = FirewallAction.BLOCK,
            domainNames = setOf("tracker.example"),
        )
        val engine = FirewallRuleEngine(InMemoryFirewallRuleProvider(listOf(domainRule))) { "directive-3" }

        val decision = engine.evaluate(
            FirewallEvaluationContext(tcpMetadata(), AppAttribution.Unknown(AttributionUnavailableReason.NOT_ATTEMPTED)),
            atMillis = 100L,
            forwarderCanEnforceRules = true,
        )

        assertFalse(decision.requestsBlock)
        assertEquals(FirewallDecisionReason.DEFAULT_ALLOW_DOMAIN_RULE_NOT_EVALUABLE, decision.reason)
    }

    @Test
    fun enforcementResultChangesOnlyTheReportedStateForItsDirective() {
        val decision = FirewallDecision(
            directiveId = "directive-4",
            requestedAction = FirewallAction.BLOCK,
            matchedRuleId = "rule",
            reason = FirewallDecisionReason.MATCHED_BLOCK_RULE,
            enforcement = FirewallEnforcementState.PENDING_FORWARDER_CONFIRMATION,
        )

        val confirmed = decision.withEnforcementResult(
            FirewallEnforcementResult("directive-4", FirewallEnforcementOutcome.BLOCKED, "Forwarder blocked packet."),
        )

        assertEquals(FirewallEnforcementState.CONFIRMED_BLOCKED, confirmed.enforcement)
    }

    private fun tcpMetadata(
        destination: String = "203.0.113.7",
        port: Int = 443,
    ): PacketMetadata = PacketMetadata(
        ipVersion = IpVersion.IPV4,
        ipProtocolNumber = 6,
        transportProtocol = TransportProtocol.TCP,
        source = NetworkEndpoint("192.0.2.10", 50_000),
        destination = NetworkEndpoint(destination, port),
        declaredIpPacketBytes = 40,
        capturedPacketBytes = 40,
    )
}
