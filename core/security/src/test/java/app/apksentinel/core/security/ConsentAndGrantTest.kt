package app.apksentinel.core.security

import app.apksentinel.core.model.ConsentDecision
import app.apksentinel.core.model.ConsentPurpose
import app.apksentinel.core.model.ConsentReceipt
import app.apksentinel.core.model.ConsentReceiptId
import app.apksentinel.core.model.ConsentScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConsentAndGrantTest {
    @Test
    fun ledgerDoesNotReuseConsentAcrossPurposesAndHonorsRevocation() {
        val ledger = InMemoryConsentLedger()
        val scope = ConsentScope("vpn.control")
        val granted = receipt(
            id = "receipt-1",
            purpose = ConsentPurpose.NETWORK_PROTECTION,
            decision = ConsentDecision.GRANTED,
            scope = scope,
            decidedAt = 100,
        )

        assertTrue(ledger.record(granted) is ConsentRecordResult.Recorded)
        assertTrue(ledger.isGranted(ConsentPurpose.NETWORK_PROTECTION, setOf(scope), 100))
        assertFalse(ledger.isGranted(ConsentPurpose.NETWORK_MONITORING, setOf(scope), 100))

        val revoked = receipt(
            id = "receipt-2",
            purpose = ConsentPurpose.NETWORK_PROTECTION,
            decision = ConsentDecision.REVOKED,
            scope = scope,
            decidedAt = 200,
        )
        assertTrue(ledger.record(revoked) is ConsentRecordResult.Recorded)
        assertFalse(ledger.isGranted(ConsentPurpose.NETWORK_PROTECTION, setOf(scope), 200))
    }

    @Test
    fun ledgerRejectsEqualTimestampDecisionsForTheSamePurpose() {
        val ledger = InMemoryConsentLedger()
        val scope = ConsentScope("export.summary")
        assertTrue(
            ledger.record(
                receipt(
                    id = "receipt-1",
                    purpose = ConsentPurpose.SENSITIVE_EXPORT,
                    decision = ConsentDecision.GRANTED,
                    scope = scope,
                    decidedAt = 100,
                ),
            ) is ConsentRecordResult.Recorded,
        )

        val result = ledger.record(
            receipt(
                id = "receipt-2",
                purpose = ConsentPurpose.SENSITIVE_EXPORT,
                decision = ConsentDecision.REVOKED,
                scope = scope,
                decidedAt = 100,
            ),
        )

        assertEquals(
            ConsentRecordRejection.NON_MONOTONIC_PURPOSE_TIMESTAMP,
            (result as ConsentRecordResult.Rejected).reason,
        )
    }

    @Test
    fun sessionGrantExpiresAndIsInvalidatedWhenConsentIsRevoked() {
        var now = 1_000L
        val scope = ConsentScope("vpn.control")
        val ledger = InMemoryConsentLedger()
        ledger.record(
            receipt(
                id = "receipt-1",
                purpose = ConsentPurpose.NETWORK_PROTECTION,
                decision = ConsentDecision.GRANTED,
                scope = scope,
                decidedAt = now,
            ),
        )
        val ids = ArrayDeque(listOf("1234567890abcdef", "abcdef1234567890"))
        val grants = SensitiveFeatureGrantManager(
            consentLedger = ledger,
            clock = EpochClock { now },
            idGenerator = OpaqueIdGenerator { ids.removeFirst() },
            maximumGrantDurationMillis = 500,
        )
        val session = SensitiveSessionId("session-value")
        val issued = grants.issue(
            SensitiveFeatureGrantRequest(
                sessionId = session,
                feature = SensitiveFeature.NETWORK_PROTECTION,
                requiredScopes = setOf(scope),
                expiresAtEpochMillis = 1_100,
            ),
        ) as SensitiveGrantIssueResult.Granted

        assertTrue(grants.isActive(issued.grant.id, session, SensitiveFeature.NETWORK_PROTECTION))
        now = 1_100
        assertEquals(SensitiveGrantState.EXPIRED, grants.status(issued.grant.id, session).state)

        now = 1_200
        val second = grants.issue(
            SensitiveFeatureGrantRequest(
                sessionId = session,
                feature = SensitiveFeature.NETWORK_PROTECTION,
                requiredScopes = setOf(scope),
                expiresAtEpochMillis = 1_300,
            ),
        ) as SensitiveGrantIssueResult.Granted
        ledger.record(
            receipt(
                id = "receipt-2",
                purpose = ConsentPurpose.NETWORK_PROTECTION,
                decision = ConsentDecision.REVOKED,
                scope = scope,
                decidedAt = now,
            ),
        )

        assertEquals(SensitiveGrantState.REVOKED, grants.status(second.grant.id, session).state)
        assertFalse(grants.isActive(second.grant.id, session, SensitiveFeature.NETWORK_PROTECTION))
        assertFalse(second.grant.toString().contains(second.grant.id.value))
        assertFalse(session.toString().contains(session.value))
    }

    private fun receipt(
        id: String,
        purpose: ConsentPurpose,
        decision: ConsentDecision,
        scope: ConsentScope,
        decidedAt: Long,
    ): ConsentReceipt = ConsentReceipt(
        id = ConsentReceiptId(id),
        purpose = purpose,
        decision = decision,
        disclosureRevision = "disclosure-v1",
        policyRevision = "privacy-v1",
        scopes = setOf(scope),
        presentedAtEpochMillis = decidedAt,
        decidedAtEpochMillis = decidedAt,
    )
}
