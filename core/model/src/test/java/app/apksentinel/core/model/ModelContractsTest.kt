package app.apksentinel.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModelContractsTest {
    @Test
    fun confidenceMapsScoresToStableLevels() {
        assertEquals(ConfidenceLevel.VERY_LOW, Confidence(0, "No corroboration").level)
        assertEquals(ConfidenceLevel.MODERATE, Confidence(55, "Two independent observations").level)
        assertEquals(ConfidenceLevel.VERY_HIGH, Confidence(100, "Direct platform result").level)
    }

    @Test
    fun consentReceiptIsPurposeScopedAndExpiryAware() {
        val receipt = ConsentReceipt(
            id = ConsentReceiptId("receipt-1"),
            purpose = ConsentPurpose.NETWORK_MONITORING,
            decision = ConsentDecision.GRANTED,
            disclosureRevision = "network-disclosure-v1",
            policyRevision = "privacy-v1",
            scopes = setOf(ConsentScope("destination.metadata"), ConsentScope("app.identity")),
            presentedAtEpochMillis = 100,
            decidedAtEpochMillis = 110,
            expiresAtEpochMillis = 200,
        )

        assertEquals(
            listOf(ConsentScope("app.identity"), ConsentScope("destination.metadata")),
            receipt.canonicalScopes,
        )
        assertTrue(receipt.isGrantedAt(110))
        assertFalse(receipt.isGrantedAt(200))
        assertEquals(ConsentPurpose.NETWORK_MONITORING, receipt.purpose)
    }

    @Test
    fun riskFindingsRequireEvidenceAndPreserveObservationDistinction() {
        val finding = RiskFinding(
            id = RiskFindingId("finding-1"),
            title = "Unusual requested permission",
            observation = "The package requests a high-risk permission.",
            interpretation = "The permission warrants review in context.",
            context = "Manifest scan",
            severity = RiskSeverity.MEDIUM,
            confidence = Confidence(60, "Manifest declaration is direct evidence."),
            evidenceIds = setOf(EvidenceId("evidence-1")),
            recommendation = "Review whether the permission is expected.",
            limitations = listOf("The app's runtime behavior was not observed."),
            detectedAtEpochMillis = 1,
        )

        assertEquals("The package requests a high-risk permission.", finding.observation)
        assertEquals("The permission warrants review in context.", finding.interpretation)
    }

    @Test
    fun auditMetadataIsOrderedAndDoesNotRenderItsValues() {
        val metadata = AuditMetadata.fromPublicFields(
            mapOf("result" to "allowed", "purpose" to "network_monitoring"),
        )

        assertEquals(listOf("purpose", "result"), metadata.asMap().keys.toList())
        assertFalse(metadata.toString().contains("network_monitoring"))
    }
}
