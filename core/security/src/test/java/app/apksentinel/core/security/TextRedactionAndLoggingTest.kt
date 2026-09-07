package app.apksentinel.core.security

import app.apksentinel.core.model.RedactionPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TextRedactionAndLoggingTest {
    @Test
    fun filenameAndDisplayNormalizationRemoveTraversalAndBidiControls() {
        val filename = SafeTextNormalizer.normalizeFileName("../CON\u202Egpj.exe")
        val reserved = SafeTextNormalizer.normalizeFileName("CON.txt")
        val display = SafeTextNormalizer.normalizeDisplayText("Invoice\u202Egpj.exe\n")

        assertFalse(filename.contains('/'))
        assertFalse(filename.contains('\\'))
        assertFalse(filename.contains('\u202E'))
        assertEquals("_CON.txt", reserved)
        assertEquals("Invoice gpj.exe", display)
    }

    @Test
    fun standardRedactionRemovesCommonSecretsAndProducesSafeAuditMetadata() {
        val original = "Authorization: Bearer top-secret user@example.com 10.0.0.1 C:\\Users\\Jane\\private.txt"
        val redacted = RedactionHelpers.redactText(original, RedactionPolicy.Standard)
        val audit = RedactionHelpers.redactAuditMetadata(
            mapOf(
                "Authorization" to "top-secret",
                "Result Detail" to "ok",
            ),
        )

        assertFalse(redacted.contains("top-secret"))
        assertFalse(redacted.contains("user@example.com"))
        assertFalse(redacted.contains("10.0.0.1"))
        assertFalse(redacted.contains("private.txt"))
        assertEquals("[redacted]", audit.asMap().getValue("authorization"))
        assertEquals("ok", audit.asMap().getValue("result_detail"))
    }

    @Test
    fun safeLoggerNeverPassesRawMetadataToItsSink() {
        val messages = mutableListOf<String>()
        val logger = RedactingSafeLogger(
            sink = SafeLogSink { _, message -> messages += message },
        )

        logger.log(
            SafeLogLevel.INFO,
            "invalid event with spaces",
            mapOf("authorization" to "top-secret"),
        )

        assertEquals(1, messages.size)
        assertTrue(messages.single().startsWith("security_event "))
        assertFalse(messages.single().contains("top-secret"))
        assertTrue(messages.single().contains("[redacted]"))
    }
}
