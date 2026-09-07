package app.apksentinel.core.reporting

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalReportRendererTest {
    private val report = LocalReport(
        reportType = "apk",
        generatedAtMillis = 1L,
        sections = listOf(
            ReportSection(
                "one",
                "Identity",
                listOf(
                    ReportField("package", "Package", "a.b"),
                    ReportField("hash", "Hash", "abc", ReportSensitivity.TECHNICAL),
                    ReportField("payload", "Payload", "secret", ReportSensitivity.SENSITIVE),
                    ReportField("quote", "Quote", "a\"b\n"),
                    ReportField("formula", "Formula", "=HYPERLINK(\"https://example.invalid\")"),
                ),
            ),
        ),
        limitations = listOf("Source metadata can be incomplete."),
        notes = listOf(
            ReportNote("technical note", ReportSensitivity.TECHNICAL),
            ReportNote("sensitive note", ReportSensitivity.SENSITIVE),
        ),
    )

    @Test
    fun sensitiveFieldsRequireBothExplicitSwitchAndAuthorization() {
        val defaultJson = LocalReportRenderer.json(report)
        assertTrue(defaultJson.contains("hash"))
        assertFalse(defaultJson.contains("secret"))
        assertFalse(defaultJson.contains("sensitive note"))
        assertTrue(defaultJson.contains("\"redacted\":true"))
        assertTrue(defaultJson.contains("\"sensitiveContentOmitted\":true"))

        val switchedOnly = LocalReportRenderer.json(report, ReportExportPolicy(includeSensitive = true))
        assertFalse(switchedOnly.contains("secret"))

        val authorized = LocalReportRenderer.json(
            report,
            ReportExportPolicy(
                includeSensitive = true,
                sensitiveExportAuthorization = SensitiveExportAuthorization.USER_CONFIRMED,
            ),
        )
        assertTrue(authorized.contains("secret"))
        assertTrue(authorized.contains("sensitive note"))
        assertTrue(authorized.contains("\"redacted\":false"))
        assertTrue(authorized.contains("\"sensitiveContentOmitted\":false"))
    }

    @Test
    fun jsonEscapesControlsQuotesAndMalformedSurrogates() {
        val unsafe = LocalReport(
            reportType = "test\u0001",
            generatedAtMillis = -1L,
            sections = listOf(
                ReportSection("id", "Title\u2028suffix", listOf(
                    ReportField("key", "Quote", "a\"b\n\u0001\uD800"),
                )),
            ),
        )

        val json = LocalReportRenderer.json(unsafe)
        assertTrue(json.contains("\\\"b "))
        assertTrue(json.contains("\\u2028"))
        assertTrue(json.contains("\\ufffd"))
        assertFalse(json.contains("\u0001"))
        assertTrue(json.contains("\"generatedAtMillis\":0"))
    }

    @Test
    fun csvEscapesQuotesAndNeutralizesSpreadsheetFormulas() {
        val csv = LocalReportRenderer.csv(report, ReportExportPolicy(includeTechnical = false))
        assertTrue(csv.contains("\"a\"\"b\""))
        assertTrue(csv.contains("\"'=HYPERLINK(\"\"https://example.invalid\"\")\""))
        assertFalse(csv.contains("hash"))
        assertFalse(csv.contains("secret"))
    }

    @Test
    fun policyBoundsOutputAndMarksItTruncated() {
        val bounded = LocalReportRenderer.json(
            report.copy(
                sections = listOf(
                    ReportSection("one", "One", listOf(ReportField("a", "A", "1"), ReportField("b", "B", "2"))),
                    ReportSection("two", "Two", listOf(ReportField("c", "C", "3"))),
                ),
                limitations = listOf("one", "two"),
            ),
            ReportExportPolicy(maximumSections = 1, maximumFields = 1, maximumNotes = 1),
        )
        assertTrue(bounded.contains("\"truncated\":true"))
        assertTrue(bounded.contains("\"key\":\"a\""))
        assertFalse(bounded.contains("\"key\":\"b\""))
        assertFalse(bounded.contains("\"key\":\"c\""))
    }

    @Test
    fun valueLimitMarksOutputTruncated() {
        val bounded = LocalReportRenderer.json(
            report,
            ReportExportPolicy(maximumValueCodePoints = 4),
        )

        assertTrue(bounded.contains("\"truncated\":true"))
    }

    @Test
    fun pcapMetadataNeverContainsPayloadOrIdentityButCanUseSensitivityPolicy() {
        val pcap = PcapMetadataReportFactory.create(
            PcapMetadata(
                captureFormat = PcapCaptureFormat.PCAPNG,
                startedAtMillis = 10L,
                endedAtMillis = 20L,
                packetCount = 2L,
                capturedByteCount = 128L,
                applicationCount = 1,
                destinationCount = 1,
                sourceContainedPayloads = true,
                fileSha256 = "a".repeat(64),
            ),
            generatedAtMillis = 30L,
            text = PcapMetadataReportText(
                captureSummary = "Capture summary",
                captureFormat = "Capture format",
                packetsObserved = "Packets observed",
                capturedBytes = "Captured bytes",
                sourceIncludedPayloads = "Source capture included payloads",
                captureStarted = "Capture started",
                captureEnded = "Capture ended",
                observedApplications = "Observed applications",
                observedDestinations = "Observed destinations",
                captureFileSha256 = "Capture file SHA-256",
                metadataOnlyLimitation = "Metadata only",
                payloadSharingWarning = "Review before sharing",
            ),
        )

        val defaultJson = LocalReportRenderer.json(pcap)
        assertTrue(defaultJson.contains("pcap_metadata"))
        assertTrue(defaultJson.contains("file_sha256"))
        assertFalse(defaultJson.contains("started_at_millis"))
        assertFalse(defaultJson.contains("application_count"))
        assertFalse(defaultJson.contains("packet_payload"))

        val authorizedJson = LocalReportRenderer.json(
            pcap,
            ReportExportPolicy(
                includeSensitive = true,
                sensitiveExportAuthorization = SensitiveExportAuthorization.USER_CONFIRMED,
            ),
        )
        assertTrue(authorizedJson.contains("started_at_millis"))
        assertTrue(authorizedJson.contains("application_count"))
    }

    @Test
    fun pcapDigestFieldCannotCarryArbitraryText() {
        var rejected = false
        try {
            PcapMetadata(
                captureFormat = PcapCaptureFormat.PCAP,
                startedAtMillis = 1L,
                endedAtMillis = 2L,
                packetCount = 0L,
                capturedByteCount = 0L,
                applicationCount = 0,
                destinationCount = 0,
                sourceContainedPayloads = false,
                fileSha256 = "C:\\Users\\private\\capture.pcap",
            )
        } catch (_: IllegalArgumentException) {
            rejected = true
        }

        assertTrue(rejected)
    }

    @Test
    fun retentionPlannerOnlyDescribesAppOwnedCleanup() {
        assertEquals(
            LocalReportRetentionDecision.DeleteNow,
            LocalReportRetentionPlanner.decision(createdAtMillis = 100L, nowMillis = 100L),
        )
        assertEquals(
            LocalReportRetentionDecision.KeepUntil(200L),
            LocalReportRetentionPlanner.decision(
                createdAtMillis = 100L,
                nowMillis = 199L,
                policy = LocalReportRetentionPolicy(keepAppOwnedArtifactsForMillis = 100L),
            ),
        )
    }
}
