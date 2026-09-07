package app.apksentinel.core.reporting

/**
 * Metadata-only representation of a capture. There is intentionally no field
 * for packets, payload bytes, destinations, app IDs, file paths, or raw PCAP
 * content. A PCAP binary must be handled by an explicit, separately-consented
 * export path outside this report renderer.
 */
data class PcapMetadata(
    val captureFormat: PcapCaptureFormat,
    val startedAtMillis: Long,
    val endedAtMillis: Long,
    val packetCount: Long,
    val capturedByteCount: Long,
    val applicationCount: Int,
    val destinationCount: Int,
    val sourceContainedPayloads: Boolean,
    val fileSha256: String? = null,
) {
    init {
        require(startedAtMillis >= 0L)
        require(endedAtMillis >= startedAtMillis)
        require(packetCount >= 0L)
        require(capturedByteCount >= 0L)
        require(applicationCount >= 0)
        require(destinationCount >= 0)
        require(fileSha256 == null || SHA256_PATTERN.matches(fileSha256)) {
            "fileSha256 must be a lower-case SHA-256 digest when present."
        }
    }

    private companion object {
        val SHA256_PATTERN = Regex("^[0-9a-f]{64}$")
    }
}

enum class PcapCaptureFormat { PCAP, PCAPNG, METADATA_ONLY }

/**
 * Host-supplied display text keeps the pure reporting module independent of
 * Android resources while making localization mandatory at the call site.
 * Stable schema identifiers and enum values remain language-neutral.
 */
data class PcapMetadataReportText(
    val captureSummary: String,
    val captureFormat: String,
    val packetsObserved: String,
    val capturedBytes: String,
    val sourceIncludedPayloads: String,
    val captureStarted: String,
    val captureEnded: String,
    val observedApplications: String,
    val observedDestinations: String,
    val captureFileSha256: String,
    val metadataOnlyLimitation: String,
    val payloadSharingWarning: String,
)

/**
 * Produces a report that is safe by default: timing and cardinality details
 * are Sensitive, the digest is Technical, and no capture payload can enter the
 * model. A sourceContainingPayloads=true warning is informational only; it
 * never serializes the payload itself.
 */
object PcapMetadataReportFactory {
    fun create(
        metadata: PcapMetadata,
        generatedAtMillis: Long,
        text: PcapMetadataReportText,
    ): LocalReport {
        require(generatedAtMillis >= 0L) { "generatedAtMillis cannot be negative." }
        return LocalReport(
            reportType = "pcap_metadata",
            generatedAtMillis = generatedAtMillis,
            sections = listOf(
                ReportSection(
                    id = "capture_summary",
                    title = text.captureSummary,
                    fields = buildList {
                        add(ReportField("format", text.captureFormat, metadata.captureFormat.name))
                        add(ReportField("packet_count", text.packetsObserved, metadata.packetCount.toString()))
                        add(ReportField("captured_bytes", text.capturedBytes, metadata.capturedByteCount.toString()))
                        add(ReportField("source_included_payloads", text.sourceIncludedPayloads, metadata.sourceContainedPayloads.toString()))
                        add(ReportField("started_at_millis", text.captureStarted, metadata.startedAtMillis.toString(), ReportSensitivity.SENSITIVE))
                        add(ReportField("ended_at_millis", text.captureEnded, metadata.endedAtMillis.toString(), ReportSensitivity.SENSITIVE))
                        add(ReportField("application_count", text.observedApplications, metadata.applicationCount.toString(), ReportSensitivity.SENSITIVE))
                        add(ReportField("destination_count", text.observedDestinations, metadata.destinationCount.toString(), ReportSensitivity.SENSITIVE))
                        metadata.fileSha256?.let { digest ->
                            add(ReportField("file_sha256", text.captureFileSha256, digest, ReportSensitivity.TECHNICAL))
                        }
                    },
                ),
            ),
            limitations = listOf(text.metadataOnlyLimitation),
            notes = if (metadata.sourceContainedPayloads) {
                listOf(ReportNote(text.payloadSharingWarning))
            } else {
                emptyList()
            },
        )
    }
}
