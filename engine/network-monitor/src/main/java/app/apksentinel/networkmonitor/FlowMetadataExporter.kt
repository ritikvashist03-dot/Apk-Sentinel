package app.apksentinel.networkmonitor

import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/** Strict bounds for the optional SAF flow-metadata export. */
data class FlowMetadataExportLimits(
    val maximumFlowsExamined: Int = 128,
    val maximumRecords: Int = 128,
    val maximumBytes: Int = 512 * 1_024,
    val maximumRecordBytes: Int = 4 * 1_024,
) {
    init {
        require(maximumFlowsExamined in 1..1_024) { "Flow bound must be between 1 and 1024." }
        require(maximumRecords in 1..maximumFlowsExamined) { "Record bound must not exceed the flow bound." }
        require(maximumBytes in 1_024..4 * 1_024 * 1_024) { "Export byte bound is outside the safe range." }
        require(maximumRecordBytes in 256..64 * 1_024) { "Record byte bound is outside the safe range." }
    }
}

data class FlowMetadataExportResult(
    val flowsExamined: Int,
    val recordsWritten: Int,
    val bytesWritten: Int,
    val truncated: Boolean,
    val containsPayload: Boolean = false,
    val containsEndpointAddresses: Boolean = false,
    val containsPlaintextDnsNames: Boolean = false,
)

/**
 * Writes a redacted technical preview of bounded flow metadata as NDJSON.
 * It deliberately omits flow IDs, package names, endpoint addresses, DNS
 * values, and all packet/payload content. The caller owns and closes [output].
 */
object SafeFlowMetadataExporter {
    const val MIME_TYPE: String = "application/x-ndjson"
    const val JSON_MIME_TYPE: String = "application/json"
    const val SUGGESTED_FILE_EXTENSION: String = "ndjson"

    @Throws(IOException::class)
    fun writeJsonLines(
        snapshot: FlowRegistrySnapshot,
        output: OutputStream,
        limits: FlowMetadataExportLimits = FlowMetadataExportLimits(),
    ): FlowMetadataExportResult {
        var examined = 0
        var written = 0
        var bytes = 0
        var truncated = snapshot.flows.size > limits.maximumFlowsExamined
        val header = "{\"schema_version\":1,\"record_type\":\"flow_metadata_export\",\"redacted\":true,\"payload_retained\":false}\n"
            .toByteArray(StandardCharsets.UTF_8)
        check(header.size <= limits.maximumBytes) { "Flow export header exceeds the configured bound." }
        output.write(header)
        bytes += header.size

        for (flow in snapshot.flows) {
            if (examined >= limits.maximumFlowsExamined || written >= limits.maximumRecords) {
                truncated = true
                break
            }
            examined += 1
            val line = flow.toRedactedJsonLine() + '\n'
            val encoded = line.toByteArray(StandardCharsets.UTF_8)
            if (encoded.size > limits.maximumRecordBytes || bytes + encoded.size > limits.maximumBytes) {
                truncated = true
                break
            }
            output.write(encoded)
            bytes += encoded.size
            written += 1
        }
        output.flush()
        return FlowMetadataExportResult(
            flowsExamined = examined,
            recordsWritten = written,
            bytesWritten = bytes,
            truncated = truncated,
        )
    }

    /** Writes the same redacted bounded records as a JSON array for JSON SAF destinations. */
    @Throws(IOException::class)
    fun writeJson(
        snapshot: FlowRegistrySnapshot,
        output: OutputStream,
        limits: FlowMetadataExportLimits = FlowMetadataExportLimits(),
    ): FlowMetadataExportResult {
        var examined = 0
        var written = 0
        var bytes = 0
        var truncated = snapshot.flows.size > limits.maximumFlowsExamined
        val prefix = "{\"schema_version\":1,\"redacted\":true,\"payload_retained\":false,\"flows\":["
            .toByteArray(StandardCharsets.UTF_8)
        val suffix = "]}\n".toByteArray(StandardCharsets.UTF_8)
        check(prefix.size + suffix.size <= limits.maximumBytes) { "Flow JSON framing exceeds the configured bound." }
        output.write(prefix)
        bytes += prefix.size

        for (flow in snapshot.flows) {
            if (examined >= limits.maximumFlowsExamined || written >= limits.maximumRecords) {
                truncated = true
                break
            }
            examined += 1
            val record = flow.toRedactedJsonLine().toByteArray(StandardCharsets.UTF_8)
            val separator = if (written == 0) ByteArray(0) else byteArrayOf(','.code.toByte())
            if (record.size + separator.size + bytes + suffix.size > limits.maximumBytes || record.size > limits.maximumRecordBytes) {
                truncated = true
                break
            }
            output.write(separator)
            output.write(record)
            bytes += separator.size + record.size
            written += 1
        }
        output.write(suffix)
        bytes += suffix.size
        output.flush()
        return FlowMetadataExportResult(
            flowsExamined = examined,
            recordsWritten = written,
            bytesWritten = bytes,
            truncated = truncated,
        )
    }

    private fun NetworkFlow.toRedactedJsonLine(): String = buildString {
        append("{\"record_type\":\"flow\"")
        append(",\"protocol\":\"").append(key.protocol.name).append('"')
        append(",\"direction\":\"").append(direction.name).append('"')
        append(",\"started_at_millis\":").append(startedAtMillis)
        append(",\"last_seen_at_millis\":").append(lastSeenAtMillis)
        append(",\"packet_count\":").append(packetCount)
        append(",\"observed_bytes\":").append(observedBytes)
        append(",\"attribution\":\"").append(if (attribution is AppAttribution.Known) "KNOWN" else "UNKNOWN").append('"')
        append(",\"dns_name_state\":\"").append(dnsState(latestDnsName)).append('"')
        append(",\"endpoint_addresses\":null,\"payload_retained\":false}")
    }

    private fun dnsState(value: SafeDnsName?): String = when (value) {
        null, SafeDnsName.NotCaptured -> "NOT_CAPTURED"
        is SafeDnsName.Hashed -> "HASHED_PER_SESSION"
        is SafeDnsName.PlaintextAfterExplicitConsent -> "PLAINTEXT_NOT_EXPORTED"
    }
}
