package app.apksentinel.networkmonitor

import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/**
 * Bounds for [SafeMetadataCaptureExporter]. The default values fit the module's
 * process-local event store, and every limit is deliberately finite so an
 * export cannot become a memory or storage-amplification path.
 */
data class MetadataCaptureExportLimits(
    val maximumEventsExamined: Int = DEFAULT_MAXIMUM_EVENTS_EXAMINED,
    val maximumRecords: Int = DEFAULT_MAXIMUM_RECORDS,
    val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    val maximumRecordBytes: Int = DEFAULT_MAXIMUM_RECORD_BYTES,
) {
    init {
        require(maximumEventsExamined in 1..MAXIMUM_EVENTS_EXAMINED) {
            "Maximum examined events must be between 1 and $MAXIMUM_EVENTS_EXAMINED."
        }
        require(maximumRecords in 1..maximumEventsExamined) {
            "Maximum records must be between 1 and maximum examined events."
        }
        require(maximumBytes in MINIMUM_BYTES..MAXIMUM_BYTES) {
            "Maximum export bytes must be between $MINIMUM_BYTES and $MAXIMUM_BYTES."
        }
        require(maximumRecordBytes in 256..MAXIMUM_RECORD_BYTES) {
            "Maximum record bytes must be between 256 and $MAXIMUM_RECORD_BYTES."
        }
    }

    private companion object {
        const val DEFAULT_MAXIMUM_EVENTS_EXAMINED = 512
        const val DEFAULT_MAXIMUM_RECORDS = 512
        const val DEFAULT_MAXIMUM_BYTES = 512 * 1_024
        const val DEFAULT_MAXIMUM_RECORD_BYTES = 2 * 1_024
        const val MAXIMUM_EVENTS_EXAMINED = 4_096
        const val MINIMUM_BYTES = 1_024
        const val MAXIMUM_BYTES = 4 * 1_024 * 1_024
        const val MAXIMUM_RECORD_BYTES = 8 * 1_024
    }
}

/** Result metadata is safe to display and contains no packet content. */
data class MetadataCaptureExportResult(
    val recordsWritten: Int,
    val eventsExamined: Int,
    val skippedEvents: Int,
    val oversizedRecordsSkipped: Int,
    val bytesWritten: Int,
    val truncated: Boolean,
    val containsRawPacketBytes: Boolean = false,
    val containsEndpointAddresses: Boolean = false,
    val containsPlaintextDnsNames: Boolean = false,
)

/**
 * Bounded JSON Lines export for local-VPN metadata only. This is deliberately
 * not a PCAPNG implementation: the module never retains raw packet bytes, and
 * emitting a synthetic PCAPNG file would falsely imply packet-capture parity.
 *
 * The exporter preserves the supplied event order, uses each event's exact
 * epoch-millisecond timestamp, and writes one record at a time to a caller-
 * owned [OutputStream]. It never materializes the supplied event sequence,
 * opens sockets, chooses a destination, or closes the stream. The caller
 * controls both sources: use a bounded local event snapshot and a
 * user-selected local document stream when the product promises local-only
 * export.
 */
object SafeMetadataCaptureExporter {
    const val MIME_TYPE: String = "application/x-ndjson"
    const val SUGGESTED_FILE_EXTENSION: String = "ndjson"
    /**
     * Writes a deterministic header followed by bounded, payload-free records.
     * The caller owns [output] and is responsible for handling [IOException].
     */
    @Throws(IOException::class)
    fun writeJsonLines(
        events: Iterable<NetworkEvent>,
        output: OutputStream,
        limits: MetadataCaptureExportLimits = MetadataCaptureExportLimits(),
    ): MetadataCaptureExportResult {
        var recordsWritten = 0
        var eventsExamined = 0
        var skippedEvents = 0
        var oversizedRecordsSkipped = 0
        var bytesWritten = 0
        var truncated = false

        val header = (HEADER_LINE + '\n').toByteArray(StandardCharsets.UTF_8)
        check(header.size <= limits.maximumBytes) {
            "Metadata export header exceeds the configured byte bound."
        }
        output.write(header)
        bytesWritten += header.size

        val iterator = events.iterator()
        while (iterator.hasNext()) {
            if (eventsExamined >= limits.maximumEventsExamined || recordsWritten >= limits.maximumRecords) {
                truncated = true
                break
            }

            val event = iterator.next()
            eventsExamined += 1
            val line = event.toMetadataJsonLine()
            if (line == null) {
                skippedEvents += 1
                continue
            }
            val encoded = (line + '\n').toByteArray(StandardCharsets.UTF_8)
            if (encoded.size > limits.maximumRecordBytes) {
                oversizedRecordsSkipped += 1
                truncated = true
                continue
            }
            if (bytesWritten + encoded.size > limits.maximumBytes) {
                truncated = true
                break
            }
            output.write(encoded)
            bytesWritten += encoded.size
            recordsWritten += 1
        }

        output.flush()
        return MetadataCaptureExportResult(
            recordsWritten = recordsWritten,
            eventsExamined = eventsExamined,
            skippedEvents = skippedEvents,
            oversizedRecordsSkipped = oversizedRecordsSkipped,
            bytesWritten = bytesWritten,
            truncated = truncated,
        )
    }

    private fun NetworkEvent.toMetadataJsonLine(): String? = when (this) {
        is PacketObservedEvent -> buildString {
            appendRecordPrefix("packet_metadata", atMillis)
            append(",\"direction\":\"").append(direction.name).append('\"')
            append(",\"ip_version\":\"").append(metadata.ipVersion.name).append('\"')
            append(",\"transport\":\"").append(metadata.transportProtocol.name).append('\"')
            append(",\"ip_protocol\":").append(metadata.ipProtocolNumber)
            append(",\"captured_bytes\":").append(metadata.capturedPacketBytes)
            append(",\"declared_ip_bytes\":")
            val declaredIpBytes = metadata.declaredIpPacketBytes
            if (declaredIpBytes == null) append("null") else append(declaredIpBytes)
            append(",\"dns_status\":\"").append(metadata.dns?.status?.name ?: "NOT_PRESENT").append('\"')
            append(",\"attribution\":\"")
            append(if (attribution is AppAttribution.Known) "KNOWN" else "UNKNOWN")
            append('\"')
            append(",\"parser_notes\":")
            appendEnumNames(metadata.notes.map { it.name })
            append('}')
        }

        is PacketParseFailureEvent -> buildString {
            appendRecordPrefix("packet_parse_failure", atMillis)
            append('}')
        }

        is FirewallDecisionEvent -> buildString {
            appendRecordPrefix("firewall_decision", atMillis)
            append(",\"requested_action\":\"").append(decision.requestedAction.name).append('\"')
            append(",\"reason\":\"").append(decision.reason.name).append('\"')
            append(",\"enforcement\":\"").append(decision.enforcement.name).append('\"')
            append(",\"has_matching_rule\":").append(decision.matchedRuleId != null)
            append(",\"matched_criteria\":")
            appendEnumNames(decision.matchedCriteria.map { it.name })
            append('}')
        }

        is ForwarderEnforcementEvent -> buildString {
            appendRecordPrefix("firewall_enforcement", atMillis)
            append(",\"outcome\":\"").append(result.outcome.name).append('\"')
            append('}')
        }

        is EngineLimitationEvent -> buildString {
            appendRecordPrefix("engine_limitation", atMillis)
            append(",\"limitation_code\":\"").append(limitation.code.name).append('\"')
            append('}')
        }

        is MonitorStateEvent -> buildString {
            appendRecordPrefix("monitor_state", atMillis)
            append(",\"state\":\"").append(state.name).append('\"')
            append('}')
        }
    }

    private fun StringBuilder.appendRecordPrefix(recordType: String, atMillis: Long) {
        append("{\"record_type\":\"").append(recordType).append('\"')
        append(",\"metadata_source_id\":").append(METADATA_SOURCE_ID)
        append(",\"timestamp_millis\":").append(atMillis)
    }

    private fun StringBuilder.appendEnumNames(names: List<String>) {
        append('[')
        names.sorted().forEachIndexed { index, name ->
            if (index > 0) append(',')
            append('\"').append(name).append('\"')
        }
        append(']')
    }

    private const val METADATA_SOURCE_ID: Int = 0

    private const val HEADER_LINE =
        "{\"schema_version\":1,\"export_kind\":\"LOCAL_VPN_METADATA_ONLY\",\"metadata_source\":{\"id\":0,\"name\":\"android-local-vpn-metadata-v1\"},\"timestamp_unit\":\"milliseconds_since_epoch\",\"raw_packet_bytes_retained\":false,\"pcapng_packet_export_available\":false}"
}
