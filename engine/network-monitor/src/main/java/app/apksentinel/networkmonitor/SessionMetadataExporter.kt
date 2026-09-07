package app.apksentinel.networkmonitor

/** Export data is returned to the host app; this module never writes or shares a file itself. */
enum class SessionExportFormat {
    JSON,
    CSV,
}

data class SessionMetadataExport(
    val format: SessionExportFormat,
    val mimeType: String,
    val suggestedFileName: String,
    val content: String,
    val containsPacketPayload: Boolean = false,
    val containsPlaintextDnsName: Boolean = false,
    val containsDestinationAddress: Boolean = false,
)

/**
 * Exports only session-level, non-payload metadata. The host must use a
 * user-selected document/share destination and disclose it before sending.
 */
object SafeSessionMetadataExporter {
    fun export(
        metadata: NetworkSessionMetadata,
        format: SessionExportFormat,
    ): SessionMetadataExport = when (format) {
        SessionExportFormat.JSON -> SessionMetadataExport(
            format = format,
            mimeType = "application/json",
            suggestedFileName = "network-session-${safeFileId(metadata.sessionId)}.json",
            content = json(metadata),
        )

        SessionExportFormat.CSV -> SessionMetadataExport(
            format = format,
            mimeType = "text/csv",
            suggestedFileName = "network-session-${safeFileId(metadata.sessionId)}.csv",
            content = csv(metadata),
        )
    }

    private fun json(metadata: NetworkSessionMetadata): String = buildString {
        append('{')
        jsonNumber("schema_version", 1)
        append(',')
        jsonField("session_id", metadata.sessionId)
        append(',')
        jsonField("requested_mode", metadata.requestedMode.name)
        append(',')
        jsonField("state", metadata.state.name)
        append(',')
        jsonNumber("started_at_millis", metadata.startedAtMillis)
        append(',')
        append("\"ended_at_millis\":")
        if (metadata.endedAtMillis == null) append("null") else append(metadata.endedAtMillis)
        append(',')
        jsonNumber("retained_event_count", metadata.retainedEventCount.toLong())
        append(',')
        jsonNumber("dropped_event_count", metadata.droppedEventCount)
        append(',')
        append("\"capabilities\":[")
        metadata.capabilities.reports.forEachIndexed { index, report ->
            if (index > 0) append(',')
            append('{')
            jsonField("id", report.capability.name)
            append(',')
            jsonField("availability", report.availability.name)
            append('}')
        }
        append(']')
        append(',')
        append("\"limitations\":[")
        metadata.limitations.map(EngineLimitation::code).distinct().forEachIndexed { index, code ->
            if (index > 0) append(',')
            append(jsonString(code.name))
        }
        append(']')
        append('}')
    }

    private fun csv(metadata: NetworkSessionMetadata): String {
        val header = listOf(
            "schema_version",
            "session_id",
            "requested_mode",
            "state",
            "started_at_millis",
            "ended_at_millis",
            "retained_event_count",
            "dropped_event_count",
            "capability_states",
            "limitation_codes",
        )
        val capabilityStates = metadata.capabilities.reports.joinToString(";") {
            "${it.capability.name}=${it.availability.name}"
        }
        val limitationCodes = metadata.limitations.map(EngineLimitation::code).distinct().joinToString(";") { it.name }
        val row = listOf(
            "1",
            metadata.sessionId,
            metadata.requestedMode.name,
            metadata.state.name,
            metadata.startedAtMillis.toString(),
            metadata.endedAtMillis?.toString().orEmpty(),
            metadata.retainedEventCount.toString(),
            metadata.droppedEventCount.toString(),
            capabilityStates,
            limitationCodes,
        )
        return header.joinToString(",") { csvField(it) } + "\n" + row.joinToString(",") { csvField(it) } + "\n"
    }

    private fun StringBuilder.jsonField(name: String, value: String) {
        append(jsonString(name))
        append(':')
        append(jsonString(value))
    }

    private fun StringBuilder.jsonNumber(name: String, value: Long) {
        append(jsonString(name))
        append(':')
        append(value)
    }

    private fun jsonString(value: String): String = buildString(value.length + 2) {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append("\\u%04x".format(character.code))
                } else {
                    append(character)
                }
            }
        }
        append('"')
    }

    private fun csvField(value: String): String = "\"${value.replace("\"", "\"\"")}\""

    private fun safeFileId(sessionId: String): String =
        sessionId.filter { it.isLetterOrDigit() || it == '-' }.take(80).ifBlank { "session" }
}
