package app.apksentinel.networkmonitor

import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/** Bounds for [SafeFlowCsvExporter], mirroring [FlowMetadataExportLimits]'s shape. */
data class FlowCsvExportLimits(
    val maximumFlowsExamined: Int = 512,
    val maximumRecords: Int = 512,
    val maximumBytes: Int = 2 * 1_024 * 1_024,
) {
    init {
        require(maximumFlowsExamined in 1..4_096) { "Flow bound must be between 1 and 4096." }
        require(maximumRecords in 1..maximumFlowsExamined) { "Record bound must not exceed the flow bound." }
        require(maximumBytes in 1_024..8 * 1_024 * 1_024) { "Export byte bound is outside the safe range." }
    }
}

data class FlowCsvExportResult(
    val flowsExamined: Int,
    val recordsWritten: Int,
    val bytesWritten: Int,
    val truncated: Boolean,
    /** This exporter always writes real endpoint addresses; kept as a field for parity with the redacted exporter's result shape. */
    val containsEndpointAddresses: Boolean = true,
    val containsPlaintextDnsNames: Boolean = false,
)

/**
 * A full, spreadsheet-ready CSV export of observed flows: one row per flow, one flow per
 * connection this session's local VPN forwarder saw. The caller owns and closes [output].
 *
 * Every cell is neutralised against CSV/formula injection before it is written: a cell
 * whose first character is `=`, `+`, `-`, or `@` gets a leading apostrophe so a spreadsheet
 * opening the file renders it as text rather than evaluating it as a formula, and any cell
 * containing a comma, quote, or line break is quoted with embedded quotes doubled, per
 * RFC 4180.
 */
object SafeFlowCsvExporter {
    const val MIME_TYPE: String = "text/csv"
    const val SUGGESTED_FILE_EXTENSION: String = "csv"

    private const val CRLF = "\r\n"
    private val FORMULA_TRIGGER_CHARS = charArrayOf('=', '+', '-', '@')

    @Throws(IOException::class)
    fun write(
        snapshot: FlowRegistrySnapshot,
        output: OutputStream,
        limits: FlowCsvExportLimits = FlowCsvExportLimits(),
    ): FlowCsvExportResult {
        var examined = 0
        var written = 0
        var bytes = 0
        var truncated = snapshot.flows.size > limits.maximumFlowsExamined
        var containsPlaintextDnsNames = false

        val header = encodeRow(FlowTabularExportRow.HEADER)
        check(header.size <= limits.maximumBytes) { "CSV header exceeds the configured byte bound." }
        output.write(header)
        bytes += header.size

        for (flow in snapshot.flows) {
            if (examined >= limits.maximumFlowsExamined || written >= limits.maximumRecords) {
                truncated = true
                break
            }
            examined += 1
            val encoded = encodeRow(FlowTabularExportRow.cellsFor(flow))
            if (bytes + encoded.size > limits.maximumBytes) {
                truncated = true
                break
            }
            output.write(encoded)
            bytes += encoded.size
            written += 1
            if (FlowTabularExportRow.containsPlaintextDnsName(flow)) containsPlaintextDnsNames = true
        }
        output.flush()
        return FlowCsvExportResult(
            flowsExamined = examined,
            recordsWritten = written,
            bytesWritten = bytes,
            truncated = truncated,
            containsPlaintextDnsNames = containsPlaintextDnsNames,
        )
    }

    private fun encodeRow(cells: List<String>): ByteArray =
        (cells.joinToString(",", postfix = CRLF, transform = ::csvCell)).toByteArray(StandardCharsets.UTF_8)

    private fun csvCell(raw: String): String {
        val neutralised = if (raw.isNotEmpty() && raw[0] in FORMULA_TRIGGER_CHARS) "'$raw" else raw
        val needsQuoting = neutralised.any { it == ',' || it == '"' || it == '\n' || it == '\r' }
        return if (needsQuoting) "\"" + neutralised.replace("\"", "\"\"") + "\"" else neutralised
    }
}
