package app.apksentinel.networkmonitor

import java.io.IOException
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Bounds for [SafeFlowXlsxExporter]. */
data class FlowXlsxExportLimits(
    val maximumFlowsExamined: Int = 512,
    val maximumRecords: Int = 512,
    /** Bounds the raw (pre-compression) worksheet text this exporter will build in memory. */
    val maximumSheetTextBytes: Int = 4 * 1_024 * 1_024,
) {
    init {
        require(maximumFlowsExamined in 1..4_096) { "Flow bound must be between 1 and 4096." }
        require(maximumRecords in 1..maximumFlowsExamined) { "Record bound must not exceed the flow bound." }
        require(maximumSheetTextBytes in 1_024..16 * 1_024 * 1_024) { "Sheet text byte bound is outside the safe range." }
    }
}

data class FlowXlsxExportResult(
    val flowsExamined: Int,
    val recordsWritten: Int,
    val truncated: Boolean,
    /** This exporter always writes real endpoint addresses; kept as a field for parity with the redacted exporter's result shape. */
    val containsEndpointAddresses: Boolean = true,
    val containsPlaintextDnsNames: Boolean = false,
)

/**
 * A minimal, dependency-free `.xlsx` writer for the same flow rows as
 * [SafeFlowCsvExporter]. An xlsx is a ZIP of OOXML parts; this writes only the
 * five parts a spreadsheet application needs to open one sheet, and uses
 * inline strings (`t="inlineStr"`) for every cell so no shared-strings part is
 * required. No third-party OOXML library is used or needed.
 *
 * A cell's type here is always an explicit inline string, never a formula
 * (`<f>`), so unlike a `.csv` a spreadsheet application has no ambiguity about
 * whether a value beginning with `=`/`+`/`-`/`@` should be evaluated: it
 * cannot be, because nothing in this file declares a formula. The CSV
 * exporter still neutralises those leading characters because CSV cells have
 * no such explicit type and some spreadsheet "text import" heuristics treat
 * a leading `=` as a formula regardless of file extension.
 */
object SafeFlowXlsxExporter {
    const val MIME_TYPE: String = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    const val SUGGESTED_FILE_EXTENSION: String = "xlsx"

    @Throws(IOException::class)
    fun write(
        snapshot: FlowRegistrySnapshot,
        output: OutputStream,
        limits: FlowXlsxExportLimits = FlowXlsxExportLimits(),
    ): FlowXlsxExportResult {
        var examined = 0
        var written = 0
        var truncated = snapshot.flows.size > limits.maximumFlowsExamined
        var containsPlaintextDnsNames = false
        var sheetTextBytes = 0

        val rows = ArrayList<List<String>>(minOf(snapshot.flows.size, limits.maximumRecords) + 1)
        rows += FlowTabularExportRow.HEADER
        sheetTextBytes += rowByteEstimate(FlowTabularExportRow.HEADER)

        for (flow in snapshot.flows) {
            if (examined >= limits.maximumFlowsExamined || written >= limits.maximumRecords) {
                truncated = true
                break
            }
            examined += 1
            val cells = FlowTabularExportRow.cellsFor(flow)
            val rowBytes = rowByteEstimate(cells)
            if (sheetTextBytes + rowBytes > limits.maximumSheetTextBytes) {
                truncated = true
                break
            }
            rows += cells
            sheetTextBytes += rowBytes
            written += 1
            if (FlowTabularExportRow.containsPlaintextDnsName(flow)) containsPlaintextDnsNames = true
        }

        writeWorkbook(rows, output)
        return FlowXlsxExportResult(
            flowsExamined = examined,
            recordsWritten = written,
            truncated = truncated,
            containsPlaintextDnsNames = containsPlaintextDnsNames,
        )
    }

    private fun rowByteEstimate(cells: List<String>): Int = cells.sumOf { it.length } + cells.size

    private fun writeWorkbook(rows: List<List<String>>, output: OutputStream) {
        val zip = ZipOutputStream(output)
        zip.writeStoredEntry("[Content_Types].xml", CONTENT_TYPES_XML)
        zip.writeStoredEntry("_rels/.rels", PACKAGE_RELS_XML)
        zip.writeStoredEntry("xl/workbook.xml", WORKBOOK_XML)
        zip.writeStoredEntry("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
        zip.writeStoredEntry("xl/worksheets/sheet1.xml", buildSheetXml(rows))
        // finish(), not close(): the caller owns [output] and is responsible for closing it.
        zip.finish()
        output.flush()
    }

    private fun ZipOutputStream.writeStoredEntry(name: String, contents: String) {
        putNextEntry(ZipEntry(name))
        write(contents.toByteArray(StandardCharsets.UTF_8))
        closeEntry()
    }

    private fun buildSheetXml(rows: List<List<String>>): String = buildString {
        append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")
        append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">")
        append("<sheetData>")
        rows.forEachIndexed { rowIndex, cells ->
            val rowNumber = rowIndex + 1
            append("<row r=\"").append(rowNumber).append("\">")
            cells.forEachIndexed { columnIndex, value ->
                append("<c r=\"").append(columnLetters(columnIndex)).append(rowNumber)
                append("\" t=\"inlineStr\"><is><t xml:space=\"preserve\">")
                append(escapeXmlText(value))
                append("</t></is></c>")
            }
            append("</row>")
        }
        append("</sheetData></worksheet>")
    }

    /** 0-based column index to spreadsheet column letters: 0 -> A, 25 -> Z, 26 -> AA, ... */
    private fun columnLetters(index: Int): String {
        var value = index
        val letters = StringBuilder()
        do {
            letters.insert(0, ('A' + (value % 26)))
            value = value / 26 - 1
        } while (value >= 0)
        return letters.toString()
    }

    private fun escapeXmlText(value: String): String = buildString(value.length) {
        value.forEach { char ->
            when {
                char == '&' -> append("&amp;")
                char == '<' -> append("&lt;")
                char == '>' -> append("&gt;")
                char == '\t' || char == '\n' || char == '\r' -> append(char)
                char.code < 0x20 -> Unit // XML 1.0 forbids other C0 control characters; drop them.
                else -> append(char)
            }
        }
    }

    private const val CONTENT_TYPES_XML =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">" +
            "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>" +
            "<Default Extension=\"xml\" ContentType=\"application/xml\"/>" +
            "<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>" +
            "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>" +
            "</Types>"

    private const val PACKAGE_RELS_XML =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            "<Relationship Id=\"rId1\" " +
            "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" " +
            "Target=\"xl/workbook.xml\"/>" +
            "</Relationships>"

    private const val WORKBOOK_XML =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" " +
            "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">" +
            "<sheets><sheet name=\"Flows\" sheetId=\"1\" r:id=\"rId1\"/></sheets>" +
            "</workbook>"

    private const val WORKBOOK_RELS_XML =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">" +
            "<Relationship Id=\"rId1\" " +
            "Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" " +
            "Target=\"worksheets/sheet1.xml\"/>" +
            "</Relationships>"
}
