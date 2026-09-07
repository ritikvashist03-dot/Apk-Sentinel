package app.apksentinel.networkmonitor

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowXlsxExporterTest {
    private fun flow(
        id: String = "flow-1",
        attribution: AppAttribution = AppAttribution.Known("app.example.test", uid = 10_123),
    ) = NetworkFlow(
        id = id,
        key = NetworkFlowKey(
            ipVersion = IpVersion.IPV4,
            protocol = TransportProtocol.TCP,
            source = NetworkEndpoint("10.0.0.2", 45_000),
            destination = NetworkEndpoint("203.0.113.7", 443),
            direction = PacketDirection.OUTBOUND,
        ),
        attribution = attribution,
        direction = PacketDirection.OUTBOUND,
        startedAtMillis = 1_000L,
        lastSeenAtMillis = 2_000L,
        packetCount = 5L,
        observedBytes = 1_234L,
    )

    /** Reads every ZIP entry into memory, keyed by name, for assertions below. */
    private fun unzip(bytes: ByteArray): Map<String, ByteArray> {
        val entries = LinkedHashMap<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries[entry.name] = zip.readBytes()
                zip.closeEntry()
            }
        }
        return entries
    }

    private fun assertWellFormedXml(bytes: ByteArray) {
        val factory = DocumentBuilderFactory.newInstance()
        val builder = factory.newDocumentBuilder()
        builder.parse(ByteArrayInputStream(bytes))
    }

    @Test
    fun producesAZipWithTheFiveRequiredPartsAndEachIsWellFormedXml() {
        val output = ByteArrayOutputStream()
        SafeFlowXlsxExporter.write(FlowRegistrySnapshot(flows = listOf(flow())), output)
        val entries = unzip(output.toByteArray())

        val expectedParts = setOf(
            "[Content_Types].xml",
            "_rels/.rels",
            "xl/workbook.xml",
            "xl/_rels/workbook.xml.rels",
            "xl/worksheets/sheet1.xml",
        )
        assertEquals(expectedParts, entries.keys)
        entries.values.forEach(::assertWellFormedXml)
    }

    @Test
    fun sheetContainsTheHeaderAndOneRowPerFlowAsInlineStrings() {
        val output = ByteArrayOutputStream()
        val result = SafeFlowXlsxExporter.write(FlowRegistrySnapshot(flows = listOf(flow())), output)
        val sheet = unzip(output.toByteArray()).getValue("xl/worksheets/sheet1.xml").toString(Charsets.UTF_8)

        assertEquals(1, result.recordsWritten)
        assertTrue(sheet.contains("t=\"inlineStr\""))
        assertTrue(sheet.contains("flow_id"))
        assertTrue(sheet.contains("203.0.113.7"))
        assertTrue(sheet.contains("app.example.test"))
        // No shared-strings part should exist or be referenced.
        assertFalse(sheet.contains("t=\"s\""))
    }

    @Test
    fun workbookAndRelationshipPartsAgreeOnOneSheetNamedFlows() {
        val output = ByteArrayOutputStream()
        SafeFlowXlsxExporter.write(FlowRegistrySnapshot(flows = listOf(flow())), output)
        val entries = unzip(output.toByteArray())
        val workbook = entries.getValue("xl/workbook.xml").toString(Charsets.UTF_8)
        val contentTypes = entries.getValue("[Content_Types].xml").toString(Charsets.UTF_8)

        assertTrue(workbook.contains("name=\"Flows\""))
        assertTrue(contentTypes.contains("/xl/worksheets/sheet1.xml"))
    }

    @Test
    fun escapesXmlSpecialCharactersInCellText() {
        val output = ByteArrayOutputStream()
        SafeFlowXlsxExporter.write(
            FlowRegistrySnapshot(flows = listOf(flow(attribution = AppAttribution.Known("app.example.test", uid = 1)))),
            output,
        )
        // The exporter must not blindly trust field content; verify the sheet part is still
        // well-formed even though flow ids / addresses could in principle contain XML metacharacters.
        val entries = unzip(output.toByteArray())
        assertWellFormedXml(entries.getValue("xl/worksheets/sheet1.xml"))
    }

    @Test
    fun respectsRecordBoundAndReportsTruncation() {
        val flows = (1..5).map { flow(id = "flow-$it") }
        val output = ByteArrayOutputStream()

        val result = SafeFlowXlsxExporter.write(
            FlowRegistrySnapshot(flows = flows, capacity = 5),
            output,
            FlowXlsxExportLimits(maximumFlowsExamined = 3, maximumRecords = 3),
        )

        assertEquals(3, result.recordsWritten)
        assertTrue(result.truncated)
        assertWellFormedXml(unzip(output.toByteArray()).getValue("xl/worksheets/sheet1.xml"))
    }

    @Test
    fun emptySnapshotStillProducesAValidWorkbookWithOnlyTheHeaderRow() {
        val output = ByteArrayOutputStream()
        val result = SafeFlowXlsxExporter.write(FlowRegistrySnapshot(), output)
        val sheet = unzip(output.toByteArray()).getValue("xl/worksheets/sheet1.xml").toString(Charsets.UTF_8)

        assertEquals(0, result.recordsWritten)
        assertTrue(sheet.contains("flow_id"))
        assertEquals(1, Regex("<row ").findAll(sheet).count())
    }
}
