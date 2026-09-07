package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowCsvExporterTest {
    private fun flow(
        id: String = "flow-1",
        destinationAddress: String = "203.0.113.7",
        attribution: AppAttribution = AppAttribution.Known("app.example.test", uid = 10_123),
        dnsName: SafeDnsName? = null,
    ) = NetworkFlow(
        id = id,
        key = NetworkFlowKey(
            ipVersion = IpVersion.IPV4,
            protocol = TransportProtocol.TCP,
            source = NetworkEndpoint("10.0.0.2", 45_000),
            destination = NetworkEndpoint(destinationAddress, 443),
            direction = PacketDirection.OUTBOUND,
        ),
        attribution = attribution,
        direction = PacketDirection.OUTBOUND,
        startedAtMillis = 1_000L,
        lastSeenAtMillis = 2_000L,
        packetCount = 5L,
        observedBytes = 1_234L,
        latestDnsName = dnsName,
    )

    @Test
    fun writesOneRowPerFlowWithARealFieldHeader() {
        val output = ByteArrayOutputStream()
        val snapshot = FlowRegistrySnapshot(flows = listOf(flow()), capacity = 4)

        val result = SafeFlowCsvExporter.write(snapshot, output)
        val lines = output.toString(Charsets.UTF_8.name()).split("\r\n").filter { it.isNotEmpty() }

        assertEquals(1, result.recordsWritten)
        assertFalse(result.truncated)
        assertEquals(FlowTabularExportRow.HEADER.joinToString(","), lines[0])
        assertTrue(lines[1].contains("203.0.113.7"))
        assertTrue(lines[1].contains("app.example.test"))
        assertTrue(lines[1].contains("10123"))
        assertEquals(2, lines.size)
    }

    @Test
    fun neutralisesLeadingFormulaCharactersOnAllFourTriggers() {
        listOf("=cmd", "+cmd", "-cmd", "@cmd").forEach { destination ->
            val output = ByteArrayOutputStream()
            SafeFlowCsvExporter.write(FlowRegistrySnapshot(flows = listOf(flow(destinationAddress = destination))), output)
            val content = output.toString(Charsets.UTF_8.name())

            assertTrue("expected neutralised cell for $destination", content.contains("'$destination"))
        }
    }

    @Test
    fun quotesCellsContainingCommaOrQuoteAndDoublesEmbeddedQuotes() {
        val output = ByteArrayOutputStream()
        SafeFlowCsvExporter.write(
            FlowRegistrySnapshot(flows = listOf(flow(destinationAddress = "10.0.0.1,\"evil\""))),
            output,
        )
        val content = output.toString(Charsets.UTF_8.name())

        assertTrue(content.contains("\"10.0.0.1,\"\"evil\"\"\""))
    }

    @Test
    fun exposesPlaintextDnsNameOnlyAfterExplicitConsentAndFlagsIt() {
        val output = ByteArrayOutputStream()
        val result = SafeFlowCsvExporter.write(
            FlowRegistrySnapshot(flows = listOf(flow(dnsName = SafeDnsName.PlaintextAfterExplicitConsent("example.test")))),
            output,
        )
        val content = output.toString(Charsets.UTF_8.name())

        assertTrue(result.containsPlaintextDnsNames)
        assertTrue(content.contains("example.test"))
        assertTrue(content.contains("PLAINTEXT_EXPLICIT_CONSENT"))
    }

    @Test
    fun hashedDnsNameNeverAppearsAsPlaintext() {
        val output = ByteArrayOutputStream()
        val result = SafeFlowCsvExporter.write(
            FlowRegistrySnapshot(flows = listOf(flow(dnsName = SafeDnsName.Hashed("deadbeef", 2)))),
            output,
        )
        val content = output.toString(Charsets.UTF_8.name())

        assertFalse(result.containsPlaintextDnsNames)
        assertTrue(content.contains("deadbeef"))
        assertTrue(content.contains("HASHED_PER_SESSION"))
    }

    @Test
    fun respectsRecordBoundAndReportsTruncation() {
        val flows = (1..5).map { flow(id = "flow-$it") }
        val output = ByteArrayOutputStream()

        val result = SafeFlowCsvExporter.write(
            FlowRegistrySnapshot(flows = flows, capacity = 5),
            output,
            FlowCsvExportLimits(maximumFlowsExamined = 3, maximumRecords = 3),
        )

        assertEquals(3, result.recordsWritten)
        assertTrue(result.truncated)
    }

    @Test
    fun emptySnapshotWritesOnlyTheHeader() {
        val output = ByteArrayOutputStream()
        val result = SafeFlowCsvExporter.write(FlowRegistrySnapshot(), output)
        val lines = output.toString(Charsets.UTF_8.name()).split("\r\n").filter { it.isNotEmpty() }

        assertEquals(0, result.recordsWritten)
        assertEquals(1, lines.size)
        // A zero-byte export was seen once on an emulator that died mid-write. This pins
        // down that the writer itself can never produce one: the header is unconditional,
        // so an empty file always means the write did not run, not that it wrote nothing.
        assertTrue(output.size() > 0)
        assertTrue(result.bytesWritten > 0)
    }
}
