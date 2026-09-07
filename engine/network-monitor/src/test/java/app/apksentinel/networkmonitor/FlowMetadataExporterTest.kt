package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowMetadataExporterTest {
    @Test
    fun exportIsBoundedRedactedAndPayloadFree() {
        val registry = BoundedFlowRegistry(capacity = 2)
        registry.observe(
            metadata = PacketMetadata(
                ipVersion = IpVersion.IPV4,
                ipProtocolNumber = 6,
                transportProtocol = TransportProtocol.TCP,
                source = NetworkEndpoint("10.0.0.2", 45_000),
                destination = NetworkEndpoint("203.0.113.7", 443),
                declaredIpPacketBytes = 100,
                capturedPacketBytes = 100,
                dns = DnsMetadata(
                    messageKind = DnsMessageKind.QUERY,
                    transactionId = 1,
                    questionName = SafeDnsName.Hashed("abc123", 2),
                    questionCount = 1,
                    responseCode = null,
                    questionType = 1,
                    status = DnsParseStatus.PARSED,
                ),
            ),
            attribution = AppAttribution.Known("app.example.test"),
            direction = PacketDirection.OUTBOUND,
            atMillis = 1L,
        )
        val output = ByteArrayOutputStream()

        val result = SafeFlowMetadataExporter.writeJsonLines(registry.snapshotState(), output)
        val content = output.toString(Charsets.UTF_8.name())

        assertTrue(result.recordsWritten == 1)
        assertFalse(result.containsPayload)
        assertFalse(result.containsEndpointAddresses)
        assertFalse(result.containsPlaintextDnsNames)
        assertTrue(content.contains("\"payload_retained\":false"))
        assertTrue(content.contains("HASHED_PER_SESSION"))
        assertFalse(content.contains("10.0.0.2"))
        assertFalse(content.contains("203.0.113.7"))
        assertFalse(content.contains("app.example.test"))
    }

    @Test
    fun jsonExportUsesAnArrayAndKeepsTheSameRedactionContract() {
        val output = ByteArrayOutputStream()
        val result = SafeFlowMetadataExporter.writeJson(
            snapshot = FlowRegistrySnapshot(),
            output = output,
        )
        val content = output.toString(Charsets.UTF_8.name())

        assertTrue(result.recordsWritten == 0)
        assertTrue(content.startsWith("{\"schema_version\":1"))
        assertTrue(content.contains("\"flows\":[]"))
        assertTrue(content.contains("\"payload_retained\":false"))
    }
}
