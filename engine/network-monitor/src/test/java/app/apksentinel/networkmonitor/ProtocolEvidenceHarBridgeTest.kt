package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtocolEvidenceHarBridgeTest {

    @Test
    fun aConsentedRequestWithAUrlBecomesAnEntry() {
        val entries = ProtocolEvidenceHarBridge.toPayloadObservations(listOf(request("/a", "host.test")))
        assertEquals(1, entries.size)
        assertEquals("http://host.test/a", entries.single().url)
        assertEquals("GET", entries.single().method)
        // Never complete: no body was observed, so no reader should infer an empty one.
        assertFalse(entries.single().complete)
    }

    @Test
    fun aRequestWithoutACapturedUrlIsSkippedRatherThanGuessed() {
        // Targets not consented, so no URL could be reconstructed.
        val withoutUrl = ProtocolEvidenceObservation(
            source = ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST,
            direction = PacketDirection.OUTBOUND,
            observedAtMillis = 1L,
            confidence = ProtocolEvidenceConfidence.HIGH,
            value = ProtocolEvidenceValue.HttpRequest("GET", "HTTP/1.1"),
            limitations = emptySet(),
        )
        assertTrue(ProtocolEvidenceHarBridge.toPayloadObservations(listOf(withoutUrl)).isEmpty())
        assertFalse(ProtocolEvidenceHarBridge.canExport(listOf(withoutUrl)))
    }

    @Test
    fun responsesAreNotPairedBecauseFlowIdentityIsNotPublic() {
        val response = ProtocolEvidenceObservation(
            source = ProtocolEvidenceSource.CLEARTEXT_HTTP_RESPONSE,
            direction = PacketDirection.INBOUND,
            observedAtMillis = 2L,
            confidence = ProtocolEvidenceConfidence.HIGH,
            value = ProtocolEvidenceValue.HttpResponse(200, "HTTP/1.1"),
            limitations = emptySet(),
        )
        assertTrue(ProtocolEvidenceHarBridge.toPayloadObservations(listOf(response)).isEmpty())
    }

    @Test
    fun entriesAreBounded() {
        val many = (1..20).map { request("/p$it", "host.test") }
        assertEquals(5, ProtocolEvidenceHarBridge.toPayloadObservations(many, maximumEntries = 5).size)
        assertTrue(ProtocolEvidenceHarBridge.toPayloadObservations(many, maximumEntries = 0).isEmpty())
    }

    @Test
    fun theResultActuallyWritesValidHarThroughTheExistingExporter() {
        val entries = ProtocolEvidenceHarBridge.toPayloadObservations(
            listOf(request("/a", "host.test"), request("/b", "host.test")),
        )
        val output = ByteArrayOutputStream()
        val result = SafeHarExporter.write(entries, output)

        assertEquals(2, result.entriesWritten)
        val text = output.toString(Charsets.UTF_8)
        assertTrue(text.contains("http://host.test/a"))
        assertTrue(text.contains("\"log\""))
    }

    private fun request(target: String, host: String) = ProtocolEvidenceObservation(
        source = ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST,
        direction = PacketDirection.OUTBOUND,
        observedAtMillis = 1L,
        confidence = ProtocolEvidenceConfidence.HIGH,
        value = ProtocolEvidenceValue.HttpRequest("GET", "HTTP/1.1", target, host),
        limitations = emptySet(),
    )
}
