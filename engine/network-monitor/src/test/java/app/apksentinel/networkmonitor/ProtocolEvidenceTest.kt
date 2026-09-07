package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

class ProtocolEvidenceTest {
    private val flow = ProtocolEvidenceFlowKey("10.0.0.2", 45_000, "203.0.113.7", 443)

    @Test
    fun enabledConfigurationRequiresFreshConsent() {
        assertThrows(IllegalArgumentException::class.java) {
            ProtocolEvidenceConfiguration(enabled = true, inspectTlsClientHelloSni = true)
        }
    }

    @Test
    fun disabledByDefaultDoesNotInspectOrRetainPayload() {
        val collector = BoundedProtocolEvidenceCollector(ProtocolEvidenceConfiguration())

        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, tlsClientHello("api.example.test"), 1L)

        val snapshot = collector.snapshot()
        assertFalse(snapshot.enabledForSession)
        assertTrue(snapshot.observations.isEmpty())
        assertTrue(snapshot.sessionLimitations.contains(ProtocolEvidenceLimitation.DISABLED_BY_SESSION))
    }

    @Test
    fun completeTlsClientHelloYieldsOnlySafeAsciiSni() {
        val collector = tlsCollector()

        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, tlsClientHello("API.Example.TEST"), 9L)

        val observation = collector.snapshot().observations.single()
        assertEquals(ProtocolEvidenceSource.TLS_CLIENT_HELLO_SNI, observation.source)
        assertEquals(ProtocolEvidenceConfidence.HIGH, observation.confidence)
        assertEquals(
            ProtocolEvidenceValue.TlsServerName("api.example.test"),
            observation.value,
        )
        assertTrue(observation.limitations.isEmpty())
    }

    @Test
    fun fragmentedMalformedOversizedAndUnicodeTlsNeverInventHostname() {
        val collector = tlsCollector()
        val complete = tlsClientHello("safe.example")
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, complete.copyOf(10), 1L)
        collector.observeTcpPayload(
            ProtocolEvidenceFlowKey("10.0.0.3", 45_001, "203.0.113.7", 443),
            PacketDirection.OUTBOUND,
            byteArrayOf(22, 3, 3, 0x50, 0),
            2L,
        )
        collector.observeTcpPayload(
            ProtocolEvidenceFlowKey("10.0.0.4", 45_002, "203.0.113.7", 443),
            PacketDirection.OUTBOUND,
            tlsClientHello(byteArrayOf(0xC3.toByte(), 0xA9.toByte(), '.'.code.toByte(), 't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte())),
            3L,
        )

        val observations = collector.snapshot().observations
        assertEquals(3, observations.size)
        assertTrue(observations.all { it.value == null })
        assertTrue(observations[0].limitations.contains(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE))
        assertTrue(observations[1].limitations.contains(ProtocolEvidenceLimitation.OVERSIZED))
        assertTrue(observations[2].limitations.contains(ProtocolEvidenceLimitation.UNSAFE_OR_UNSUPPORTED_NAME))
    }

    @Test
    fun invalidTlsVersionsAndIpv4LiteralSniNeverBecomeHostnameEvidence() {
        val collector = tlsCollector()
        val invalidRecordVersion = tlsClientHello("safe.example").also {
            it[1] = 2
            it[2] = 0
        }
        val invalidHelloVersion = tlsClientHello("safe.example").also {
            // TLS record header is five bytes, handshake header is four bytes,
            // then ClientHello.legacy_version starts at offset nine.
            it[9] = 2
            it[10] = 0
        }
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, invalidRecordVersion, 1L)
        collector.observeTcpPayload(
            ProtocolEvidenceFlowKey("10.0.0.3", 45_001, "203.0.113.7", 443),
            PacketDirection.OUTBOUND,
            invalidHelloVersion,
            2L,
        )
        collector.observeTcpPayload(
            ProtocolEvidenceFlowKey("10.0.0.4", 45_002, "203.0.113.7", 443),
            PacketDirection.OUTBOUND,
            tlsClientHello("192.0.2.8"),
            3L,
        )

        val observations = collector.snapshot().observations
        assertEquals(3, observations.size)
        assertTrue(observations.all { it.value == null })
        assertTrue(observations[0].limitations.contains(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED))
        assertTrue(observations[1].limitations.contains(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED))
        assertTrue(observations[2].limitations.contains(ProtocolEvidenceLimitation.UNSAFE_OR_UNSUPPORTED_NAME))
    }

    @Test
    fun httpIsOptInAndRemovesQueriesCredentialsHeadersAndBodies() {
        val request = (
            "GET /account?token=secret-value HTTP/1.1\r\n" +
                "Host: api.example.test\r\n" +
                "Authorization: Bearer never-retain\r\n" +
                "Cookie: session=never-retain\r\n\r\n" +
                "body=never-retain"
            ).encodeToByteArray()
        val disabled = tlsCollector()
        disabled.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 1L)
        assertTrue(disabled.snapshot().observations.isEmpty())

        val collector = httpCollector()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 2L)

        val observation = collector.snapshot().observations.single()
        assertEquals(ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST, observation.source)
        assertEquals(
            ProtocolEvidenceValue.HttpRequest("GET", "HTTP/1.1"),
            observation.value,
        )
        assertTrue(observation.limitations.contains(ProtocolEvidenceLimitation.BODY_NOT_CAPTURED))
        assertTrue(observation.limitations.contains(ProtocolEvidenceLimitation.SENSITIVE_HEADERS_OMITTED))
        assertFalse(observation.toString().contains("secret-value"))
        assertFalse(observation.toString().contains("never-retain"))
    }

    @Test
    fun responseSummaryOmitsSetCookieAndMalformedOrIncompleteHttpHasNoValue() {
        val collector = httpCollector()
        collector.observeTcpPayload(
            flow,
            PacketDirection.INBOUND,
            "HTTP/1.1 204 No Content\r\nSet-Cookie: sid=private\r\n\r\n".encodeToByteArray(),
            4L,
        )
        collector.observeTcpPayload(
            ProtocolEvidenceFlowKey("203.0.113.7", 80, "10.0.0.2", 45_001),
            PacketDirection.INBOUND,
            "HTTP/1.1 200 OK\r\nX-Unsafe: \u0000\r\n\r\n".encodeToByteArray(),
            5L,
        )
        collector.observeTcpPayload(
            ProtocolEvidenceFlowKey("203.0.113.7", 80, "10.0.0.2", 45_002),
            PacketDirection.INBOUND,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n".encodeToByteArray(),
            6L,
        )

        val observations = collector.snapshot().observations
        assertEquals(3, observations.size)
        assertEquals(ProtocolEvidenceValue.HttpResponse(204, "HTTP/1.1"), observations[0].value)
        assertTrue(observations[0].limitations.contains(ProtocolEvidenceLimitation.SENSITIVE_HEADERS_OMITTED))
        assertNull(observations[1].value)
        assertTrue(observations[1].limitations.contains(ProtocolEvidenceLimitation.MALFORMED))
        assertNull(observations[2].value)
        assertTrue(observations[2].limitations.contains(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE))
    }

    @Test
    fun perFlowAndGlobalBoundsEvictMetadataWithoutRetainingPayload() {
        val collector = BoundedProtocolEvidenceCollector(
            ProtocolEvidenceConfiguration(
                enabled = true,
                consent = testConsent(),
                inspectCleartextHttp = true,
                maximumTrackedFlows = 1,
                maximumObservations = 1,
                maximumObservationsPerFlowDirection = 1,
            ),
        )
        val first = "GET /one HTTP/1.1\r\nHost: test\r\n\r\n".encodeToByteArray()
        val second = "GET /two HTTP/1.1\r\nHost: test\r\n\r\n".encodeToByteArray()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, first, 1L)
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, second, 2L)

        val snapshot = collector.snapshot()
        assertEquals(1, snapshot.observations.size)
        assertEquals(1L, snapshot.droppedObservations)
        assertEquals(ProtocolEvidenceValue.HttpRequest("GET", "HTTP/1.1"), snapshot.observations.single().value)
    }

    @Test
    fun requestTargetsAreOmittedUnlessSeparatelyConsented() {
        val request = ("GET /account/42 HTTP/1.1\r\nHost: api.example.test\r\n\r\n").encodeToByteArray()
        val collector = httpCollector()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 1L)

        val value = collector.snapshot().observations.single().value as ProtocolEvidenceValue.HttpRequest
        assertNull(value.target)
        assertNull(value.host)
        assertNull(value.absoluteUrl)
    }

    @Test
    fun consentedRequestTargetCaptureReconstructsTheUrl() {
        val request = ("GET /account/42 HTTP/1.1\r\nHost: api.example.test\r\n\r\n").encodeToByteArray()
        val collector = urlCollector()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 1L)

        val value = collector.snapshot().observations.single().value as ProtocolEvidenceValue.HttpRequest
        assertEquals("/account/42", value.target)
        assertEquals("api.example.test", value.host)
        assertEquals("http://api.example.test/account/42", value.absoluteUrl)
    }

    @Test
    fun credentialHeadersStayExcludedEvenWhenTargetsAreCaptured() {
        val request = (
            "GET /account/42 HTTP/1.1\r\n" +
                "Host: api.example.test\r\n" +
                "Authorization: Bearer never-retain\r\n" +
                "Cookie: session=never-retain\r\n\r\n"
            ).encodeToByteArray()
        val collector = urlCollector()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 1L)

        val observation = collector.snapshot().observations.single()
        assertTrue(observation.limitations.contains(ProtocolEvidenceLimitation.SENSITIVE_HEADERS_OMITTED))
        assertFalse(observation.toString().contains("never-retain"))
    }

    @Test
    fun anAbsoluteFormTargetIsRefusedRatherThanNormalised() {
        // Absolute-form can carry credentials in the authority, so it is dropped outright.
        val request = (
            "GET http://user:pass@evil.test/x HTTP/1.1\r\nHost: api.example.test\r\n\r\n"
            ).encodeToByteArray()
        val collector = urlCollector()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 1L)

        val value = collector.snapshot().observations.single().value as ProtocolEvidenceValue.HttpRequest
        assertNull(value.target)
        assertFalse(collector.snapshot().observations.single().toString().contains("pass"))
    }

    @Test
    fun anUnsafeHostHeaderIsRefused() {
        val request = ("GET /x HTTP/1.1\r\nHost: not a host\r\n\r\n").encodeToByteArray()
        val collector = urlCollector()
        collector.observeTcpPayload(flow, PacketDirection.OUTBOUND, request, 1L)

        val value = collector.snapshot().observations.single().value as ProtocolEvidenceValue.HttpRequest
        assertNull(value.host)
        assertNull(value.absoluteUrl)
    }

    private fun urlCollector() = BoundedProtocolEvidenceCollector(
        ProtocolEvidenceConfiguration(
            enabled = true,
            consent = testConsent(),
            inspectCleartextHttp = true,
            captureRequestTargets = true,
        ),
    )

    private fun tlsCollector() = BoundedProtocolEvidenceCollector(
        ProtocolEvidenceConfiguration(enabled = true, consent = testConsent(), inspectTlsClientHelloSni = true),
    )

    private fun httpCollector() = BoundedProtocolEvidenceCollector(
        ProtocolEvidenceConfiguration(enabled = true, consent = testConsent(), inspectCleartextHttp = true),
    )

    private fun testConsent() = ProtocolEvidenceConsent("protocol-evidence-test", 1L)

    private fun tlsClientHello(hostname: String): ByteArray = tlsClientHello(hostname.encodeToByteArray())

    private fun tlsClientHello(hostname: ByteArray): ByteArray {
        val serverName = byteArrayOf(0) + u16(hostname.size) + hostname
        val serverNameList = u16(serverName.size) + serverName
        val extension = u16(0) + u16(serverNameList.size) + serverNameList
        val hello = byteArrayOf(3, 3) + ByteArray(32) + byteArrayOf(0) +
            u16(2) + byteArrayOf(0x13, 0x01) + byteArrayOf(1, 0) + u16(extension.size) + extension
        val handshake = byteArrayOf(1) + u24(hello.size) + hello
        return byteArrayOf(22, 3, 1) + u16(handshake.size) + handshake
    }

    private fun u16(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    private fun u24(value: Int): ByteArray = byteArrayOf(
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )
}
