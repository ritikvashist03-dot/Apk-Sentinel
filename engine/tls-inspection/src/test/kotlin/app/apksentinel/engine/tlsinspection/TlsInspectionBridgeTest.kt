package app.apksentinel.engine.tlsinspection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertPathValidatorException
import java.util.Date
import javax.net.ssl.SSLContext
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder

class TlsInspectionBridgeTest {
    @Test
    fun fragmentedClientHelloExtractsOnlyDnsSniAndTls12() {
        val parser = TlsClientHelloParser()
        val source = clientHello("api.example.test", listOf(0x0303, 0x0304))
        var result: TlsClientHelloParseResult = TlsClientHelloParseResult.NeedMore
        source.forEach { result = parser.offer(byteArrayOf(it)) }

        val ready = result as TlsClientHelloParseResult.Ready
        assertEquals("api.example.test", ready.hello.serverName)
        assertTrue(ready.hello.offeredTls12)
        assertTrue(ready.hello.offeredTls13)
    }

    @Test
    fun tls13OnlyNoSniMalformedAndOversizedInputsFailClosed() {
        val tls13Only = TlsClientHelloParser().offer(clientHello("api.example.test", listOf(0x0304)))
        assertTrue(tls13Only is TlsClientHelloParseResult.Ready)
        val tls13Ready = tls13Only as TlsClientHelloParseResult.Ready
        assertTrue(tls13Ready.hello.offeredTls13)
        assertTrue(!tls13Ready.hello.offeredTls12)

        val noSni = TlsClientHelloParser().offer(clientHello(null, listOf(0x0303)))
        assertEquals(TlsInspectionBridgeFailure.NO_SNI, (noSni as TlsClientHelloParseResult.Rejected).reason)

        val malformed = TlsClientHelloParser().offer(byteArrayOf(22, 3, 3, 0, 4, 2, 0, 0, 0))
        assertTrue(malformed is TlsClientHelloParseResult.Rejected)

        val quic = TlsClientHelloParser().offer(byteArrayOf(0xc0.toByte(), 0, 0, 0, 0))
        assertEquals(TlsInspectionBridgeFailure.QUIC_NOT_SUPPORTED, (quic as TlsClientHelloParseResult.Rejected).reason)

        val bounded = TlsClientHelloParser(maximumBytes = 1_024)
        assertEquals(
            TlsInspectionBridgeFailure.CLIENT_HELLO_TOO_LARGE,
            (bounded.offer(ByteArray(1_025)) as TlsClientHelloParseResult.Rejected).reason,
        )
    }

    @Test
    fun bridgeKeepsTls13OnlyAndTls12FallbackProviderBounds() {
        val (ca, keyPair) = testCa()
        val tls13 = TlsInspectionSslenegineBridge(
            ca,
            keyPair.private,
            plaintextConsumer = TlsInspectionBridgePlaintextConsumer { _, _, _ -> },
        )
        assertTrue(tls13.offerClientHello(clientHello("api.example.test", listOf(0x0304))) is TlsInspectionBridgeAcceptResult.Accepted)
        val server = runCatching { tls13.createServerEngine() }
        if ("TLSv1.3" in server.getOrNull()?.supportedProtocols.orEmpty()) {
            assertArrayEquals(arrayOf("TLSv1.3"), server.getOrThrow().enabledProtocols)
        } else {
            assertEquals(TlsInspectionBridgeFailure.UNSUPPORTED_PROTOCOL, (server.exceptionOrNull() as TlsInspectionBridgeException).reason)
        }

        val fallback = TlsInspectionSslenegineBridge(
            ca,
            keyPair.private,
            plaintextConsumer = TlsInspectionBridgePlaintextConsumer { _, _, _ -> },
        )
        assertTrue(fallback.offerClientHello(clientHello("api.example.test", listOf(0x0303, 0x0304))) is TlsInspectionBridgeAcceptResult.Accepted)
        val fallbackServer = fallback.createServerEngine()
        assertTrue("TLSv1.2" in fallbackServer.enabledProtocols)
    }

    @Test
    fun upstreamEnginePinsSniAndHttpsEndpointIdentificationToParsedHost() {
        val (ca, keyPair) = testCa()
        val bridge = TlsInspectionSslenegineBridge(
            ca,
            keyPair.private,
            plaintextConsumer = TlsInspectionBridgePlaintextConsumer { _, _, _ -> },
        )
        assertTrue(bridge.offerClientHello(clientHello("api.example.test", listOf(0x0303))) is TlsInspectionBridgeAcceptResult.Accepted)
        bridge.createServerEngine()
        val upstream = bridge.createUpstreamEngine(SSLContext.getDefault())
        assertEquals("HTTPS", upstream.sslParameters.endpointIdentificationAlgorithm)
        assertEquals("api.example.test", (upstream.sslParameters.serverNames.single() as javax.net.ssl.SNIHostName).asciiName)
    }

    @Test
    fun directionAndEphemeralSegmentAreExplicitAndZeroized() {
        var observed: TlsInspectionPlaintextDirection? = null
        val segment = EphemeralTlsDecryptedSegment("GET / HTTP/1.1\r\n".encodeToByteArray())
        val callback = TlsInspectionBridgePlaintextConsumer { direction, value, _ ->
            observed = direction
            value.useReadOnlyBytes { bytes -> assertNotNull(bytes.get()) }
        }
        callback.onPlaintext(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, segment, TlsInspectionHttpProtocol.HTTP_1_1)
        segment.zeroize()
        assertEquals(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, observed)
        assertEquals(0, segment.size)
    }

    @Test
    fun typedHandshakeMappingSeparatesTrustAndPinningSignals() {
        assertEquals(
            TlsInspectionBridgeFailure.UPSTREAM_TRUST_REJECTED,
            mapTlsHandshakeFailure(CertPathValidatorException("path")),
        )
        assertEquals(
            TlsInspectionBridgeFailure.CERTIFICATE_PINNING_REJECTED,
            mapTlsHandshakeFailure(javax.net.ssl.SSLHandshakeException("certificate pinning failure")),
        )
    }

    private fun testCa(): Pair<java.security.cert.X509Certificate, KeyPair> {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2_048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val cert = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                X500Name("CN=Test CA"), BigInteger("123456789"), Date(now - 60_000L), Date(now + 86_400_000L),
                X500Name("CN=Test CA"), keyPair.public,
            )
                .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
                .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
                .build(TlsContentSignerFactory.create("SHA256withRSA", keyPair.private)),
        )
        return cert to keyPair
    }

    private fun clientHello(serverName: String?, versions: List<Int>): ByteArray {
        val extensions = ByteArrayOutputStream()
        if (serverName != null) {
            val name = serverName.encodeToByteArray()
            val sniData = ByteArrayOutputStream().apply {
                write((name.size + 3) ushr 8)
                write(name.size + 3)
                write(0)
                write(name.size ushr 8)
                write(name.size)
                write(name)
            }.toByteArray()
            extensions.write(0)
            extensions.write(0)
            extensions.write(sniData.size ushr 8)
            extensions.write(sniData.size)
            extensions.write(sniData)
        }
        val versionData = ByteArrayOutputStream().apply {
            write(versions.size * 2)
            versions.forEach {
                write(it ushr 8)
                write(it)
            }
        }.toByteArray()
        extensions.write(0)
        extensions.write(43)
        extensions.write(versionData.size ushr 8)
        extensions.write(versionData.size)
        extensions.write(versionData)
        val ext = extensions.toByteArray()
        val body = ByteArrayOutputStream().apply {
            write(3); write(3)
            write(ByteArray(32))
            write(0)
            write(0); write(2); write(0x13); write(0x01)
            write(1); write(0)
            write(ext.size ushr 8); write(ext.size); write(ext)
        }.toByteArray()
        return ByteArrayOutputStream().apply {
            write(22); write(3); write(3)
            write((body.size + 4) ushr 8); write(body.size + 4)
            write(1)
            write((body.size ushr 16) and 0xff); write((body.size ushr 8) and 0xff); write(body.size)
            write(body)
        }.toByteArray()
    }
}
