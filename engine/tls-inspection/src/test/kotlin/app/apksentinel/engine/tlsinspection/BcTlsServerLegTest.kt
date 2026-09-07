package app.apksentinel.engine.tlsinspection

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLEngineResult.HandshakeStatus
import javax.net.ssl.SSLParameters
import javax.net.ssl.TrustManagerFactory
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Drives a real JSSE client against the BouncyCastle server leg. These are the tests that
 * decide whether a key log is possible at all: they assert that a handshake actually
 * completes against a stock client, and that the secrets captured belong to that exact
 * session rather than being well-formed noise.
 */
class BcTlsServerLegTest {

    @Test
    fun aTls13HandshakeCompletesAndYieldsTrafficSecretsForTheRealClientRandom() {
        val session = handshake(listOf("TLSv1.3"))

        assertTrue(session.leg.isHandshakeComplete())
        assertEquals(TlsInspectionNegotiatedProtocol.TLS_1_3, session.leg.negotiatedProtocol())

        val lines = session.secrets.flatMap(TlsKeyLog::linesFor)
        // TLS 1.3 has no master secret to log; a CLIENT_RANDOM line here would make Wireshark
        // report a failed decryption rather than none.
        assertFalse(lines.any { it.startsWith(TlsKeyLog.LABEL_CLIENT_RANDOM + " ") })
        assertTrue(lines.any { it.startsWith(TlsKeyLog.LABEL_CLIENT_HANDSHAKE) })
        assertTrue(lines.any { it.startsWith(TlsKeyLog.LABEL_SERVER_HANDSHAKE) })
        assertTrue(lines.any { it.startsWith(TlsKeyLog.LABEL_CLIENT_APPLICATION) })
        assertTrue(lines.any { it.startsWith(TlsKeyLog.LABEL_SERVER_APPLICATION) })

        // Every line must carry the client random that was actually on the wire.
        assertTrue(lines.all { it.split(' ')[1] == session.clientRandomHex })
        // A TLS 1.3 traffic secret is a full hash length, never empty or truncated.
        assertTrue(lines.all { it.split(' ')[2].length >= 64 })
    }

    @Test
    fun aTls12HandshakeCompletesAndYieldsTheMasterSecretForTheRealClientRandom() {
        val session = handshake(listOf("TLSv1.2"))

        assertTrue(session.leg.isHandshakeComplete())
        assertEquals(TlsInspectionNegotiatedProtocol.TLS_1_2, session.leg.negotiatedProtocol())

        val lines = session.secrets.flatMap(TlsKeyLog::linesFor)
        val clientRandomLines = lines.filter { it.startsWith(TlsKeyLog.LABEL_CLIENT_RANDOM + " ") }
        assertEquals(1, clientRandomLines.size)
        assertEquals(session.clientRandomHex, clientRandomLines.single().split(' ')[1])
        // A TLS 1.2 master secret is 48 bytes; anything else means the wrong field was read.
        assertEquals(96, clientRandomLines.single().split(' ')[2].length)
    }

    @Test
    fun applicationDataSurvivesTheLegInBothDirections() {
        val session = handshake(listOf("TLSv1.3"))

        val request = "GET /health HTTP/1.1\r\nHost: test.example\r\n\r\n".toByteArray()
        val received = session.leg.offerCiphertext(wrapData(session.client, request))
        assertEquals(String(request), String(received.plaintext))

        val response = "HTTP/1.1 204 No Content\r\n\r\n".toByteArray()
        val encrypted = session.leg.writePlaintext(response)
        assertFalse(encrypted.failed)
        assertEquals(String(response), String(feed(session.client, encrypted.outboundCiphertext)))
    }

    @Test
    fun aClientThatRefusesTheCertificateNeverReachesAnEstablishedHandshake() {
        val ca = testCa()
        val leaf = leafFor(ca)
        val leg = BcTlsServerLeg(
            leafCertificate = leaf.certificate,
            caCertificate = ca.certificate,
            leafPrivateKey = leaf.keyPair.private,
            offeredTls12 = true,
            offeredTls13 = true,
        )
        leg.start()

        // The default trust manager has no reason to accept a freshly generated private CA.
        val untrusting = SSLContext.getInstance("TLS")
            .apply { init(null, null, SecureRandom()) }
            .createSSLEngine("test.example", 443)
            .apply {
                useClientMode = true
                sslParameters = sslParameters.apply { serverNames = listOf(SNIHostName("test.example")) }
                beginHandshake()
            }

        runCatching { drive(untrusting, leg, mutableListOf()) }

        assertFalse(leg.isHandshakeComplete())
    }

    @Test
    fun disposeDropsRetainedSecrets() {
        val session = handshake(listOf("TLSv1.3"))
        session.leg.dispose()
        assertTrue(session.leg.drainCapturedSecrets().isEmpty())
    }

    // ---- harness -------------------------------------------------------------------------

    private class Session(
        val leg: BcTlsServerLeg,
        val client: SSLEngine,
        val secrets: List<TlsKeyLogSecrets>,
        val clientRandomHex: String,
    )

    private fun handshake(protocols: List<String>): Session {
        val ca = testCa()
        val leaf = leafFor(ca)
        val leg = BcTlsServerLeg(
            leafCertificate = leaf.certificate,
            caCertificate = ca.certificate,
            leafPrivateKey = leaf.keyPair.private,
            offeredTls12 = protocols.contains("TLSv1.2"),
            offeredTls13 = protocols.contains("TLSv1.3"),
        )
        leg.start()
        val client = trustingClient(ca.certificate, protocols)
        val captured = mutableListOf<TlsKeyLogSecrets>()
        val clientRandomHex = drive(client, leg, captured)
        return Session(leg, client, captured, requireNotNull(clientRandomHex) { "No ClientHello was sent." })
    }

    /**
     * Runs the handshake to completion, following whatever the client asks for next.
     *
     * A TLS 1.3 client interleaves: it consumes ServerHello, then insists on sending its
     * change-cipher-spec before it will read the rest of the flight. A driver that only
     * alternates whole wraps and unwraps deadlocks there, which is why this follows
     * handshakeStatus one step at a time.
     *
     * Returns the client random observed on the wire.
     */
    private fun drive(
        client: SSLEngine,
        leg: BcTlsServerLeg,
        captured: MutableList<TlsKeyLogSecrets>,
    ): String? {
        var clientRandomHex: String? = null
        var fromServer = ByteBuffer.allocate(0)
        var guard = 0
        while (guard++ < 400) {
            when (client.handshakeStatus) {
                HandshakeStatus.NEED_TASK -> runTasks(client)

                HandshakeStatus.NEED_WRAP -> {
                    val destination = ByteBuffer.allocate(client.session.packetBufferSize)
                    client.wrap(EMPTY_BUFFER, destination)
                    val toServer = drain(destination)
                    if (toServer.isEmpty()) return clientRandomHex
                    if (clientRandomHex == null && toServer.size > 43) {
                        // record type(1) version(2) length(2) msg type(1) length(3) version(2)
                        clientRandomHex = toServer.copyOfRange(11, 43)
                            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
                    }
                    val result = leg.offerCiphertext(toServer)
                    captured += leg.drainCapturedSecrets()
                    if (result.failed) return clientRandomHex
                    fromServer = append(fromServer, result.outboundCiphertext)
                }

                HandshakeStatus.NOT_HANDSHAKING -> {
                    captured += leg.drainCapturedSecrets()
                    return clientRandomHex
                }

                else -> {
                    if (!fromServer.hasRemaining()) {
                        val result = leg.offerCiphertext(ByteArray(0))
                        captured += leg.drainCapturedSecrets()
                        fromServer = append(fromServer, result.outboundCiphertext)
                        if (!fromServer.hasRemaining()) return clientRandomHex
                    }
                    val destination = ByteBuffer.allocate(client.session.applicationBufferSize)
                    val result = client.unwrap(fromServer, destination)
                    if (result.status != SSLEngineResult.Status.OK) return clientRandomHex
                }
            }
        }
        return clientRandomHex
    }

    private fun append(existing: ByteBuffer, addition: ByteArray): ByteBuffer {
        if (addition.isEmpty()) return existing
        val combined = ByteArray(existing.remaining() + addition.size)
        existing.get(combined, 0, existing.remaining())
        addition.copyInto(combined, combined.size - addition.size)
        return ByteBuffer.wrap(combined)
    }

    /** Feeds ciphertext into a settled engine and returns any application data it yielded. */
    private fun feed(engine: SSLEngine, ciphertext: ByteArray): ByteArray {
        val source = ByteBuffer.wrap(ciphertext)
        val application = ByteArrayOutputStream()
        var guard = 0
        while (source.hasRemaining() && guard++ < 64) {
            if (engine.handshakeStatus == HandshakeStatus.NEED_TASK) {
                runTasks(engine)
                continue
            }
            val destination = ByteBuffer.allocate(engine.session.applicationBufferSize)
            val result = engine.unwrap(source, destination)
            application.write(drain(destination))
            if (result.status != SSLEngineResult.Status.OK) break
        }
        return application.toByteArray()
    }

    /** Encrypts application data once the handshake has settled. */
    private fun wrapData(engine: SSLEngine, plain: ByteArray): ByteArray {
        val source = ByteBuffer.wrap(plain)
        val collected = ByteArrayOutputStream()
        var guard = 0
        while (source.hasRemaining() && guard++ < 32) {
            val destination = ByteBuffer.allocate(engine.session.packetBufferSize)
            val result = engine.wrap(source, destination)
            collected.write(drain(destination))
            if (result.status != SSLEngineResult.Status.OK) break
        }
        return collected.toByteArray()
    }

    private fun runTasks(engine: SSLEngine) {
        while (true) (engine.delegatedTask ?: return).run()
    }

    private fun drain(buffer: ByteBuffer): ByteArray {
        buffer.flip()
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)
        return bytes
    }

    private fun trustingClient(ca: X509Certificate, protocols: List<String>): SSLEngine {
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("test-ca", ca)
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(keyStore) }
        val context = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, SecureRandom()) }
        return context.createSSLEngine("test.example", 443).apply {
            useClientMode = true
            enabledProtocols = protocols.toTypedArray()
            val parameters: SSLParameters = sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            parameters.serverNames = listOf(SNIHostName("test.example"))
            sslParameters = parameters
            beginHandshake()
        }
    }

    private class TestCertificate(val certificate: X509Certificate, val keyPair: KeyPair)

    private fun testCa(): TestCertificate {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2_048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val name = X500Name("CN=APK Sentinel Test CA")
        val certificate = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now),
                Date(now - 60_000L),
                Date(now + 86_400_000L),
                name,
                keyPair.public,
            )
                .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
                .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
                .build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)),
        )
        return TestCertificate(certificate, keyPair)
    }

    private fun leafFor(ca: TestCertificate): TestCertificate {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2_048) }.generateKeyPair()
        val certificate = TlsInspectionLeafCertificateFactory.generate(
            serverName = "test.example",
            caCertificate = ca.certificate,
            caPrivateKey = ca.keyPair.private,
            nowMillis = System.currentTimeMillis(),
            leafPublicKey = keyPair.public,
        )
        return TestCertificate(certificate, keyPair)
    }

    private companion object {
        val EMPTY_BUFFER: ByteBuffer = ByteBuffer.allocate(0)
    }
}
