package app.apksentinel.engine.tlsinspection

import java.io.IOException
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import org.bouncycastle.tls.AlertDescription
import org.bouncycastle.tls.CertificateEntry
import org.bouncycastle.tls.CipherSuite
import org.bouncycastle.tls.DefaultTlsServer
import org.bouncycastle.tls.HandshakeMessageInput
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.SignatureScheme
import org.bouncycastle.tls.TlsCredentialedDecryptor
import org.bouncycastle.tls.TlsCredentialedSigner
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsServerContext
import org.bouncycastle.tls.TlsServerProtocol
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.jcajce.JcaDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider

/** What one drive of the leg produced. Buffers are freshly allocated and owned by the caller. */
class BcTlsServerLegResult(
    val outboundCiphertext: ByteArray,
    val plaintext: ByteArray,
    val handshakeComplete: Boolean,
    val closed: Boolean,
    val failure: TlsInspectionBridgeFailure? = null,
) {
    val failed: Boolean get() = failure != null
}

/**
 * The client-facing TLS leg, driven by BouncyCastle instead of JSSE.
 *
 * This exists for exactly one reason: key logging. JSSE gives no portable access to a
 * session's secrets, and on Android the default provider keeps them inside BoringSSL where
 * no Java reflection can reach them, so the only way to produce a key log is to own the
 * handshake. It is a deliberate, opt-in substitution for the JSSE server engine and is never
 * used unless the user turns key logging on.
 *
 * It replaces only the leg this app terminates, where the credentials are ours and there is
 * no peer to authenticate. The upstream leg deliberately stays on JSSE with system trust and
 * HTTPS endpoint identification: re-implementing peer verification is where interception
 * proxies get their CVEs, and a key log is not worth that trade.
 *
 * Non-blocking throughout - the host data plane owns the sockets, exactly as with JSSE.
 */
class BcTlsServerLeg(
    private val leafCertificate: X509Certificate,
    private val caCertificate: X509Certificate,
    private val leafPrivateKey: PrivateKey,
    private val offeredTls12: Boolean,
    private val offeredTls13: Boolean,
    secureRandom: SecureRandom = SecureRandom(),
    private val maximumPlaintextBytes: Int = 64 * 1_024,
) {
    private val crypto: JcaTlsCrypto =
        JcaTlsCryptoProvider().setProvider(BouncyCastleProvider()).create(secureRandom)
    private val sampler = BcTlsKeyLogSampler()
    private val protocol = SamplingServerProtocol()
    private val server = InspectionServer()
    private var started = false
    private var handshakeComplete = false
    private var pendingSecrets = mutableListOf<TlsKeyLogSecrets>()

    /** Begins the handshake. Must be called before any ciphertext is offered. */
    fun start() {
        check(!started) { "The BouncyCastle server leg is already started." }
        started = true
        protocol.accept(server)
    }

    /** Feeds ciphertext received from the app and drains whatever the leg produced. */
    fun offerCiphertext(ciphertext: ByteArray): BcTlsServerLegResult = drive {
        if (ciphertext.isNotEmpty()) protocol.offerInput(ciphertext)
    }

    /** Encrypts [plain] for the app. */
    fun writePlaintext(plain: ByteArray): BcTlsServerLegResult = drive {
        if (plain.isNotEmpty()) protocol.writeApplicationData(plain, 0, plain.size)
    }

    /** Sends close_notify and returns the resulting ciphertext. */
    fun close(): BcTlsServerLegResult = drive { runCatching { protocol.close() } }

    /** Key-log secrets observed since the last call. The caller owns and must zeroize them. */
    fun drainCapturedSecrets(): List<TlsKeyLogSecrets> {
        val drained = pendingSecrets
        pendingSecrets = mutableListOf()
        return drained
    }

    fun isHandshakeComplete(): Boolean = handshakeComplete

    fun negotiatedProtocol(): TlsInspectionNegotiatedProtocol? = runCatching {
        val version = server.exposedContext?.serverVersion ?: return@runCatching null
        if (!handshakeComplete) {
            null
        } else if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version)) {
            TlsInspectionNegotiatedProtocol.TLS_1_3
        } else {
            TlsInspectionNegotiatedProtocol.TLS_1_2
        }
    }.getOrNull()

    /** Zeroizes retained secrets and the sampler's comparison values. */
    fun dispose() {
        sampler.clear()
        pendingSecrets.forEach(::zeroize)
        pendingSecrets = mutableListOf()
        runCatching { protocol.close() }
    }

    private fun zeroize(secrets: TlsKeyLogSecrets) {
        secrets.clientRandom.fill(0)
        secrets.masterSecret?.fill(0)
        secrets.clientHandshakeTrafficSecret?.fill(0)
        secrets.serverHandshakeTrafficSecret?.fill(0)
        secrets.clientApplicationTrafficSecret?.fill(0)
        secrets.serverApplicationTrafficSecret?.fill(0)
        secrets.exporterSecret?.fill(0)
    }

    private inline fun drive(action: () -> Unit): BcTlsServerLegResult {
        if (!started) return failureResult(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        return try {
            action()
            // Sample around every drive rather than at a single handshake hook: TLS 1.3
            // rotates its traffic secrets in place and the transitions have no public callback.
            pendingSecrets += sampler.sample(server.exposedContext)
            val plaintext = readPlaintext()
            pendingSecrets += sampler.sample(server.exposedContext)
            val outbound = readOutbound()
            // Authoritative signal comes from the peer callback: `!isHandshaking` is also
            // true before the handshake starts and after it fails.
            BcTlsServerLegResult(
                outboundCiphertext = outbound,
                plaintext = plaintext,
                handshakeComplete = handshakeComplete,
                closed = protocol.isClosed,
            )
        } catch (_: TlsFatalAlert) {
            // A fatal alert on the leg facing the app is the app refusing our certificate,
            // which is the pinning-or-user-CA case rather than an internal failure.
            failureResult(TlsInspectionBridgeFailure.CERTIFICATE_PINNING_OR_CA_REJECTED)
        } catch (_: IOException) {
            failureResult(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        } catch (_: RuntimeException) {
            failureResult(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    private fun readOutbound(): ByteArray {
        val available = protocol.availableOutputBytes
        if (available <= 0) return EMPTY
        val buffer = ByteArray(available)
        val read = protocol.readOutput(buffer, 0, available)
        return if (read == available) buffer else buffer.copyOf(maxOf(read, 0))
    }

    private fun readPlaintext(): ByteArray {
        val available = minOf(protocol.availableInputBytes, maximumPlaintextBytes)
        if (available <= 0) return EMPTY
        val buffer = ByteArray(available)
        val read = protocol.readInput(buffer, 0, available)
        return if (read == available) buffer else buffer.copyOf(maxOf(read, 0))
    }

    private fun failureResult(reason: TlsInspectionBridgeFailure) = BcTlsServerLegResult(
        outboundCiphertext = runCatching { readOutbound() }.getOrDefault(EMPTY),
        plaintext = EMPTY,
        handshakeComplete = handshakeComplete,
        closed = true,
        failure = reason,
    )

    /**
     * Samples between handshake messages.
     *
     * BouncyCastle consumes a traffic secret as soon as it has derived the record keys from
     * it, so by the time `offerInput` returns the secret object is already destroyed and
     * reading it yields nothing. Overriding the per-message handler is the narrowest hook
     * that runs while the values are still live.
     */
    private inner class SamplingServerProtocol : TlsServerProtocol() {
        override fun handleHandshakeMessage(type: Short, buf: HandshakeMessageInput) {
            captureNow()
            super.handleHandshakeMessage(type, buf)
            captureNow()
        }
    }

    private fun captureNow() {
        runCatching { pendingSecrets.addAll(sampler.sample(server.exposedContext)) }
    }

    private inner class InspectionServer : DefaultTlsServer(crypto) {
        /** [DefaultTlsServer] keeps the context protected; the sampler has to read it. */
        val exposedContext: TlsServerContext? get() = context

        override fun getSupportedVersions(): Array<ProtocolVersion> = buildList {
            if (offeredTls13) add(ProtocolVersion.TLSv13)
            if (offeredTls12) add(ProtocolVersion.TLSv12)
        }.ifEmpty { listOf(ProtocolVersion.TLSv12) }.toTypedArray()

        override fun getSupportedCipherSuites(): IntArray = intArrayOf(
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        )

        override fun notifyHandshakeComplete() {
            super.notifyHandshakeComplete()
            handshakeComplete = true
            captureNow()
        }

        override fun getCredentials(): TlsCredentials = signerCredentials()

        override fun getECDSASignerCredentials(): TlsCredentialedSigner = signerCredentials()

        override fun getRSASignerCredentials(): TlsCredentialedSigner = signerCredentials()

        /**
         * Static-RSA key exchange is deliberately unavailable: it has no forward secrecy and
         * is absent from the offered suites, so reaching here is a negotiation bug.
         */
        override fun getRSAEncryptionCredentials(): TlsCredentialedDecryptor =
            throw TlsFatalAlert(AlertDescription.internal_error)

        private fun signerCredentials(): TlsCredentialedSigner {
            val activeContext = context ?: throw TlsFatalAlert(AlertDescription.internal_error)
            // `crypto` on the peer is the erased TlsCrypto; the Jca-typed one is the outer field.
            val jcaCrypto = this@BcTlsServerLeg.crypto
            val chain = arrayOf(
                jcaCrypto.createCertificate(leafCertificate.encoded),
                jcaCrypto.createCertificate(caCertificate.encoded),
            )
            val certificate = if (isTls13(activeContext)) {
                org.bouncycastle.tls.Certificate(
                    ByteArray(0),
                    chain.map { CertificateEntry(it, null) }.toTypedArray(),
                )
            } else {
                org.bouncycastle.tls.Certificate(chain)
            }
            return JcaDefaultTlsCredentialedSigner(
                TlsCryptoParameters(activeContext),
                jcaCrypto,
                leafPrivateKey,
                certificate,
                chooseSignatureAlgorithm(activeContext),
            )
        }

        private fun isTls13(activeContext: TlsServerContext): Boolean {
            val version = activeContext.serverVersion ?: return false
            return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version)
        }

        /**
         * Picks a scheme the leaf key can actually produce and the app actually offered.
         * TLS 1.3 forbids PKCS#1 signatures, so an RSA leaf must use PSS there.
         */
        private fun chooseSignatureAlgorithm(activeContext: TlsServerContext): SignatureAndHashAlgorithm {
            val preferred = when (leafPrivateKey.algorithm.uppercase()) {
                "EC", "ECDSA" -> intArrayOf(SignatureScheme.ecdsa_secp256r1_sha256)
                else -> if (isTls13(activeContext)) {
                    intArrayOf(SignatureScheme.rsa_pss_rsae_sha256)
                } else {
                    intArrayOf(SignatureScheme.rsa_pss_rsae_sha256, SignatureScheme.rsa_pkcs1_sha256)
                }
            }
            val offered = runCatching {
                activeContext.securityParametersHandshake
                    ?.clientSigAlgs
                    ?.filterIsInstance<SignatureAndHashAlgorithm>()
            }.getOrNull().orEmpty()
            val candidates = preferred.map(SignatureScheme::getSignatureAndHashAlgorithm)
            return candidates.firstOrNull { candidate -> offered.isEmpty() || candidate in offered }
                ?: candidates.first()
        }
    }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
