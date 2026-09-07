package app.apksentinel.engine.tlsinspection

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import app.apksentinel.core.security.HostValidation
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.cert.CertificateException
import java.security.cert.CertPathValidatorException
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLParameters
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLEngineResult.HandshakeStatus
import javax.net.ssl.X509ExtendedKeyManager
import java.net.Socket
import java.security.Principal

/** Parser outcomes are explicit so a caller cannot treat a partial ClientHello as ready. */
sealed interface TlsClientHelloParseResult {
    data object NeedMore : TlsClientHelloParseResult
    data class Ready(val hello: TlsClientHello) : TlsClientHelloParseResult
    data class Rejected(val reason: TlsInspectionBridgeFailure) : TlsClientHelloParseResult
}

data class TlsClientHello(
    val serverName: String,
    val offeredTls12: Boolean,
    val offeredTls13: Boolean,
)

enum class TlsInspectionBridgeFailure {
    CLIENT_HELLO_TOO_LARGE,
    CIPHERTEXT_BUFFER_FULL,
    MALFORMED_CLIENT_HELLO,
    UNSUPPORTED_TLS_RECORD,
    UNSUPPORTED_PROTOCOL,
    TLS_PROVIDER_UNAVAILABLE,
    /** Kept for source compatibility; TLS 1.3-only ClientHello is now accepted when available. */
    @Deprecated("TLS 1.3-only ClientHello is negotiated or rejected as UNSUPPORTED_PROTOCOL")
    TLS_1_3_ONLY,
    NO_SNI,
    INVALID_SNI,
    QUIC_NOT_SUPPORTED,
    NON_HTTP,
    PLAINTEXT_TOO_LARGE,
    NO_UPSTREAM_PROTOCOL,
    /** Kept for source compatibility; use NO_UPSTREAM_PROTOCOL. */
    @Deprecated("Use NO_UPSTREAM_PROTOCOL")
    NO_UPSTREAM_TLS12,
    UPSTREAM_TRUST_REJECTED,
    USER_CA_REJECTED,
    CERTIFICATE_PINNING_REJECTED,
    CERTIFICATE_PINNING_OR_CA_REJECTED,
    ENGINE_FAILURE,
    CLOSED,
}

/**
 * Bounded, fragmentation-safe TLS record/ClientHello parser. It parses only
 * the SNI and supported-version extension, then wipes its input buffer.
 */
class TlsClientHelloParser(
    private val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
) {
    private val bytes = ByteArray(maximumBytes)
    private val handshake = ByteArray(maximumBytes)
    private var size = 0
    private var recordOffset = 0
    private var handshakeSize = 0
    private var expectedHandshakeSize: Int? = null
    private var terminal: TlsClientHelloParseResult? = null

    init {
        require(maximumBytes in 1_024..64 * 1_024)
    }

    @Synchronized
    fun offer(fragment: ByteArray): TlsClientHelloParseResult {
        terminal?.let { return it }
        if (fragment.isEmpty()) return TlsClientHelloParseResult.NeedMore
        if (fragment.size > maximumBytes - size) return reject(TlsInspectionBridgeFailure.CLIENT_HELLO_TOO_LARGE)
        fragment.copyInto(bytes, size)
        size += fragment.size
        return parseAvailableRecords()
    }

    @Synchronized
    fun clear() {
        bytes.fill(0)
        handshake.fill(0)
        size = 0
        recordOffset = 0
        handshakeSize = 0
        expectedHandshakeSize = null
        terminal = TlsClientHelloParseResult.Rejected(TlsInspectionBridgeFailure.CLOSED)
    }

    /** Parse only newly completed records; one-byte fragmentation is O(n), not O(n^2). */
    private fun parseAvailableRecords(): TlsClientHelloParseResult {
        while (true) {
            if (size - recordOffset < RECORD_HEADER_BYTES) return TlsClientHelloParseResult.NeedMore
            val contentType = bytes[recordOffset].toInt() and 0xff
            val major = bytes[recordOffset + 1].toInt() and 0xff
            val minor = bytes[recordOffset + 2].toInt() and 0xff
            val recordLength = u16(bytes, recordOffset + 3)
            if (recordOffset == 0 && contentType and 0x80 != 0) return reject(TlsInspectionBridgeFailure.QUIC_NOT_SUPPORTED)
            if (contentType != HANDSHAKE_CONTENT_TYPE || major != 3 || minor !in 1..3 || recordLength > MAX_TLS_RECORD_BYTES) {
                return reject(TlsInspectionBridgeFailure.UNSUPPORTED_TLS_RECORD)
            }
            val recordEnd = recordOffset + RECORD_HEADER_BYTES + recordLength
            if (recordEnd > size) return TlsClientHelloParseResult.NeedMore
            if (handshakeSize > maximumBytes - recordLength) return reject(TlsInspectionBridgeFailure.CLIENT_HELLO_TOO_LARGE)
            bytes.copyInto(handshake, handshakeSize, recordOffset + RECORD_HEADER_BYTES, recordEnd)
            handshakeSize += recordLength
            recordOffset = recordEnd
            if (expectedHandshakeSize == null && handshakeSize >= HANDSHAKE_HEADER_BYTES) {
                if ((handshake[0].toInt() and 0xff) != CLIENT_HELLO_TYPE) return reject(TlsInspectionBridgeFailure.MALFORMED_CLIENT_HELLO)
                val bodyLength = u24(handshake, 1)
                if (bodyLength > maximumBytes - HANDSHAKE_HEADER_BYTES) return reject(TlsInspectionBridgeFailure.CLIENT_HELLO_TOO_LARGE)
                expectedHandshakeSize = HANDSHAKE_HEADER_BYTES + bodyLength
            }
            val expected = expectedHandshakeSize ?: continue
            if (handshakeSize < expected) continue
            val parsed = parseClientHello(handshake, HANDSHAKE_HEADER_BYTES, expected - HANDSHAKE_HEADER_BYTES)
            handshake.fill(0)
            return when (parsed) {
                is TlsClientHelloParseResult.Ready -> {
                    bytes.fill(0)
                    terminal = parsed
                    parsed
                }
                is TlsClientHelloParseResult.Rejected -> reject(parsed.reason)
                TlsClientHelloParseResult.NeedMore -> TlsClientHelloParseResult.NeedMore
            }
        }
    }

    private fun parseClientHello(data: ByteArray, start: Int, length: Int): TlsClientHelloParseResult {
        val cursor = Cursor(data, start, start + length)
        val legacyMajor = cursor.u8() ?: return malformed()
        val legacyMinor = cursor.u8() ?: return malformed()
        if (legacyMajor != 3 || legacyMinor != 3) return reject(TlsInspectionBridgeFailure.UNSUPPORTED_TLS_RECORD)
        cursor.skip(32) ?: return malformed()
        val sessionIdLength = cursor.u8() ?: return malformed()
        cursor.skip(sessionIdLength) ?: return malformed()
        val cipherSuitesLength = cursor.u16() ?: return malformed()
        if (cipherSuitesLength == 0 || cipherSuitesLength % 2 != 0) return malformed()
        cursor.skip(cipherSuitesLength) ?: return malformed()
        val compressionLength = cursor.u8() ?: return malformed()
        if (compressionLength == 0) return malformed()
        cursor.skip(compressionLength) ?: return malformed()
        val extensionsLength = cursor.u16() ?: return malformed()
        val extensionsEnd = cursor.position + extensionsLength
        if (extensionsEnd > cursor.limit) return malformed()
        var sni: String? = null
        var offeredTls12 = true
        var offeredTls13 = false
        while (cursor.position < extensionsEnd) {
            val type = cursor.u16() ?: return malformed()
            val extensionLength = cursor.u16() ?: return malformed()
            if (cursor.position + extensionLength > extensionsEnd) return malformed()
            val extensionEnd = cursor.position + extensionLength
            when (type) {
                SERVER_NAME_EXTENSION -> {
                    val namesLength = cursor.u16() ?: return malformed()
                    val namesEnd = cursor.position + namesLength
                    if (namesEnd > extensionEnd) return malformed()
                    while (cursor.position < namesEnd) {
                        val nameType = cursor.u8() ?: return malformed()
                        val nameLength = cursor.u16() ?: return malformed()
                        if (nameType == HOST_NAME_TYPE && sni == null) {
                            val candidate = cursor.asciiLowercase(nameLength) ?: return malformed()
                            if (!isValidDnsName(candidate)) return reject(TlsInspectionBridgeFailure.INVALID_SNI)
                            sni = candidate
                        } else if (cursor.skip(nameLength) == null) return malformed()
                    }
                    if (cursor.position != namesEnd || cursor.position != extensionEnd) return malformed()
                }
                SUPPORTED_VERSIONS_EXTENSION -> {
                    val versionsLength = cursor.u8() ?: return malformed()
                    if (versionsLength % 2 != 0 || versionsLength != extensionLength - 1) return malformed()
                    offeredTls12 = false
                    repeat(versionsLength / 2) {
                        val version = cursor.u16() ?: return malformed()
                        if (version == TLS_1_2) offeredTls12 = true
                        if (version == TLS_1_3) offeredTls13 = true
                    }
                }
                else -> cursor.skip(extensionLength) ?: return malformed()
            }
            if (cursor.position != extensionEnd) return malformed()
        }
        if (cursor.position != extensionsEnd) return malformed()
        if (sni == null) return reject(TlsInspectionBridgeFailure.NO_SNI)
        if (!offeredTls12 && !offeredTls13) return reject(TlsInspectionBridgeFailure.UNSUPPORTED_PROTOCOL)
        return TlsClientHelloParseResult.Ready(TlsClientHello(sni, offeredTls12, offeredTls13))
    }

    private fun malformed(): TlsClientHelloParseResult = reject(TlsInspectionBridgeFailure.MALFORMED_CLIENT_HELLO)

    private fun wipeAndNeedMore(handshake: ByteArray): TlsClientHelloParseResult {
        handshake.fill(0)
        return TlsClientHelloParseResult.NeedMore
    }

    private fun reject(reason: TlsInspectionBridgeFailure): TlsClientHelloParseResult {
        val result = TlsClientHelloParseResult.Rejected(reason)
        bytes.fill(0)
        handshake.fill(0)
        terminal = result
        return result
    }

    private class Cursor(val data: ByteArray, var position: Int, val limit: Int) {
        fun u8(): Int? = if (position < limit) data[position++].toInt() and 0xff else null
        fun u16(): Int? = if (position + 2 <= limit) ((u8()!! shl 8) or u8()!!) else null
        fun skip(count: Int): Cursor? = if (count in 0..limit - position) apply { position += count } else null
        fun asciiLowercase(count: Int): String? {
            if (count !in 0..limit - position) return null
            val value = StringBuilder(count)
            repeat(count) {
                val c = data[position++].toInt() and 0xff
                if (c > 0x7f) return null
                value.append(c.toChar().lowercaseChar())
            }
            return value.toString()
        }
    }

    companion object {
        const val DEFAULT_MAXIMUM_BYTES = 32 * 1_024
        private const val RECORD_HEADER_BYTES = 5
        private const val HANDSHAKE_HEADER_BYTES = 4
        private const val MAX_TLS_RECORD_BYTES = 18_432
        private const val HANDSHAKE_CONTENT_TYPE = 22
        private const val CLIENT_HELLO_TYPE = 1
        private const val SERVER_NAME_EXTENSION = 0
        private const val SUPPORTED_VERSIONS_EXTENSION = 43
        private const val HOST_NAME_TYPE = 0
        private const val TLS_1_2 = 0x0303
        private const val TLS_1_3 = 0x0304
        private fun u16(data: ByteArray, offset: Int): Int = ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)
        private fun u24(data: ByteArray, offset: Int): Int =
            ((data[offset].toInt() and 0xff) shl 16) or ((data[offset + 1].toInt() and 0xff) shl 8) or (data[offset + 2].toInt() and 0xff)

        /**
         * Gates generation of an interception leaf certificate, so it uses the one strict
         * host validator rather than a local copy. The previous local version accepted any
         * Unicode letter, which meant a Cyrillic homograph the firewall and evidence layers
         * both reject would still get a certificate minted for it.
         */
        private fun isValidDnsName(value: String): Boolean = HostValidation.isValidDomain(value)
    }
}

object TlsInspectionLeafCertificateFactory {
    private val provider = BouncyCastleProvider()

    /** Generates a short-lived in-memory SAN leaf and never persists its key/certificate. */
    fun generate(
        serverName: String,
        caCertificate: X509Certificate,
        caPrivateKey: PrivateKey,
        nowMillis: Long,
        secureRandom: SecureRandom = SecureRandom(),
        leafPublicKey: PublicKey? = null,
    ): X509Certificate {
        require(serverName.length in 1..253 && serverName == serverName.lowercase())
        require(serverName.split('.').all { it.isNotEmpty() && it.length <= 63 && it.all { c -> c.isLetterOrDigit() || c == '-' } })
        require(caCertificate.basicConstraints >= 0)
        require(nowMillis > 0L)
        val notBefore = Date(maxOf(caCertificate.notBefore.time, nowMillis - 60_000L))
        val notAfter = Date(minOf(caCertificate.notAfter.time, nowMillis + 10L * 60L * 1_000L))
        require(notAfter.after(notBefore))
        val issuer = X500Name(caCertificate.subjectX500Principal.name)
        val subject = X500Name("CN=$serverName")
        val serial = generateSequence { BigInteger(96, secureRandom).takeIf { it.signum() > 0 } }.first()
        val signatureAlgorithm = when (caPrivateKey.algorithm.uppercase()) {
            "RSA" -> "SHA256withRSA"
            "EC", "ECDSA" -> "SHA256withECDSA"
            else -> throw IllegalArgumentException("Unsupported CA key algorithm")
        }
        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, leafPublicKey ?: caCertificate.publicKey,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
            .addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
            .addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, serverName)))
        val certificate = JcaX509CertificateConverter()
            .setProvider(provider)
            .getCertificate(
                builder.build(
                TlsContentSignerFactory.create(signatureAlgorithm, caPrivateKey),
                ),
            )
        certificate.verify(caCertificate.publicKey)
        certificate.checkValidity(Date(nowMillis))
        require(certificate.subjectAlternativeNames.orEmpty().any { san ->
            san is List<*> && san.size == 2 && san[1] == serverName
        })
        return certificate
    }
}

enum class TlsInspectionBridgeState { WAITING_FOR_CLIENT_HELLO, CLIENT_HELLO_ACCEPTED, HANDSHAKING, ESTABLISHED, FAILED, CLOSED }

enum class TlsInspectionPlaintextDirection { CLIENT_TO_UPSTREAM, UPSTREAM_TO_CLIENT }

enum class TlsInspectionNegotiatedProtocol { TLS_1_2, TLS_1_3 }

class TlsInspectionBridgeException(
    val reason: TlsInspectionBridgeFailure,
) : SSLException("TLS inspection bridge failed: $reason")

sealed interface TlsInspectionBridgeAcceptResult {
    data object NeedMore : TlsInspectionBridgeAcceptResult
    data class Accepted(val clientHello: TlsClientHello) : TlsInspectionBridgeAcceptResult
    data class Rejected(val reason: TlsInspectionBridgeFailure) : TlsInspectionBridgeAcceptResult
}

enum class TlsInspectionBridgeEngineStatus { PROGRESSED, NEED_MORE_INPUT, NEED_TASK, CLOSED, FAILED }

data class TlsInspectionBridgeEngineResult(
    val status: TlsInspectionBridgeEngineStatus,
    val outbound: ByteArray = ByteArray(0),
    val failure: TlsInspectionBridgeFailure? = null,
    val consumedCiphertextBytes: Int = 0,
    val producedPlaintextBytes: Int = 0,
    val consumedPlaintextBytes: Int = 0,
    val pendingCiphertextBytes: Int = 0,
) {
    val consumedBytes: Int get() = consumedCiphertextBytes
    val producedBytes: Int get() = producedPlaintextBytes
}

fun interface TlsInspectionBridgePlaintextConsumer {
    /** The segment is valid only during this callback and is zeroized before return. */
    fun onPlaintext(
        direction: TlsInspectionPlaintextDirection,
        segment: EphemeralTlsDecryptedSegment,
        protocol: TlsInspectionHttpProtocol,
    )
}

/** Source-compatible adapter for hosts that do not need direction labels. */
fun interface TlsInspectionBridgeLegacyPlaintextConsumer {
    fun onPlaintext(segment: EphemeralTlsDecryptedSegment, protocol: TlsInspectionHttpProtocol)
}

/** Naming alias for hosts that prefer to make the direction-aware contract explicit. */
typealias TlsInspectionBridgeDirectionalPlaintextConsumer = TlsInspectionBridgePlaintextConsumer

/**
 * SSLEngine bridge core. The host data plane owns sockets and drives the four
 * engine methods; this class owns protocol containment, mandatory SNI, TLS 1.2
 * and TLS 1.3 negotiation when supported, upstream HTTPS endpoint validation,
 * and plaintext lifetime. Calls are serialized; a callback may synchronously
 * call a wrap method to forward its ephemeral segment, but must not call unwrap
 * or close until the callback returns.
 */
class TlsInspectionSslenegineBridge(
    private val caCertificate: X509Certificate,
    private val caPrivateKey: PrivateKey,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val plaintextConsumer: TlsInspectionBridgePlaintextConsumer,
    private val maximumPlaintextBytes: Int = 4 * 1_024,
    private val maximumCiphertextBytes: Int = 64 * 1_024,
    /**
     * When present, the leg facing the app is driven by BouncyCastle instead of JSSE so its
     * TLS secrets can be logged, and every secret observed is handed here. Null - the
     * default - keeps the JSSE server engine and produces no key material at all.
     */
    private val keyLogSink: ((List<TlsKeyLogSecrets>) -> Unit)? = null,
) {
    /** Legacy two-argument callback constructor. The callback remains ephemeral and in-memory. */
    constructor(
        caCertificate: X509Certificate,
        caPrivateKey: PrivateKey,
        nowMillis: () -> Long = System::currentTimeMillis,
        plaintextConsumer: TlsInspectionBridgeLegacyPlaintextConsumer,
        maximumPlaintextBytes: Int = 4 * 1_024,
        maximumCiphertextBytes: Int = 64 * 1_024,
    ) : this(
        caCertificate,
        caPrivateKey,
        nowMillis = nowMillis,
        plaintextConsumer = TlsInspectionBridgePlaintextConsumer { _, segment, protocol ->
            plaintextConsumer.onPlaintext(segment, protocol)
        },
        maximumPlaintextBytes = maximumPlaintextBytes,
        maximumCiphertextBytes = maximumCiphertextBytes,
    )
    private val parser = TlsClientHelloParser()
    private var state = TlsInspectionBridgeState.WAITING_FOR_CLIENT_HELLO
    private var clientHello: TlsClientHello? = null
    private var serverEngine: SSLEngine? = null
    private var bcServerLeg: BcTlsServerLeg? = null
    private val bcPendingOutbound = java.io.ByteArrayOutputStream()
    private var upstreamEngine: SSLEngine? = null
    private var httpProtocol: TlsInspectionHttpProtocol? = null
    private var clientHandshakeComplete = false
    private var upstreamHandshakeComplete = false
    private var clientTlsProtocol: TlsInspectionNegotiatedProtocol? = null
    private var upstreamTlsProtocol: TlsInspectionNegotiatedProtocol? = null
    private var clientCloseSent = false
    private var upstreamCloseSent = false
    private val clientCiphertext = CiphertextQueue(maximumCiphertextBytes)
    private val upstreamCiphertext = CiphertextQueue(maximumCiphertextBytes)
    private val decryptedBytes = ByteArray(maximumPlaintextBytes)
    private val clientProtocolDetector = HttpProtocolDetector(clientPrefaceRequired = true)
    private val upstreamProtocolDetector = HttpProtocolDetector(clientPrefaceRequired = false)

    init {
        require(maximumPlaintextBytes in 256..16 * 1_024)
        require(maximumCiphertextBytes in 4 * 1_024..256 * 1_024)
        require(caCertificate.basicConstraints == 0)
    }

    @Synchronized
    fun offerClientHello(fragment: ByteArray): TlsInspectionBridgeAcceptResult {
        if (state != TlsInspectionBridgeState.WAITING_FOR_CLIENT_HELLO) return TlsInspectionBridgeAcceptResult.Rejected(TlsInspectionBridgeFailure.CLOSED)
        return when (val parsed = parser.offer(fragment)) {
            TlsClientHelloParseResult.NeedMore -> TlsInspectionBridgeAcceptResult.NeedMore
            is TlsClientHelloParseResult.Rejected -> fail(parsed.reason)
            is TlsClientHelloParseResult.Ready -> {
                clientHello = parsed.hello
                state = TlsInspectionBridgeState.CLIENT_HELLO_ACCEPTED
                TlsInspectionBridgeAcceptResult.Accepted(parsed.hello)
            }
        }
    }

    /** Create the local server engine with an in-memory SAN leaf and offered-version bounds. */
    @Synchronized
    fun createServerEngine(): SSLEngine {
        val hello = clientHello ?: throw IllegalStateException("ClientHello must be accepted first")
        check(state == TlsInspectionBridgeState.CLIENT_HELLO_ACCEPTED)
        return try {
            val (leaf, leafPrivateKey) = buildLeaf(hello)
            val keyManager = SingleLeafKeyManager(leafPrivateKey, arrayOf(leaf, caCertificate))
            val context = SSLContext.getInstance("TLS").apply { init(arrayOf(keyManager), null, null) }
            val engine = context.createSSLEngine()
            engine.useClientMode = false
            val enabled = compatibleProtocols(hello, engine.supportedProtocols)
            if (enabled.isEmpty()) throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.UNSUPPORTED_PROTOCOL)
            engine.enabledProtocols = enabled
            engine.beginHandshake()
            serverEngine = engine
            state = TlsInspectionBridgeState.HANDSHAKING
            engine
        } catch (failure: TlsInspectionBridgeException) {
            fail(failure.reason)
            throw failure
        } catch (_: NoSuchAlgorithmException) {
            fail(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
        } catch (_: GeneralSecurityException) {
            fail(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
        } catch (_: RuntimeException) {
            fail(TlsInspectionBridgeFailure.ENGINE_FAILURE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    /**
     * The caller supplies the normal system-trust SSLContext. HTTPS endpoint
     * identification and SNI are mandatory; no trust-all manager is accepted.
     */
    @Synchronized
    fun createUpstreamEngine(sslContext: SSLContext, port: Int = 443): SSLEngine {
        val hello = clientHello ?: throw IllegalStateException("ClientHello must be accepted first")
        check(state == TlsInspectionBridgeState.HANDSHAKING || state == TlsInspectionBridgeState.CLIENT_HELLO_ACCEPTED)
        return try {
            val engine = sslContext.createSSLEngine(hello.serverName, port)
            engine.useClientMode = true
            val enabled = compatibleProtocols(hello, engine.supportedProtocols)
            if (enabled.isEmpty()) {
                fail(TlsInspectionBridgeFailure.NO_UPSTREAM_PROTOCOL)
                throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.NO_UPSTREAM_PROTOCOL)
            }
            engine.enabledProtocols = enabled
            val parameters: SSLParameters = engine.sslParameters
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            parameters.serverNames = listOf(SNIHostName(hello.serverName))
            engine.sslParameters = parameters
            engine.beginHandshake()
            upstreamEngine = engine
            state = TlsInspectionBridgeState.HANDSHAKING
            engine
        } catch (failure: TlsInspectionBridgeException) {
            throw failure
        } catch (_: NoSuchAlgorithmException) {
            fail(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
        } catch (_: GeneralSecurityException) {
            fail(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
        } catch (_: RuntimeException) {
            fail(TlsInspectionBridgeFailure.ENGINE_FAILURE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    private fun buildLeaf(hello: TlsClientHello): Pair<X509Certificate, PrivateKey> {
        val leafKeyPair = generateLeafKeyPair(caPrivateKey)
        val leaf = TlsInspectionLeafCertificateFactory.generate(
            hello.serverName,
            caCertificate,
            caPrivateKey,
            nowMillis(),
            leafPublicKey = leafKeyPair.public,
        )
        check(leaf.publicKey.encoded.contentEquals(leafKeyPair.public.encoded))
        return leaf to leafKeyPair.private
    }

    /**
     * Creates the leg facing the app, choosing the implementation by whether a key log was
     * asked for. JSSE stays the default because it is the proven path; the BouncyCastle leg
     * exists only because JSSE cannot expose the secrets a key log needs.
     */
    @Synchronized
    fun createClientFacingLeg() {
        if (keyLogSink == null) {
            createServerEngine()
            return
        }
        val hello = clientHello ?: throw IllegalStateException("ClientHello must be accepted first")
        check(state == TlsInspectionBridgeState.CLIENT_HELLO_ACCEPTED)
        try {
            val (leaf, leafPrivateKey) = buildLeaf(hello)
            val leg = BcTlsServerLeg(
                leafCertificate = leaf,
                caCertificate = caCertificate,
                leafPrivateKey = leafPrivateKey,
                offeredTls12 = hello.offeredTls12,
                offeredTls13 = hello.offeredTls13,
                maximumPlaintextBytes = maximumCiphertextBytes,
            )
            leg.start()
            bcServerLeg = leg
            state = TlsInspectionBridgeState.HANDSHAKING
        } catch (failure: TlsInspectionBridgeException) {
            fail(failure.reason)
            throw failure
        } catch (_: GeneralSecurityException) {
            fail(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.TLS_PROVIDER_UNAVAILABLE)
        } catch (_: RuntimeException) {
            fail(TlsInspectionBridgeFailure.ENGINE_FAILURE)
            throw TlsInspectionBridgeException(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    private fun drainKeyLog(leg: BcTlsServerLeg) {
        val sink = keyLogSink ?: return
        val secrets = leg.drainCapturedSecrets()
        if (secrets.isNotEmpty()) runCatching { sink(secrets) }
    }

    /**
     * Buffers what the BouncyCastle leg produced so it leaves through the same
     * `wrapForClient` call the JSSE path uses. The host drains handshake output that way,
     * and returning it from unwrap instead would silently drop it.
     */
    private fun unwrapClientBc(ciphertext: ByteArray): TlsInspectionBridgeEngineResult {
        val leg = bcServerLeg ?: return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        if (state == TlsInspectionBridgeState.CLOSED) return failed(TlsInspectionBridgeFailure.CLOSED)
        if (state == TlsInspectionBridgeState.FAILED) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        val result = leg.offerCiphertext(ciphertext)
        drainKeyLog(leg)
        bcPendingOutbound.write(result.outboundCiphertext)
        result.failure?.let { return failEngine(it) }
        if (result.handshakeComplete && !clientHandshakeComplete) {
            clientHandshakeComplete = true
            clientTlsProtocol = leg.negotiatedProtocol()
        }
        if (result.plaintext.isNotEmpty()) {
            deliverClientPlaintext(result.plaintext)?.let { return failEngine(it) }
        }
        if (result.closed) {
            transitionClosed()
            return closedResult(
                consumedCiphertextBytes = ciphertext.size,
                producedPlaintextBytes = result.plaintext.size,
            )
        }
        return TlsInspectionBridgeEngineResult(
            status = TlsInspectionBridgeEngineStatus.PROGRESSED,
            consumedCiphertextBytes = ciphertext.size,
            producedPlaintextBytes = result.plaintext.size,
        )
    }

    private fun wrapClientBc(plain: ByteArray): TlsInspectionBridgeEngineResult {
        val leg = bcServerLeg ?: return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        if (state == TlsInspectionBridgeState.CLOSED) return failed(TlsInspectionBridgeFailure.CLOSED)
        if (state == TlsInspectionBridgeState.FAILED) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        if (plain.size > maximumPlaintextBytes) return failed(TlsInspectionBridgeFailure.PLAINTEXT_TOO_LARGE)
        if (plain.isNotEmpty() && !bothHandshakesComplete()) {
            return TlsInspectionBridgeEngineResult(TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT)
        }
        if (plain.isNotEmpty()) {
            val written = leg.writePlaintext(plain)
            drainKeyLog(leg)
            bcPendingOutbound.write(written.outboundCiphertext)
            written.failure?.let { return failEngine(it) }
        }
        val outbound = bcPendingOutbound.toByteArray()
        bcPendingOutbound.reset()
        if (outbound.size > maximumCiphertextBytes) {
            return failEngine(TlsInspectionBridgeFailure.CIPHERTEXT_BUFFER_FULL)
        }
        return TlsInspectionBridgeEngineResult(
            status = TlsInspectionBridgeEngineStatus.PROGRESSED,
            outbound = outbound,
            consumedPlaintextBytes = plain.size,
        )
    }

    /**
     * Runs decrypted client bytes through protocol detection and the plaintext consumer,
     * matching what the JSSE unwrap loop does. Returns a failure, or null when accepted.
     */
    private fun deliverClientPlaintext(plaintext: ByteArray): TlsInspectionBridgeFailure? {
        if (!bothHandshakesComplete()) return null
        return when (val detection = clientProtocolDetector.consume(plaintext, plaintext.size)) {
            HttpProtocolDetection.INVALID -> TlsInspectionBridgeFailure.NON_HTTP
            HttpProtocolDetection.NEED_MORE -> null
            is HttpProtocolDetection.READY -> {
                val protocol = detection.protocol
                if (httpProtocol != null && httpProtocol != protocol) {
                    return TlsInspectionBridgeFailure.NON_HTTP
                }
                httpProtocol = protocol
                val ephemeral = EphemeralTlsDecryptedSegment(detection.plaintext ?: plaintext.copyOf())
                try {
                    plaintextConsumer.onPlaintext(
                        TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM,
                        ephemeral,
                        protocol,
                    )
                } finally {
                    ephemeral.zeroize()
                }
                null
            }
        }
    }

    fun serverEngine(): SSLEngine? = serverEngine
    fun upstreamEngine(): SSLEngine? = upstreamEngine
    fun state(): TlsInspectionBridgeState = state
    fun clientProtocol(): TlsInspectionHttpProtocol? = clientProtocolDetector.protocol
    fun upstreamProtocol(): TlsInspectionHttpProtocol? = upstreamProtocolDetector.protocol
    fun clientTlsProtocol(): TlsInspectionNegotiatedProtocol? = clientTlsProtocol
    fun upstreamTlsProtocol(): TlsInspectionNegotiatedProtocol? = upstreamTlsProtocol

    /** Wraps bytes for the selected engine; encrypted bytes are returned transiently to the host. */
    @Synchronized
    fun wrapForClient(plain: ByteArray): TlsInspectionBridgeEngineResult =
        if (bcServerLeg != null) wrapClientBc(plain) else wrap(Direction.CLIENT, serverEngine, plain)
    @Synchronized
    fun wrapForUpstream(plain: ByteArray): TlsInspectionBridgeEngineResult = wrap(Direction.UPSTREAM, upstreamEngine, plain)

    /**
     * Convenience for a direction-aware callback: copies only for the duration
     * of the wrap call, then wipes the copy. The segment itself remains owned by
     * this bridge and is zeroized when the callback returns.
     */
    @Synchronized
    fun wrapForClient(segment: EphemeralTlsDecryptedSegment): TlsInspectionBridgeEngineResult =
        wrapSegment(Direction.CLIENT, serverEngine, segment)

    @Synchronized
    fun wrapForUpstream(segment: EphemeralTlsDecryptedSegment): TlsInspectionBridgeEngineResult =
        wrapSegment(Direction.UPSTREAM, upstreamEngine, segment)

    /** Unwraps one bounded ciphertext fragment and delivers plaintext only in the callback. */
    @Synchronized
    fun unwrapFromClient(ciphertext: ByteArray): TlsInspectionBridgeEngineResult =
        if (bcServerLeg != null) unwrapClientBc(ciphertext) else unwrap(Direction.CLIENT, serverEngine, ciphertext)
    @Synchronized
    fun unwrapFromUpstream(ciphertext: ByteArray): TlsInspectionBridgeEngineResult = unwrap(Direction.UPSTREAM, upstreamEngine, ciphertext)

    private fun wrapSegment(
        direction: Direction,
        engine: SSLEngine?,
        segment: EphemeralTlsDecryptedSegment,
    ): TlsInspectionBridgeEngineResult = segment.useReadOnlyBytes { view ->
        val copy = ByteArray(view.remaining())
        try {
            view.get(copy)
            wrap(direction, engine, copy)
        } finally {
            copy.fill(0)
        }
    }

    @Synchronized
    fun rejectUpstream(cause: Throwable): TlsInspectionBridgeEngineResult {
        val reason = mapTlsHandshakeFailure(cause)
        fail(reason)
        return TlsInspectionBridgeEngineResult(TlsInspectionBridgeEngineStatus.FAILED, failure = reason)
    }

    /** Explicit host signal when an app's pinning or user-CA policy rejects the leaf. */
    @Synchronized
    fun rejectUpstream(reason: TlsInspectionBridgeFailure): TlsInspectionBridgeEngineResult {
        require(reason == TlsInspectionBridgeFailure.CERTIFICATE_PINNING_REJECTED ||
            reason == TlsInspectionBridgeFailure.USER_CA_REJECTED ||
            reason == TlsInspectionBridgeFailure.UPSTREAM_TRUST_REJECTED ||
            reason == TlsInspectionBridgeFailure.CERTIFICATE_PINNING_OR_CA_REJECTED)
        fail(reason)
        return TlsInspectionBridgeEngineResult(TlsInspectionBridgeEngineStatus.FAILED, failure = reason)
    }

    @Synchronized
    fun close() {
        runCatching { serverEngine?.closeOutbound() }
        runCatching { upstreamEngine?.closeOutbound() }
        runCatching { bcServerLeg?.dispose() }
        bcServerLeg = null
        bcPendingOutbound.reset()
        parser.clear()
        clientCiphertext.clear()
        upstreamCiphertext.clear()
        decryptedBytes.fill(0)
        clientProtocolDetector.clear()
        upstreamProtocolDetector.clear()
        state = TlsInspectionBridgeState.CLOSED
    }

    /** Initiates one leg's TLS close_notify; drain the returned ciphertext before close(). */
    @Synchronized
    fun closeForClient(): TlsInspectionBridgeEngineResult = closeLeg(Direction.CLIENT, serverEngine)

    @Synchronized
    fun closeForUpstream(): TlsInspectionBridgeEngineResult = closeLeg(Direction.UPSTREAM, upstreamEngine)

    private fun closeLeg(direction: Direction, engine: SSLEngine?): TlsInspectionBridgeEngineResult {
        if (engine == null) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        return try {
            engine.closeOutbound()
            wrap(direction, engine, ByteArray(0))
        } catch (_: RuntimeException) {
            failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    private fun wrap(direction: Direction, engine: SSLEngine?, plain: ByteArray): TlsInspectionBridgeEngineResult {
        if (state == TlsInspectionBridgeState.CLOSED) return failed(TlsInspectionBridgeFailure.CLOSED)
        if (state == TlsInspectionBridgeState.FAILED) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        if (engine == null) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        if (plain.size > maximumPlaintextBytes) return failed(TlsInspectionBridgeFailure.PLAINTEXT_TOO_LARGE)
        if (plain.isNotEmpty() && !bothHandshakesComplete()) {
            return TlsInspectionBridgeEngineResult(TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT)
        }
        val initialPacketCapacity = engine.session.packetBufferSize.coerceAtLeast(16 * 1_024)
        if (initialPacketCapacity > maximumCiphertextBytes) {
            return failEngine(TlsInspectionBridgeFailure.CIPHERTEXT_BUFFER_FULL)
        }
        var output = ByteBuffer.allocate(initialPacketCapacity)
        var consumedTotal = 0
        var lastResult: SSLEngineResult? = null
        return try {
            var first = true
            repeat(MAX_WRAP_ITERATIONS) {
                if (!runDelegatedTasks(engine)) return failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
                val input = if (first) ByteBuffer.wrap(plain) else ByteBuffer.allocate(0)
                first = false
                val result = engine.wrap(input, output)
                lastResult = result
                consumedTotal += result.bytesConsumed()
                updateHandshake(direction, result, engine)
                if (!runDelegatedTasks(engine)) return failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
                when (result.status) {
                    SSLEngineResult.Status.BUFFER_OVERFLOW -> {
                        if (output.capacity() >= maximumCiphertextBytes) return failEngine(TlsInspectionBridgeFailure.CIPHERTEXT_BUFFER_FULL)
                        val larger = ByteBuffer.allocate((output.capacity() * 2).coerceAtMost(maximumCiphertextBytes))
                        output.flip()
                        larger.put(output)
                        output = larger
                    }
                    SSLEngineResult.Status.CLOSED -> {
                        output.flip()
                        val closeBytes = ByteArray(output.remaining()).also { output.get(it) }
                        markOutboundClosed(direction)
                        return closedResult(outbound = closeBytes, consumedPlaintextBytes = consumedTotal)
                    }
                    else -> {
                        if (plain.isNotEmpty() || result.bytesProduced() == 0 || result.handshakeStatus != HandshakeStatus.NEED_WRAP) return@repeat
                    }
                }
            }
            output.flip()
            val outbound = ByteArray(output.remaining()).also { output.get(it) }
            val result = lastResult
            TlsInspectionBridgeEngineResult(
                status = when {
                    result == null -> TlsInspectionBridgeEngineStatus.PROGRESSED
                    result.handshakeStatus == HandshakeStatus.NEED_TASK -> TlsInspectionBridgeEngineStatus.NEED_TASK
                    result.handshakeStatus == HandshakeStatus.NEED_UNWRAP -> TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT
                    else -> TlsInspectionBridgeEngineStatus.PROGRESSED
                },
                outbound = outbound,
                consumedPlaintextBytes = consumedTotal,
            )
        } catch (_: SSLException) {
            failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        } catch (_: RuntimeException) {
            failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    private fun unwrap(direction: Direction, engine: SSLEngine?, ciphertext: ByteArray): TlsInspectionBridgeEngineResult {
        if (state == TlsInspectionBridgeState.CLOSED) return failed(TlsInspectionBridgeFailure.CLOSED)
        if (state == TlsInspectionBridgeState.FAILED) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        if (engine == null) return failed(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        val queue = if (direction == Direction.CLIENT) clientCiphertext else upstreamCiphertext
        if (!queue.append(ciphertext)) return failEngine(TlsInspectionBridgeFailure.CIPHERTEXT_BUFFER_FULL)
        var consumedTotal = 0
        var producedTotal = 0
        var underflow = false
        var lastHandshakeStatus = engine.handshakeStatus
        return try {
            if (!runDelegatedTasks(engine)) return failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
            repeat(MAX_UNWRAP_ITERATIONS) {
                if (queue.isEmpty()) return@repeat
                val input = queue.buffer()
                val output = ByteBuffer.wrap(decryptedBytes)
                val result = engine.unwrap(input, output)
                val consumed = input.position()
                if (consumed > 0) {
                    queue.discard(consumed)
                    consumedTotal += consumed
                }
                val produced = output.position()
                producedTotal += produced
                if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    return failEngine(TlsInspectionBridgeFailure.PLAINTEXT_TOO_LARGE)
                }
                if (result.status == SSLEngineResult.Status.CLOSED) {
                    transitionClosed()
                    return closedResult(consumedCiphertextBytes = consumedTotal, producedPlaintextBytes = producedTotal)
                }
                updateHandshake(direction, result, engine)
                lastHandshakeStatus = result.handshakeStatus
                if (!runDelegatedTasks(engine)) return failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
                if (produced > 0) {
                    if (bothHandshakesComplete()) {
                        val detector = if (direction == Direction.CLIENT) clientProtocolDetector else upstreamProtocolDetector
                        when (val detection = detector.consume(decryptedBytes, produced)) {
                            HttpProtocolDetection.INVALID -> return failEngine(TlsInspectionBridgeFailure.NON_HTTP)
                            HttpProtocolDetection.NEED_MORE -> Unit
                            is HttpProtocolDetection.READY -> {
                                val protocol = detection.protocol
                                if (httpProtocol != null && httpProtocol != protocol) return failEngine(TlsInspectionBridgeFailure.NON_HTTP)
                                httpProtocol = protocol
                                val callbackBytes = detection.plaintext ?: decryptedBytes.copyOfRange(0, produced)
                                val ephemeral = EphemeralTlsDecryptedSegment(callbackBytes)
                                try {
                                    val callbackDirection = if (direction == Direction.CLIENT) {
                                        TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM
                                    } else {
                                        TlsInspectionPlaintextDirection.UPSTREAM_TO_CLIENT
                                    }
                                    plaintextConsumer.onPlaintext(callbackDirection, ephemeral, protocol)
                                } finally {
                                    ephemeral.zeroize()
                                }
                            }
                        }
                    }
                    decryptedBytes.fill(0, 0, produced)
                }
                underflow = result.status == SSLEngineResult.Status.BUFFER_UNDERFLOW
                if (underflow || (consumed == 0 && produced == 0)) return@repeat
            }
            TlsInspectionBridgeEngineResult(
                status = when {
                    underflow || lastHandshakeStatus == HandshakeStatus.NEED_UNWRAP -> TlsInspectionBridgeEngineStatus.NEED_MORE_INPUT
                    else -> TlsInspectionBridgeEngineStatus.PROGRESSED
                },
                consumedCiphertextBytes = consumedTotal,
                producedPlaintextBytes = producedTotal,
                pendingCiphertextBytes = queue.size,
            )
        } catch (failure: SSLHandshakeException) {
            val reason = if (direction == Direction.CLIENT) {
                if (failure.causes().any { it.message?.contains("pin", ignoreCase = true) == true }) {
                    TlsInspectionBridgeFailure.CERTIFICATE_PINNING_REJECTED
                } else {
                    TlsInspectionBridgeFailure.USER_CA_REJECTED
                }
            } else {
                mapTlsHandshakeFailure(failure)
            }
            failEngine(reason)
        } catch (_: SSLException) {
            failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        } catch (_: RuntimeException) {
            failEngine(TlsInspectionBridgeFailure.ENGINE_FAILURE)
        }
    }

    private fun runDelegatedTasks(engine: SSLEngine): Boolean {
        var tasks = 0
        while (engine.handshakeStatus == HandshakeStatus.NEED_TASK) {
            if (++tasks > MAX_DELEGATED_TASKS) return false
            val task = engine.delegatedTask ?: return false
            task.run()
        }
        return engine.handshakeStatus != HandshakeStatus.NEED_TASK
    }

    private fun updateHandshake(direction: Direction, result: SSLEngineResult, engine: SSLEngine) {
        val complete = result.handshakeStatus == HandshakeStatus.FINISHED ||
            (result.handshakeStatus == HandshakeStatus.NOT_HANDSHAKING && engine.handshakeStatus == HandshakeStatus.NOT_HANDSHAKING)
        if (direction == Direction.CLIENT) {
            clientHandshakeComplete = clientHandshakeComplete || complete
            if (complete) clientTlsProtocol = protocolOf(engine.session.protocol)
        } else {
            upstreamHandshakeComplete = upstreamHandshakeComplete || complete
            if (complete) upstreamTlsProtocol = protocolOf(engine.session.protocol)
        }
        if (bothHandshakesComplete()) state = TlsInspectionBridgeState.ESTABLISHED
    }

    private fun bothHandshakesComplete(): Boolean =
        clientHandshakeComplete && upstreamHandshakeComplete && serverEngine != null && upstreamEngine != null

    private fun failEngine(reason: TlsInspectionBridgeFailure): TlsInspectionBridgeEngineResult {
        failBridge(reason)
        return failed(reason)
    }

    private fun transitionClosed() {
        clientCiphertext.clear()
        upstreamCiphertext.clear()
        decryptedBytes.fill(0)
        parser.clear()
        clientProtocolDetector.clear()
        upstreamProtocolDetector.clear()
        state = TlsInspectionBridgeState.CLOSED
    }

    private fun markOutboundClosed(direction: Direction) {
        if (direction == Direction.CLIENT) clientCloseSent = true else upstreamCloseSent = true
        if (clientCloseSent && upstreamCloseSent) transitionClosed()
    }

    private fun closedResult(
        outbound: ByteArray = ByteArray(0),
        consumedCiphertextBytes: Int = 0,
        producedPlaintextBytes: Int = 0,
        consumedPlaintextBytes: Int = 0,
    ) = TlsInspectionBridgeEngineResult(
        status = TlsInspectionBridgeEngineStatus.CLOSED,
        outbound = outbound,
        consumedCiphertextBytes = consumedCiphertextBytes,
        producedPlaintextBytes = producedPlaintextBytes,
        consumedPlaintextBytes = consumedPlaintextBytes,
    )

    private fun failBridge(reason: TlsInspectionBridgeFailure) {
        if (state == TlsInspectionBridgeState.CLOSED) return
        state = TlsInspectionBridgeState.FAILED
        clientCiphertext.clear()
        upstreamCiphertext.clear()
        decryptedBytes.fill(0)
        parser.clear()
        clientProtocolDetector.clear()
        upstreamProtocolDetector.clear()
    }

    private enum class Direction { CLIENT, UPSTREAM }

    private fun compatibleProtocols(hello: TlsClientHello, supported: Array<String>): Array<String> {
        val available = supported.toSet()
        return buildList {
            // Preserve TLS 1.3 preference when both versions are offered; SSLEngine
            // then performs normal provider negotiation without a forced downgrade.
            if (hello.offeredTls13 && "TLSv1.3" in available) add("TLSv1.3")
            if (hello.offeredTls12 && "TLSv1.2" in available) add("TLSv1.2")
        }.toTypedArray()
    }

    private fun protocolOf(value: String): TlsInspectionNegotiatedProtocol? = when (value) {
        "TLSv1.2" -> TlsInspectionNegotiatedProtocol.TLS_1_2
        "TLSv1.3" -> TlsInspectionNegotiatedProtocol.TLS_1_3
        else -> null
    }

    private class CiphertextQueue(private val capacity: Int) {
        private val bytes = ByteArray(capacity)
        var size: Int = 0
            private set
        fun isEmpty(): Boolean = size == 0
        fun append(input: ByteArray): Boolean {
            if (input.size > capacity - size) return false
            input.copyInto(bytes, size)
            size += input.size
            return true
        }
        fun buffer(): ByteBuffer = ByteBuffer.wrap(bytes, 0, size).slice()
        fun discard(count: Int) {
            if (count <= 0) return
            if (count >= size) {
                bytes.fill(0, 0, size)
                size = 0
                return
            }
            bytes.copyInto(bytes, 0, count, size)
            bytes.fill(0, size - count, size)
            size -= count
        }
        fun clear() {
            bytes.fill(0)
            size = 0
        }
    }

    private sealed interface HttpProtocolDetection {
        data object NEED_MORE : HttpProtocolDetection
        data object INVALID : HttpProtocolDetection
        data class READY(
            val protocol: TlsInspectionHttpProtocol,
            /** The complete not-yet-delivered prefix on first detection, or this chunk thereafter. */
            val plaintext: ByteArray? = null,
        ) : HttpProtocolDetection
    }

    /** Bounded protocol detector: client preface or HTTP/1.1 line; upstream SETTINGS or response line. */
    private inner class HttpProtocolDetector(private val clientPrefaceRequired: Boolean) {
        private val prefix = ByteArray(HTTP_PREFIX_LIMIT)
        private var prefixSize = 0
        private var inspectedPrefix = 0
        private var deliveredPrefix = 0
        private var phase = 0 // 0 unknown, 1 HTTP/1.1, 2 HTTP/2
        private val frames = Http2FrameValidator()
        var protocol: TlsInspectionHttpProtocol? = null
            private set

        fun consume(data: ByteArray, length: Int): HttpProtocolDetection {
            if (length <= 0) return HttpProtocolDetection.NEED_MORE
            if (protocol == TlsInspectionHttpProtocol.HTTP_1_1) {
                return HttpProtocolDetection.READY(protocol!!, data.copyOfRange(0, length))
            }
            if (phase == 2) {
                return if (frames.consume(data, 0, length)) {
                    HttpProtocolDetection.READY(TlsInspectionHttpProtocol.HTTP_2, data.copyOfRange(0, length))
                } else HttpProtocolDetection.INVALID
            }
            if (prefixSize > HTTP_PREFIX_LIMIT - length) return HttpProtocolDetection.INVALID
            data.copyInto(prefix, prefixSize, 0, length)
            prefixSize += length
            if (clientPrefaceRequired) {
                val preface = HTTP2_PREFACE
                val comparable = minOf(prefixSize, preface.size)
                for (index in 0 until comparable) if (prefix[index] != preface[index]) {
                    phase = 1
                    return detectHttp1()
                }
                if (prefixSize < preface.size) return HttpProtocolDetection.NEED_MORE
                phase = 2
                protocol = TlsInspectionHttpProtocol.HTTP_2
                val remaining = prefixSize - preface.size
                if (remaining > 0 && !frames.consume(prefix, preface.size, remaining)) return HttpProtocolDetection.INVALID
                return HttpProtocolDetection.READY(protocol!!, undispatchedPrefix())
            }
            val responsePrefix = byteArrayOf('H'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte(), 'P'.code.toByte(), '/'.code.toByte(), '1'.code.toByte(), '.'.code.toByte(), '1'.code.toByte(), ' '.code.toByte())
            val comparable = minOf(prefixSize, responsePrefix.size)
            var responseMatches = true
            for (index in 0 until comparable) if (prefix[index] != responsePrefix[index]) responseMatches = false
            if (responseMatches && prefixSize < responsePrefix.size) return HttpProtocolDetection.NEED_MORE
            if (responseMatches) {
                phase = 1
                protocol = TlsInspectionHttpProtocol.HTTP_1_1
                return if (validHttp1Response(prefix, prefixSize)) {
                    HttpProtocolDetection.READY(protocol!!, undispatchedPrefix())
                } else HttpProtocolDetection.NEED_MORE
            }
            if (prefixSize - inspectedPrefix > 0) {
                if (!frames.consume(prefix, inspectedPrefix, prefixSize - inspectedPrefix)) return HttpProtocolDetection.INVALID
                inspectedPrefix = prefixSize
                if (frames.started) {
                    phase = 2
                    protocol = TlsInspectionHttpProtocol.HTTP_2
                    return HttpProtocolDetection.READY(protocol!!, undispatchedPrefix())
                }
            }
            return HttpProtocolDetection.NEED_MORE
        }

        fun clear() {
            prefix.fill(0)
            prefixSize = 0
            inspectedPrefix = 0
            deliveredPrefix = 0
            phase = 0
            protocol = null
            frames.clear()
        }

        private fun detectHttp1(): HttpProtocolDetection {
            if (!validHttp1Request(prefix, prefixSize)) return if (hasCrlf(prefix, prefixSize) || prefixSize >= HTTP_PREFIX_LIMIT) HttpProtocolDetection.INVALID else HttpProtocolDetection.NEED_MORE
            phase = 1
            protocol = TlsInspectionHttpProtocol.HTTP_1_1
            return HttpProtocolDetection.READY(protocol!!, undispatchedPrefix())
        }

        private fun undispatchedPrefix(): ByteArray {
            val pending = prefix.copyOfRange(deliveredPrefix, prefixSize)
            // Protocol detection is complete for this prefix. Do not retain
            // request/response bytes after handing the copy to the bridge.
            prefix.fill(0)
            prefixSize = 0
            inspectedPrefix = 0
            deliveredPrefix = 0
            return pending
        }

        private fun validHttp1Request(data: ByteArray, length: Int): Boolean {
            val lineEnd = findCrlf(data, length)
            if (lineEnd < 0) return false
            var firstSpace = -1
            var secondSpace = -1
            for (i in 0 until lineEnd) if (data[i] == ' '.code.toByte()) {
                if (firstSpace < 0) firstSpace = i else { secondSpace = i; break }
            }
            if (firstSpace !in 1..15 || secondSpace <= firstSpace + 1) return false
            if (!validMethod(data, firstSpace)) return false
            return matches(data, secondSpace + 1, "HTTP/1.1".encodeToByteArray(), lineEnd - secondSpace - 1)
        }

        private fun validHttp1Response(data: ByteArray, length: Int): Boolean {
            val lineEnd = findCrlf(data, length)
            if (lineEnd < 0) return false
            return lineEnd >= 12 && data[9] == ' '.code.toByte() && (data[10].toInt() and 0xff) in 48..57 && (data[11].toInt() and 0xff) in 48..57
        }

        private fun validMethod(data: ByteArray, length: Int): Boolean {
            val methods = arrayOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT")
            return methods.any { matches(data, 0, it.encodeToByteArray(), length) }
        }
    }

    private class Http2FrameValidator {
        private val header = ByteArray(9)
        private var headerSize = 0
        private var payloadRemaining = 0
        private var firstFrame = true
        var started = false
            private set
        fun consume(data: ByteArray, offset: Int, length: Int): Boolean {
            var index = offset
            val end = offset + length
            while (index < end) {
                if (payloadRemaining > 0) {
                    val take = minOf(payloadRemaining, end - index)
                    payloadRemaining -= take
                    index += take
                    continue
                }
                header[headerSize++] = data[index++]
                if (headerSize < 9) continue
                val frameLength = ((header[0].toInt() and 0xff) shl 16) or ((header[1].toInt() and 0xff) shl 8) or (header[2].toInt() and 0xff)
                val type = header[3].toInt() and 0xff
                val flags = header[4].toInt() and 0xff
                val stream = ((header[5].toInt() and 0x7f) shl 24) or ((header[6].toInt() and 0xff) shl 16) or ((header[7].toInt() and 0xff) shl 8) or (header[8].toInt() and 0xff)
                if (type > 0x9 || stream < 0 || frameLength > if (type == 0x4) 65_535 else 16_384) return false
                if (firstFrame && (type != 0x4 || stream != 0 || (flags and 0x1 != 0 && frameLength != 0) || frameLength % 6 != 0)) return false
                if (type == 0x4 && stream != 0) return false
                payloadRemaining = frameLength
                firstFrame = false
                started = true
                headerSize = 0
            }
            return true
        }
        fun clear() {
            header.fill(0)
            headerSize = 0
            payloadRemaining = 0
            firstFrame = true
            started = false
        }
    }

    private fun findCrlf(data: ByteArray, length: Int): Int {
        for (i in 1 until length) if (data[i - 1] == '\r'.code.toByte() && data[i] == '\n'.code.toByte()) return i - 1
        return -1
    }

    private fun hasCrlf(data: ByteArray, length: Int): Boolean = findCrlf(data, length) >= 0

    private fun matches(data: ByteArray, offset: Int, expected: ByteArray, available: Int): Boolean {
        if (available != expected.size || offset < 0 || offset + expected.size > data.size) return false
        for (i in expected.indices) if (data[offset + i] != expected[i]) return false
        return true
    }

    private fun fail(reason: TlsInspectionBridgeFailure): TlsInspectionBridgeAcceptResult.Rejected {
        failBridge(reason)
        return TlsInspectionBridgeAcceptResult.Rejected(reason)
    }

    private fun failed(reason: TlsInspectionBridgeFailure) = TlsInspectionBridgeEngineResult(
        TlsInspectionBridgeEngineStatus.FAILED,
        failure = reason,
    )

    private companion object {
        const val MAX_UNWRAP_ITERATIONS = 64
        const val MAX_WRAP_ITERATIONS = 64
        const val MAX_DELEGATED_TASKS = 32
        const val HTTP_PREFIX_LIMIT = 1_024
        val HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".encodeToByteArray()
    }

    private fun generateLeafKeyPair(caPrivateKey: PrivateKey): KeyPair {
        val algorithm = when (caPrivateKey.algorithm.uppercase()) {
            "RSA" -> "RSA"
            "EC", "ECDSA" -> "EC"
            else -> throw IllegalArgumentException("Unsupported CA key algorithm")
        }
        return KeyPairGenerator.getInstance(algorithm).apply {
            if (algorithm == "RSA") initialize(2_048)
            else initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
    }

    private class SingleLeafKeyManager(
        private val privateKey: PrivateKey,
        private val chain: Array<X509Certificate>,
    ) : X509ExtendedKeyManager() {
        private val alias = "tls-inspection-leaf"
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? = null
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf(alias)
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String = alias
        override fun getCertificateChain(alias: String?): Array<X509Certificate> = if (alias == this.alias) chain.copyOf() else emptyArray()
        override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == this.alias) privateKey else null
        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? = null
        override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?): String = alias
    }
}

/** Correctly maps common upstream failures without bypassing trust or pinning. */
fun mapTlsHandshakeFailure(cause: Throwable): TlsInspectionBridgeFailure = when {
    cause.causes().any { it is CertPathValidatorException } -> TlsInspectionBridgeFailure.UPSTREAM_TRUST_REJECTED
    cause.causes().any { it is CertificateException } -> TlsInspectionBridgeFailure.USER_CA_REJECTED
    cause.causes().any { it is SSLHandshakeException && it.message?.contains("pin", ignoreCase = true) == true } ->
        TlsInspectionBridgeFailure.CERTIFICATE_PINNING_REJECTED
    cause.causes().any { it is SSLHandshakeException } -> TlsInspectionBridgeFailure.UPSTREAM_TRUST_REJECTED
    cause.causes().any { it is SSLException } -> TlsInspectionBridgeFailure.CERTIFICATE_PINNING_OR_CA_REJECTED
    else -> TlsInspectionBridgeFailure.ENGINE_FAILURE
}

private fun Throwable.causes(): Sequence<Throwable> = sequence {
    val seen = HashSet<Throwable>()
    var current: Throwable? = this@causes
    while (current != null && seen.add(current)) {
        yield(current)
        current = current.cause
    }
}

/** Canonical spelling retained as aliases while downstream composition is pending. */
typealias TlsInspectionSslEngineBridge = TlsInspectionSslenegineBridge
typealias TlsInspectionSSLEngineBridge = TlsInspectionSslenegineBridge
