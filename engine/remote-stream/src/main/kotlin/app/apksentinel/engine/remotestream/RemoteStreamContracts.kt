package app.apksentinel.engine.remotestream

import java.net.Inet6Address
import java.net.InetAddress
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Locale

/**
 * Containment-first contracts for a future user-paired receiver stream.
 *
 * This library has no socket, listener, discovery, cloud, DNS, VPN, service,
 * file, export, or telemetry implementation. A host must deliberately supply
 * a pinned, mutually authenticated TLS transport before a session can start.
 */
enum class RemoteStreamDataCategory {
    /** Bounded event labels and counters only. */
    METADATA,

    /** A packet already classified upstream as encrypted/raw. It is encrypted again on the wire. */
    RAW_ENCRYPTED_PACKET,

    /** Never available without a fresh, separate upstream classification and consent. */
    DECRYPTED_PAYLOAD,

    /** Never available without a fresh, separate upstream classification and consent. */
    CREDENTIAL,
}

enum class RemoteStreamNetworkUse { OUTBOUND_PINNED_MUTUAL_TLS_ONLY }

enum class RemoteStreamDestinationRejection {
    BLANK,
    TOO_LONG,
    NOT_A_LITERAL_IP,
    INVALID_PORT,
    UNSPECIFIED_OR_LOOPBACK,
    MULTICAST_OR_BROADCAST,
}

sealed interface RemoteStreamDestinationResult {
    data class Accepted(val destination: RemoteStreamDestination) : RemoteStreamDestinationResult
    data class Rejected(val reason: RemoteStreamDestinationRejection) : RemoteStreamDestinationResult
}

/**
 * An outbound, user-entered IPv4/IPv6 literal only. Host names are refused so
 * this layer never performs DNS resolution or permits DNS-rebinding changes.
 */
class RemoteStreamDestination private constructor(
    val literalAddress: String,
    val port: Int,
    private val packedAddress: ByteArray,
) {
    val displayValue: String get() = if (literalAddress.contains(':')) "[$literalAddress]:$port" else "$literalAddress:$port"

    /** A defensive copy suitable for [InetAddress.getByAddress]; never resolve a name. */
    fun addressBytes(): ByteArray = packedAddress.copyOf()

    companion object {
        fun parse(literalAddress: String, port: Int): RemoteStreamDestinationResult {
            val candidate = literalAddress.trim()
            if (candidate.isEmpty()) return RemoteStreamDestinationResult.Rejected(RemoteStreamDestinationRejection.BLANK)
            if (candidate.length > 45) return RemoteStreamDestinationResult.Rejected(RemoteStreamDestinationRejection.TOO_LONG)
            if (port !in 1..65_535) return RemoteStreamDestinationResult.Rejected(RemoteStreamDestinationRejection.INVALID_PORT)

            val normalized = parseLiteral(candidate) ?: return RemoteStreamDestinationResult.Rejected(RemoteStreamDestinationRejection.NOT_A_LITERAL_IP)
            if (normalized.isAnyLocalAddress || normalized.isLoopbackAddress) {
                return RemoteStreamDestinationResult.Rejected(RemoteStreamDestinationRejection.UNSPECIFIED_OR_LOOPBACK)
            }
            if (normalized.isMulticastAddress || isIpv4Broadcast(normalized)) {
                return RemoteStreamDestinationResult.Rejected(RemoteStreamDestinationRejection.MULTICAST_OR_BROADCAST)
            }
            return RemoteStreamDestinationResult.Accepted(
                RemoteStreamDestination(normalized.hostAddress ?: candidate, port, normalized.address.copyOf()),
            )
        }

        private fun parseLiteral(value: String): InetAddress? {
            if (value.indexOf('%') >= 0 || value.any { !(it.isDigit() || it in "abcdefABCDEF:." ) }) return null
            return if (value.contains(':')) parseIpv6(value) else parseIpv4(value)
        }

        private fun parseIpv4(value: String): InetAddress? {
            val sections = value.split('.')
            if (sections.size != 4 || sections.any { it.isEmpty() || it.length > 3 || (it.length > 1 && it.startsWith('0')) }) return null
            val octets = IntArray(4)
            for (index in sections.indices) {
                val parsed = sections[index].toIntOrNull() ?: return null
                if (parsed !in 0..255) return null
                octets[index] = parsed
            }
            return InetAddress.getByAddress(byteArrayOf(octets[0].toByte(), octets[1].toByte(), octets[2].toByte(), octets[3].toByte()))
        }

        private fun isIpv4Broadcast(address: InetAddress): Boolean =
            address.address.size == 4 && address.address.all { it.toInt() and 0xff == 255 }

        /** Strict numeric IPv6 parser. It deliberately has no name-resolution branch. */
        private fun parseIpv6(value: String): InetAddress? {
            val compression = value.indexOf("::")
            if (compression != value.lastIndexOf("::")) return null
            val left = if (compression >= 0) value.substring(0, compression) else value
            val right = if (compression >= 0) value.substring(compression + 2) else ""
            val leftParts = if (left.isEmpty()) emptyList() else left.split(':')
            val rightParts = if (right.isEmpty()) emptyList() else right.split(':')
            if (leftParts.any(String::isEmpty) || rightParts.any(String::isEmpty)) return null
            fun parsePart(part: String): List<Int>? {
                if (part.contains('.')) {
                    val ipv4 = parseIpv4(part) ?: return null
                    val bytes = ipv4.address
                    return listOf(
                        ((bytes[0].toInt() and 0xff) shl 8) or (bytes[1].toInt() and 0xff),
                        ((bytes[2].toInt() and 0xff) shl 8) or (bytes[3].toInt() and 0xff),
                    )
                }
                if (part.length !in 1..4 || part.any { it !in "0123456789abcdefABCDEF" }) return null
                return listOf(part.toInt(16))
            }
            val groups = ArrayList<Int>(8)
            for (part in leftParts + rightParts) {
                groups.addAll(parsePart(part) ?: return null)
            }
            if (groups.size > 8) return null
            val expanded = if (compression >= 0) {
                val missing = 8 - groups.size
                if (missing < 1) return null
                val leftGroups = ArrayList<Int>(leftParts.size)
                for (part in leftParts) leftGroups.addAll(parsePart(part) ?: return null)
                val rightGroups = ArrayList<Int>(rightParts.size)
                for (part in rightParts) rightGroups.addAll(parsePart(part) ?: return null)
                leftGroups + List(missing) { 0 } + rightGroups
            } else groups
            if (expanded.size != 8) return null
            val bytes = ByteArray(16)
            expanded.forEachIndexed { index, group ->
                bytes[index * 2] = (group ushr 8).toByte()
                bytes[index * 2 + 1] = group.toByte()
            }
            return InetAddress.getByAddress(bytes)
        }
    }
}

enum class RemoteReceiverIdentityRejection {
    INVALID_KEY_ID,
    INVALID_FINGERPRINT,
    INVALID_PUBLIC_KEY_ENCODING,
    UNSUPPORTED_PUBLIC_KEY,
    FINGERPRINT_MISMATCH,
}

sealed interface RemoteReceiverIdentityResult {
    data class Accepted(val identity: RemoteReceiverIdentity) : RemoteReceiverIdentityResult
    data class Rejected(val reason: RemoteReceiverIdentityRejection) : RemoteReceiverIdentityResult
}

/**
 * Immutable pinned receiver identity. Its X.509 public key is public pairing
 * material; no local private key is represented anywhere in this module.
 */
class RemoteReceiverIdentity private constructor(
    val keyId: String,
    val sha256Fingerprint: String,
    private val x509PublicKey: ByteArray,
) {
    internal fun receiverPublicKey(): PublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(x509PublicKey.copyOf()))
    internal fun receiverPublicKeyDer(): ByteArray = x509PublicKey.copyOf()

    companion object {
        fun fromP256X509(
            keyId: String,
            base64X509PublicKey: String,
            expectedSha256Fingerprint: String,
        ): RemoteReceiverIdentityResult {
            if (!KEY_ID.matches(keyId)) return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.INVALID_KEY_ID)
            val fingerprint = expectedSha256Fingerprint.lowercase(Locale.ROOT)
            if (!FINGERPRINT.matches(fingerprint)) return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.INVALID_FINGERPRINT)
            val encoded = runCatching { Base64.getDecoder().decode(base64X509PublicKey) }.getOrNull()
                ?: return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.INVALID_PUBLIC_KEY_ENCODING)
            if (encoded.size !in 64..4_096) return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.INVALID_PUBLIC_KEY_ENCODING)
            val publicKey = runCatching {
                KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
            }.getOrNull() ?: return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.UNSUPPORTED_PUBLIC_KEY)
            if (!publicKey.algorithm.equals("EC", ignoreCase = true) || !isP256PublicKey(publicKey)) {
                return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.UNSUPPORTED_PUBLIC_KEY)
            }
            val calculated = sha256Hex(encoded)
            if (!MessageDigest.isEqual(calculated.encodeToByteArray(), fingerprint.encodeToByteArray())) {
                encoded.fill(0)
                return RemoteReceiverIdentityResult.Rejected(RemoteReceiverIdentityRejection.FINGERPRINT_MISMATCH)
            }
            return RemoteReceiverIdentityResult.Accepted(RemoteReceiverIdentity(keyId, fingerprint, encoded.copyOf()).also { encoded.fill(0) })
        }

        internal fun sha256Hex(value: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }

        private fun isP256PublicKey(key: PublicKey): Boolean = runCatching {
            val ec = key as? ECPublicKey ?: return@runCatching false
            val parameters = AlgorithmParameters.getInstance("EC").apply {
                init(ECGenParameterSpec("secp256r1"))
            }.getParameterSpec(ECParameterSpec::class.java)
            ec.params.curve == parameters.curve &&
                ec.params.generator == parameters.generator &&
                ec.params.order == parameters.order &&
                ec.params.cofactor == parameters.cofactor
        }.getOrDefault(false)

        private val KEY_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
        private val FINGERPRINT = Regex("^[0-9a-f]{64}$")
    }
}

private fun sha256Hex(value: ByteArray): String = RemoteReceiverIdentity.sha256Hex(value)

/** Pairing material is only valid when its matching consent is still fresh. */
data class RemoteStreamPairing(
    val destination: RemoteStreamDestination,
    val receiverIdentity: RemoteReceiverIdentity,
    val consent: RemoteStreamPairingConsent,
)

data class RemoteStreamPairingConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
    val expiresAtMillis: Long,
    val destinationDisplayValue: String,
    val receiverFingerprint: String,
    val networkUse: RemoteStreamNetworkUse = RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY,
) {
    init {
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120)
        require(acknowledgedAtMillis > 0L && expiresAtMillis > acknowledgedAtMillis)
        require(destinationDisplayValue.isNotBlank() && destinationDisplayValue.length <= 96)
        require(receiverFingerprint.matches(Regex("^[0-9a-f]{64}$")))
    }
}

data class RemoteStreamSessionConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
    val expiresAtMillis: Long,
    val destinationDisplayValue: String,
    val receiverFingerprint: String,
    val dataCategories: Set<RemoteStreamDataCategory>,
    val maximumPackets: Int,
    val maximumBytes: Long,
    val maximumDurationMillis: Long,
    val maximumQueueBytes: Int,
    val maximumQueueRecords: Int = RemoteStreamConfiguration().maximumQueueRecords,
    val networkUse: RemoteStreamNetworkUse = RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY,
) {
    init {
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120)
        require(acknowledgedAtMillis > 0L && expiresAtMillis > acknowledgedAtMillis)
        require(destinationDisplayValue.isNotBlank() && destinationDisplayValue.length <= 96)
        require(receiverFingerprint.matches(Regex("^[0-9a-f]{64}$")))
        require(dataCategories.isNotEmpty())
        require(maximumPackets > 0 && maximumBytes > 0L && maximumDurationMillis > 0L && maximumQueueBytes > 0)
        require(maximumQueueRecords > 0)
    }
}

/** Required in addition to session consent before decrypted data or credentials can be queued. */
data class RemoteStreamSensitivePayloadAuthorization(
    val upstreamClassifierId: String,
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
    val expiresAtMillis: Long,
    val destinationDisplayValue: String,
    val receiverFingerprint: String,
    val categories: Set<RemoteStreamDataCategory>,
    val networkUse: RemoteStreamNetworkUse = RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY,
) {
    init {
        require(upstreamClassifierId.matches(Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")))
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120)
        require(acknowledgedAtMillis > 0L && expiresAtMillis > acknowledgedAtMillis)
        require(destinationDisplayValue.isNotBlank() && destinationDisplayValue.length <= 96)
        require(receiverFingerprint.matches(Regex("^[0-9a-f]{64}$")))
        require(categories.isNotEmpty() && categories.all { it in SENSITIVE_CATEGORIES })
    }

    companion object {
        val SENSITIVE_CATEGORIES = setOf(RemoteStreamDataCategory.DECRYPTED_PAYLOAD, RemoteStreamDataCategory.CREDENTIAL)
    }
}

data class RemoteStreamConfiguration(
    val enabled: Boolean = false,
    val allowedDataCategories: Set<RemoteStreamDataCategory> = DEFAULT_DATA_CATEGORIES,
    val maximumPackets: Int = 2_000,
    val maximumBytes: Long = 8L * 1_024L * 1_024L,
    val maximumRecordBytes: Int = 16 * 1_024,
    val maximumQueueRecords: Int = 32,
    val maximumQueueBytes: Int = 256 * 1_024,
    val maximumDurationMillis: Long = 10L * 60L * 1_000L,
) {
    val isRequested: Boolean get() = enabled

    companion object {
        val DEFAULT_DATA_CATEGORIES = setOf(RemoteStreamDataCategory.METADATA, RemoteStreamDataCategory.RAW_ENCRYPTED_PACKET)
    }
}

enum class RemoteStreamConfigurationRejection {
    EMPTY_DATA_CATEGORIES,
    LIMIT_OUT_OF_RANGE,
    RECORD_LARGER_THAN_QUEUE,
}

internal fun RemoteStreamConfiguration.validate(): RemoteStreamConfigurationRejection? = when {
    allowedDataCategories.isEmpty() -> RemoteStreamConfigurationRejection.EMPTY_DATA_CATEGORIES
    maximumPackets !in 1..50_000 || maximumBytes !in 4_096L..64L * 1_024L * 1_024L ||
        maximumRecordBytes !in 1..64 * 1_024 || maximumQueueRecords !in 1..128 ||
        maximumQueueBytes !in 4 * 1_024..512 * 1_024 || maximumDurationMillis !in 5_000L..30L * 60L * 1_000L -> RemoteStreamConfigurationRejection.LIMIT_OUT_OF_RANGE
    maximumRecordBytes > maximumQueueBytes -> RemoteStreamConfigurationRejection.RECORD_LARGER_THAN_QUEUE
    else -> null
}

interface RemoteStreamClock { fun nowMillis(): Long }

object SystemRemoteStreamClock : RemoteStreamClock { override fun nowMillis(): Long = System.currentTimeMillis() }

/**
 * The host owns Android Keystore keys/certificates and the actual outbound
 * TLS connection. This module never accepts a local private key or persists a
 * session secret. Implementations must not discover receivers or use cleartext.
 */
interface RemoteStreamSecureHost {
    fun openPinnedMutualTransport(request: RemoteStreamTransportOpenRequest): RemoteStreamTransportOpenResult
}

data class RemoteStreamTransportOpenRequest(
    val destination: RemoteStreamDestination,
    val receiverKeyId: String,
    val receiverPublicKeyDer: ByteArray,
    val expectedReceiverFingerprint: String,
    val sessionNonce: ByteArray,
    val networkUse: RemoteStreamNetworkUse = RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY,
) {
    init {
        require(receiverPublicKeyDer.size in 64..4_096 && sessionNonce.size == 32)
    }
}

enum class RemoteStreamTransportOpenRejection {
    LOCAL_KEY_UNAVAILABLE,
    TLS_UNAVAILABLE,
    RECEIVER_UNREACHABLE,
    RECEIVER_AUTH_FAILED,
    PIN_MISMATCH,
    HOST_REFUSED,
}

sealed interface RemoteStreamTransportOpenResult {
    data class Opened(
        val transport: RemoteStreamAuthenticatedTransport,
        val proof: RemoteStreamTransportProof,
        val sessionKey: RemoteStreamEphemeralSessionKey,
    ) : RemoteStreamTransportOpenResult

    data class Rejected(val reason: RemoteStreamTransportOpenRejection) : RemoteStreamTransportOpenResult
}

enum class RemoteStreamTlsVersion { TLS_1_2, TLS_1_3 }

/** The host must generate this proof after the TLS handshake and pin verification complete. */
data class RemoteStreamTransportProof(
    val tlsVersion: RemoteStreamTlsVersion,
    val destinationDisplayValue: String,
    val observedReceiverFingerprint: String,
    val mutualAuthenticationConfirmed: Boolean,
    val echoedSessionNonce: ByteArray,
) {
    init { require(observedReceiverFingerprint.matches(Regex("^[0-9a-f]{64}$")) && echoedSessionNonce.size == 32) }
}

/**
 * One outbound connection only. The host must synchronously copy a frame it
 * accepts; this module zeroizes sent buffers immediately after [SENT].
 */
interface RemoteStreamAuthenticatedTransport {
    fun send(frame: ByteArray): RemoteStreamTransportSendResult
    fun close()
}

enum class RemoteStreamTransportSendResult { SENT, BACKPRESSURE, AUTHENTICATION_LOST, TRANSPORT_FAILED }

/** A one-session secret capability. It must return a new transient copy and invalidate itself on destroy. */
interface RemoteStreamEphemeralSessionKey {
    fun copyForImmediateUse(): ByteArray?
    fun destroy()
}

internal fun RemoteStreamPairingConsent.isFreshFor(pairing: RemoteStreamPairing, nowMillis: Long): Boolean =
    disclosureVersion.isNotBlank() &&
        destinationDisplayValue == pairing.destination.displayValue &&
        receiverFingerprint == pairing.receiverIdentity.sha256Fingerprint &&
        networkUse == RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY &&
        nowMillis in acknowledgedAtMillis..expiresAtMillis &&
        expiresAtMillis - acknowledgedAtMillis <= MAX_CONSENT_WINDOW_MILLIS

internal fun RemoteStreamSessionConsent.isFreshFor(
    pairing: RemoteStreamPairing,
    configuration: RemoteStreamConfiguration,
    nowMillis: Long,
): Boolean =
    disclosureVersion.isNotBlank() &&
        destinationDisplayValue == pairing.destination.displayValue &&
        receiverFingerprint == pairing.receiverIdentity.sha256Fingerprint &&
        dataCategories == configuration.allowedDataCategories &&
        maximumPackets == configuration.maximumPackets &&
        maximumBytes == configuration.maximumBytes &&
        maximumDurationMillis == configuration.maximumDurationMillis &&
        maximumQueueBytes == configuration.maximumQueueBytes &&
        maximumQueueRecords == configuration.maximumQueueRecords &&
        networkUse == RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY &&
        nowMillis in acknowledgedAtMillis..expiresAtMillis &&
        expiresAtMillis - acknowledgedAtMillis <= MAX_CONSENT_WINDOW_MILLIS

internal fun RemoteStreamSensitivePayloadAuthorization.isFreshFor(
    pairing: RemoteStreamPairing,
    requested: Set<RemoteStreamDataCategory>,
    nowMillis: Long,
): Boolean =
    disclosureVersion.isNotBlank() &&
    destinationDisplayValue == pairing.destination.displayValue &&
        receiverFingerprint == pairing.receiverIdentity.sha256Fingerprint &&
        networkUse == RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY &&
        requested.all { it in categories } && nowMillis in acknowledgedAtMillis..expiresAtMillis &&
        expiresAtMillis - acknowledgedAtMillis <= MAX_CONSENT_WINDOW_MILLIS

internal const val MAX_CONSENT_WINDOW_MILLIS: Long = 15L * 60L * 1_000L
