package app.apksentinel.networkmonitor

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Offline-only country/ASN attribution. A match describes a provider's IP
 * allocation data, not a person's location, an app's intent, or harmfulness.
 * This module never downloads, persists, resolves DNS, or calls this lookup
 * from a forwarding thread by itself.
 */
data class OfflineAttributionMetadata(
    val version: Long,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
    val keyId: String,
    val provider: String,
    val prefixCount: Int,
)

data class OfflineIpAttribution(
    /** ISO 3166-1 alpha-2 syntax only; a country code is not a risk signal. */
    val countryCode: String,
    /** Public autonomous-system number, not an identity or a malware verdict. */
    val autonomousSystemNumber: Long,
    /** Dataset-supplied, bounded network/provider label. */
    val providerLabel: String,
)

sealed interface OfflineIpAttributionResult {
    data class Match(
        val attribution: OfflineIpAttribution,
        val matchedPrefixLength: Int,
        val metadata: OfflineAttributionMetadata,
    ) : OfflineIpAttributionResult

    data object NoMatch : OfflineIpAttributionResult
    data object InvalidLiteral : OfflineIpAttributionResult
    data class Unavailable(val reason: OfflineAttributionFailure) : OfflineIpAttributionResult
}

/** All values are stable codes. No provider exception or raw bundle text is exposed. */
enum class OfflineAttributionFailure {
    DATASET_UNAVAILABLE,
    PAYLOAD_SIZE,
    FORMAT,
    ENTRY_LIMIT,
    TIME_OR_VERSION,
    EXPIRED,
    FUTURE_DATED,
    CLOCK_ROLLBACK,
    VERSION_ROLLBACK,
    KEY_UNKNOWN,
    KEY_CONFIGURATION,
    SIGNATURE_ENCODING,
    SIGNATURE_INVALID,
    INVALID_ENTRY,
    DUPLICATE_PREFIX,
    LOADER_UNAVAILABLE,
    LOADER_FAILED,
}

/** A host owns this state; this engine deliberately does not persist it. */
interface OfflineAttributionRollbackGuard {
    /** The highest successfully installed version for this signing key, if the host has one. */
    fun highestAcceptedVersion(keyId: String): Long?

    /** A monotonic wall-clock floor recorded by the host, if it has one. */
    fun latestTrustedNowMillis(): Long?
}

object NoOfflineAttributionRollbackGuard : OfflineAttributionRollbackGuard {
    override fun highestAcceptedVersion(keyId: String): Long? = null

    override fun latestTrustedNowMillis(): Long? = null
}

data class OfflineAttributionSigningKey(
    val keyId: String,
    /** Canonical padded Base64 encoding of a P-256 X.509 SubjectPublicKeyInfo. */
    val x509EcPublicKeyBase64: String,
)

/**
 * Read-only lookup surface. The default is explicitly unavailable, so adding
 * it to [NetworkMonitorDependencies] cannot silently enable attribution.
 */
interface OfflineIpAttributionLookup {
    fun lookup(literalAddress: String): OfflineIpAttributionResult

    fun metadata(): OfflineAttributionMetadata? = null

    companion object {
        fun unavailable(): OfflineIpAttributionLookup = UnavailableOfflineIpAttributionLookup
    }
}

private object UnavailableOfflineIpAttributionLookup : OfflineIpAttributionLookup {
    override fun lookup(literalAddress: String): OfflineIpAttributionResult =
        OfflineIpAttributionResult.Unavailable(OfflineAttributionFailure.DATASET_UNAVAILABLE)
}

sealed interface OfflineAttributionLoadResult {
    data class Accepted(
        val lookup: OfflineIpAttributionLookup,
        val metadata: OfflineAttributionMetadata,
    ) : OfflineAttributionLoadResult

    data class Rejected(val reason: OfflineAttributionFailure) : OfflineAttributionLoadResult
}

/**
 * Strict signed text-bundle verifier. The signature covers the exact UTF-8
 * payload bytes, including one final LF. There is intentionally no network or
 * storage API here: a separately reviewed host supplies both bytes and trust.
 *
 * Bundle V1:
 * APK_SENTINEL_IP_ATTRIBUTION_V1\n
 * version=42\n
 * issuedAtMillis=...\n
 * expiresAtMillis=...\n
 * keyId=publisher-2026\n
 * provider=Example Registry\n
 * entries:\n
 * 203.0.113.0/24|IN|64496|Example Transit\n
 */
class OfflineIpAttributionVerifier(
    trustedKeys: List<OfflineAttributionSigningKey>,
    private val maximumPrefixes: Int = DEFAULT_MAX_PREFIXES,
    private val maximumPayloadBytes: Int = DEFAULT_MAX_PAYLOAD_BYTES,
    private val maximumSignatureBytes: Int = DEFAULT_MAX_SIGNATURE_BYTES,
    private val maximumLifetimeMillis: Long = DEFAULT_MAX_LIFETIME_MILLIS,
    private val futureClockSkewMillis: Long = DEFAULT_FUTURE_CLOCK_SKEW_MILLIS,
) {
    private val keyring: Map<String, LoadedKey>
    private val duplicateKeyIds: Set<String>

    init {
        require(maximumPrefixes in 1..MAX_SUPPORTED_PREFIXES) { "Prefix limit is outside the supported range." }
        require(maximumPayloadBytes in 256..MAX_SUPPORTED_PAYLOAD_BYTES) { "Payload limit is outside the supported range." }
        require(maximumSignatureBytes in 8..MAX_SUPPORTED_SIGNATURE_BYTES) { "Signature limit is outside the supported range." }
        require(maximumLifetimeMillis in 1..MAX_SUPPORTED_LIFETIME_MILLIS) { "Lifetime limit is outside the supported range." }
        require(futureClockSkewMillis in 0..MAX_SUPPORTED_CLOCK_SKEW_MILLIS) { "Clock skew is outside the supported range." }
        val grouped = trustedKeys.groupBy { it.keyId }
        duplicateKeyIds = grouped.filterValues { it.size != 1 }.keys
        keyring = grouped.mapValues { (_, keys) ->
            val definition = keys.first()
            LoadedKey(definition, decodeP256PublicKey(definition.x509EcPublicKeyBase64))
        }
    }

    fun verify(
        canonicalPayload: ByteArray,
        signatureBase64: String,
        nowMillis: Long,
        rollbackGuard: OfflineAttributionRollbackGuard = NoOfflineAttributionRollbackGuard,
    ): OfflineAttributionLoadResult {
        if (canonicalPayload.isEmpty() || canonicalPayload.size > maximumPayloadBytes) {
            return rejected(OfflineAttributionFailure.PAYLOAD_SIZE)
        }
        if (nowMillis < 0L) return rejected(OfflineAttributionFailure.TIME_OR_VERSION)
        val trustedFloor = rollbackGuard.latestTrustedNowMillis()
        if (trustedFloor != null && (trustedFloor < 0L || nowMillis < trustedFloor)) {
            return rejected(OfflineAttributionFailure.CLOCK_ROLLBACK)
        }
        val parsed = parsePayload(canonicalPayload) ?: return rejected(OfflineAttributionFailure.FORMAT)
        if (parsed.entries.size > maximumPrefixes) return rejected(OfflineAttributionFailure.ENTRY_LIMIT)
        if (parsed.version <= 0L || parsed.issuedAtMillis <= 0L || parsed.expiresAtMillis <= parsed.issuedAtMillis) {
            return rejected(OfflineAttributionFailure.TIME_OR_VERSION)
        }
        if (parsed.expiresAtMillis - parsed.issuedAtMillis > maximumLifetimeMillis) {
            return rejected(OfflineAttributionFailure.TIME_OR_VERSION)
        }
        if (parsed.issuedAtMillis > saturatingAdd(nowMillis, futureClockSkewMillis)) {
            return rejected(OfflineAttributionFailure.FUTURE_DATED)
        }
        if (parsed.expiresAtMillis <= nowMillis) return rejected(OfflineAttributionFailure.EXPIRED)
        val key = keyring[parsed.keyId] ?: return rejected(OfflineAttributionFailure.KEY_UNKNOWN)
        if (parsed.keyId in duplicateKeyIds || key.publicKey == null) {
            return rejected(OfflineAttributionFailure.KEY_CONFIGURATION)
        }
        val versionFloor = rollbackGuard.highestAcceptedVersion(parsed.keyId)
        if (versionFloor != null && (versionFloor < 0L || parsed.version <= versionFloor)) {
            return rejected(OfflineAttributionFailure.VERSION_ROLLBACK)
        }
        val signatureBytes = decodeCanonicalBase64(signatureBase64, maximumSignatureBytes)
            ?: return rejected(OfflineAttributionFailure.SIGNATURE_ENCODING)
        val verified = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key.publicKey)
                update(canonicalPayload)
                verify(signatureBytes)
            }
        } catch (_: Exception) {
            false
        } finally {
            signatureBytes.fill(0)
        }
        if (!verified) return rejected(OfflineAttributionFailure.SIGNATURE_INVALID)
        if (parsed.entries.isEmpty()) return rejected(OfflineAttributionFailure.INVALID_ENTRY)

        val seen = HashSet<PrefixIdentity>(parsed.entries.size)
        val builder4 = MutablePrefixNode()
        val builder6 = MutablePrefixNode()
        parsed.entries.forEach { line ->
            val entry = parseEntry(line) ?: return rejected(OfflineAttributionFailure.INVALID_ENTRY)
            if (!seen.add(entry.prefix.identity)) return rejected(OfflineAttributionFailure.DUPLICATE_PREFIX)
            insert(if (entry.prefix.family == IpVersion.IPV4) builder4 else builder6, entry.prefix, entry.attribution)
        }
        val metadata = OfflineAttributionMetadata(
            version = parsed.version,
            issuedAtMillis = parsed.issuedAtMillis,
            expiresAtMillis = parsed.expiresAtMillis,
            keyId = parsed.keyId,
            provider = parsed.provider,
            prefixCount = parsed.entries.size,
        )
        return OfflineAttributionLoadResult.Accepted(
            ImmutableOfflineIpAttributionLookup(freeze(builder4), freeze(builder6), metadata),
            metadata,
        )
    }

    private fun parsePayload(bytes: ByteArray): ParsedBundle? {
        val text = decodeStrictUtf8(bytes) ?: return null
        if (!text.endsWith('\n') || text.contains('\r') || text.startsWith('\uFEFF')) return null
        if (text.any { it.isISOControl() && it != '\n' }) return null
        val lines = text.dropLast(1).split('\n')
        if (lines.size < HEADER_LINES || lines.any { it.isEmpty() || it.length > MAX_LINE_CHARS }) return null
        if (lines[0] != FORMAT || lines[6] != ENTRIES) return null
        val version = canonicalPositiveLong(lines[1], "version=") ?: return null
        val issued = canonicalPositiveLong(lines[2], "issuedAtMillis=") ?: return null
        val expires = canonicalPositiveLong(lines[3], "expiresAtMillis=") ?: return null
        val keyId = lines[4].removePrefix("keyId=")
        val provider = lines[5].removePrefix("provider=")
        if (!lines[4].startsWith("keyId=") || !KEY_ID.matches(keyId) ||
            !lines[5].startsWith("provider=") || !isSafeProviderLabel(provider)
        ) return null
        return ParsedBundle(version, issued, expires, keyId, provider, lines.drop(HEADER_LINES))
    }

    private fun parseEntry(line: String): PrefixEntry? {
        val fields = line.split('|')
        if (fields.size != 4 || fields.any { it.isEmpty() || it.length > MAX_FIELD_CHARS }) return null
        val prefix = parseCidr(fields[0]) ?: return null
        if (!COUNTRY_CODE.matches(fields[1])) return null
        val asn = fields[2].toLongOrNull()?.takeIf { it in 1L..MAX_ASN } ?: return null
        if (!isSafeProviderLabel(fields[3])) return null
        return PrefixEntry(prefix, OfflineIpAttribution(fields[1], asn, fields[3]))
    }

    private fun rejected(reason: OfflineAttributionFailure): OfflineAttributionLoadResult.Rejected =
        OfflineAttributionLoadResult.Rejected(reason)

    private data class LoadedKey(
        val definition: OfflineAttributionSigningKey,
        val publicKey: ECPublicKey?,
    )

    private data class ParsedBundle(
        val version: Long,
        val issuedAtMillis: Long,
        val expiresAtMillis: Long,
        val keyId: String,
        val provider: String,
        val entries: List<String>,
    )

    private companion object {
        const val FORMAT = "APK_SENTINEL_IP_ATTRIBUTION_V1"
        const val ENTRIES = "entries:"
        const val HEADER_LINES = 7
        const val MAX_LINE_CHARS = 512
        const val MAX_FIELD_CHARS = 160
        const val MAX_ASN = 4_294_967_295L
        const val DEFAULT_MAX_PREFIXES = 50_000
        const val MAX_SUPPORTED_PREFIXES = 100_000
        const val DEFAULT_MAX_PAYLOAD_BYTES = 2 * 1_024 * 1_024
        const val MAX_SUPPORTED_PAYLOAD_BYTES = 4 * 1_024 * 1_024
        const val DEFAULT_MAX_SIGNATURE_BYTES = 1_024
        const val MAX_SUPPORTED_SIGNATURE_BYTES = 4_096
        const val DEFAULT_MAX_LIFETIME_MILLIS = 31L * 24L * 60L * 60L * 1_000L
        const val MAX_SUPPORTED_LIFETIME_MILLIS = 90L * 24L * 60L * 60L * 1_000L
        const val DEFAULT_FUTURE_CLOCK_SKEW_MILLIS = 5L * 60L * 1_000L
        const val MAX_SUPPORTED_CLOCK_SKEW_MILLIS = 60L * 60L * 1_000L
        val KEY_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
        val CANONICAL_POSITIVE_LONG = Regex("^[1-9][0-9]{0,18}$")
        val COUNTRY_CODE = Regex("^[A-Z]{2}$")
        val PROVIDER_LABEL = Regex("^[A-Za-z0-9][A-Za-z0-9 .,_()/-]{0,79}$")
    }
}

/**
 * Optional app-composed loader. It only parses bytes supplied by the host on
 * one background executor. A failed candidate leaves the prior immutable
 * lookup in place; neither bytes nor metadata are written to disk here.
 */
class OfflineIpAttributionLoader(
    private val verifier: OfflineIpAttributionVerifier,
    private val rollbackGuard: OfflineAttributionRollbackGuard = NoOfflineAttributionRollbackGuard,
    private val clock: EpochClock = SystemEpochClock,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "apk-sentinel-offline-attribution").apply { isDaemon = true }
    },
) : AutoCloseable {
    @Volatile
    private var current: OfflineIpAttributionLookup = OfflineIpAttributionLookup.unavailable()

    fun currentLookup(): OfflineIpAttributionLookup = current

    fun loadInBackground(
        canonicalPayload: ByteArray,
        signatureBase64: String,
        callback: (OfflineAttributionLoadResult) -> Unit = {},
    ): Boolean {
        val candidate = canonicalPayload.copyOf()
        return try {
            executor.execute {
                val result = try {
                    verifier.verify(candidate, signatureBase64, clock.nowMillis(), rollbackGuard)
                } catch (_: Exception) {
                    OfflineAttributionLoadResult.Rejected(OfflineAttributionFailure.LOADER_FAILED)
                } finally {
                    candidate.fill(0)
                }
                if (result is OfflineAttributionLoadResult.Accepted) current = result.lookup
                callback(result)
            }
            true
        } catch (_: RejectedExecutionException) {
            candidate.fill(0)
            callback(OfflineAttributionLoadResult.Rejected(OfflineAttributionFailure.LOADER_UNAVAILABLE))
            false
        }
    }

    /** Drops the currently loaded immutable index. This does not delete host-owned bundle storage. */
    fun clear() {
        current = OfflineIpAttributionLookup.unavailable()
    }

    override fun close() {
        clear()
        executor.shutdownNow()
    }
}

private class ImmutableOfflineIpAttributionLookup(
    private val ipv4: FrozenPrefixNode,
    private val ipv6: FrozenPrefixNode,
    private val datasetMetadata: OfflineAttributionMetadata,
) : OfflineIpAttributionLookup {
    override fun lookup(literalAddress: String): OfflineIpAttributionResult {
        val address = parseLiteralAddress(literalAddress) ?: return OfflineIpAttributionResult.InvalidLiteral
        val match = lookup(if (address.family == IpVersion.IPV4) ipv4 else ipv6, address.bytes)
            ?: return OfflineIpAttributionResult.NoMatch
        return OfflineIpAttributionResult.Match(match.attribution, match.prefixLength, datasetMetadata)
    }

    override fun metadata(): OfflineAttributionMetadata = datasetMetadata
}

private data class PrefixEntry(val prefix: IpPrefix, val attribution: OfflineIpAttribution)

private data class PrefixIdentity(val family: IpVersion, val bytes: List<Byte>, val prefixLength: Int)

private data class IpPrefix(val family: IpVersion, val bytes: ByteArray, val prefixLength: Int) {
    val identity: PrefixIdentity get() = PrefixIdentity(family, bytes.toList(), prefixLength)
}

private data class LiteralAddress(val family: IpVersion, val bytes: ByteArray)

private class MutablePrefixNode {
    var zero: MutablePrefixNode? = null
    var one: MutablePrefixNode? = null
    var value: PrefixValue? = null
}

private data class PrefixValue(val prefixLength: Int, val attribution: OfflineIpAttribution)

private data class FrozenPrefixNode(
    val zero: FrozenPrefixNode? = null,
    val one: FrozenPrefixNode? = null,
    val value: PrefixValue? = null,
)

private fun insert(root: MutablePrefixNode, prefix: IpPrefix, attribution: OfflineIpAttribution) {
    var node = root
    repeat(prefix.prefixLength) { bitIndex ->
        if (bitAt(prefix.bytes, bitIndex) == 0) {
            node = node.zero ?: MutablePrefixNode().also { node.zero = it }
        } else {
            node = node.one ?: MutablePrefixNode().also { node.one = it }
        }
    }
    node.value = PrefixValue(prefix.prefixLength, attribution)
}

private fun freeze(node: MutablePrefixNode?): FrozenPrefixNode {
    if (node == null) return FrozenPrefixNode()
    return FrozenPrefixNode(freeze(node.zero).takeUnless { it.isEmpty() }, freeze(node.one).takeUnless { it.isEmpty() }, node.value)
}

private fun FrozenPrefixNode.isEmpty(): Boolean = zero == null && one == null && value == null

private fun lookup(root: FrozenPrefixNode, address: ByteArray): PrefixValue? {
    var node: FrozenPrefixNode? = root
    var matched: PrefixValue? = root.value
    val bitCount = address.size * 8
    for (index in 0 until bitCount) {
        node = if (bitAt(address, index) == 0) node?.zero else node?.one
        if (node == null) break
        node.value?.let { matched = it }
    }
    return matched
}

private fun parseCidr(raw: String): IpPrefix? {
    val separator = raw.indexOf('/')
    if (separator <= 0 || separator != raw.lastIndexOf('/') || separator == raw.lastIndex) return null
    val address = parseLiteralAddress(raw.substring(0, separator)) ?: return null
    val rawLength = raw.substring(separator + 1)
    if (!rawLength.all { it in '0'..'9' }) return null
    val prefixLength = rawLength.toIntOrNull() ?: return null
    if (rawLength != prefixLength.toString() || prefixLength !in 0..address.bytes.size * 8) return null
    if (!hasZeroHostBits(address.bytes, prefixLength)) return null
    return IpPrefix(address.family, address.bytes, prefixLength)
}

/** Literal-only parser. It never calls InetAddress.getByName or any DNS API. */
private fun parseLiteralAddress(raw: String): LiteralAddress? =
    parseIpv4(raw)?.let { LiteralAddress(IpVersion.IPV4, it) } ?: parseIpv6(raw)?.let { LiteralAddress(IpVersion.IPV6, it) }

private fun parseIpv4(raw: String): ByteArray? {
    if (raw.length !in 7..15 || raw.any { it !in '0'..'9' && it != '.' }) return null
    val parts = raw.split('.')
    if (parts.size != 4) return null
    val bytes = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.isEmpty() || part.length > 3 || (part.length > 1 && part.startsWith('0'))) return null
        val value = part.toIntOrNull() ?: return null
        if (value !in 0..255) return null
        bytes[index] = value.toByte()
    }
    return bytes
}

/** Supports normal hexadecimal IPv6 and :: compression, but deliberately rejects zone IDs and dotted suffixes. */
private fun parseIpv6(raw: String): ByteArray? {
    if (raw.length !in 2..45 || raw.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' && it != ':' }) return null
    val doubleIndex = raw.indexOf("::")
    if (doubleIndex >= 0 && doubleIndex != raw.lastIndexOf("::")) return null
    val groups = ArrayList<String>(8)
    if (doubleIndex >= 0) {
        val left = raw.substring(0, doubleIndex).takeIf { it.isNotEmpty() }?.split(':') ?: emptyList()
        val right = raw.substring(doubleIndex + 2).takeIf { it.isNotEmpty() }?.split(':') ?: emptyList()
        if (left.any { it.isEmpty() } || right.any { it.isEmpty() } || left.size + right.size >= 8) return null
        groups.addAll(left)
        repeat(8 - left.size - right.size) { groups += "0" }
        groups.addAll(right)
    } else {
        groups.addAll(raw.split(':'))
        if (groups.size != 8 || groups.any { it.isEmpty() }) return null
    }
    if (groups.size != 8 || groups.any { it.length !in 1..4 || it.any { character -> character.digitToIntOrNull(16) == null } }) return null
    return ByteArray(16).also { result ->
        groups.forEachIndexed { index, group ->
            val value = group.toInt(16)
            result[index * 2] = (value ushr 8).toByte()
            result[index * 2 + 1] = value.toByte()
        }
    }
}

private fun hasZeroHostBits(bytes: ByteArray, prefixLength: Int): Boolean {
    for (index in prefixLength until bytes.size * 8) if (bitAt(bytes, index) != 0) return false
    return true
}

private fun bitAt(bytes: ByteArray, index: Int): Int =
    ((bytes[index / 8].toInt() and 0xff) ushr (7 - (index % 8))) and 1

private fun canonicalPositiveLong(line: String, prefix: String): Long? {
    if (!line.startsWith(prefix)) return null
    val value = line.removePrefix(prefix)
    return value.takeIf { CANONICAL_NUMBER.matches(it) }?.toLongOrNull()
}

private fun isSafeProviderLabel(value: String): Boolean = PROVIDER.matches(value)

private fun decodeStrictUtf8(bytes: ByteArray): String? = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (_: CharacterCodingException) {
    null
}

private fun decodeCanonicalBase64(value: String, maximumBytes: Int): ByteArray? {
    if (value.isEmpty() || value.length > maximumBytes * 2 || !BASE64.matches(value)) return null
    return try {
        Base64.getDecoder().decode(value).takeIf { bytes ->
            bytes.isNotEmpty() && bytes.size <= maximumBytes && Base64.getEncoder().encodeToString(bytes) == value
        }
    } catch (_: IllegalArgumentException) {
        null
    }
}

private fun decodeP256PublicKey(value: String): ECPublicKey? {
    val bytes = decodeCanonicalBase64(value, MAX_PUBLIC_KEY_BYTES) ?: return null
    return try {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes)) as? ECPublicKey
        key?.takeIf(::isNistP256)
    } catch (_: Exception) {
        null
    } finally {
        bytes.fill(0)
    }
}

private fun isNistP256(key: ECPublicKey): Boolean {
    val expected = NIST_P256_PARAMETERS ?: return false
    return key.params.curve == expected.curve &&
        key.params.generator == expected.generator &&
        key.params.order == expected.order &&
        key.params.cofactor == expected.cofactor
}

private val NIST_P256_PARAMETERS: ECParameterSpec? by lazy {
    runCatching {
        AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
    }.getOrNull()
}

private fun saturatingAdd(left: Long, right: Long): Long = if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right

private const val MAX_PUBLIC_KEY_BYTES = 2_048
private val CANONICAL_NUMBER = Regex("^[1-9][0-9]{0,18}$")
private val PROVIDER = Regex("^[A-Za-z0-9][A-Za-z0-9 .,_()/-]{0,79}$")
private val BASE64 = Regex("^[A-Za-z0-9+/]+={0,2}$")
