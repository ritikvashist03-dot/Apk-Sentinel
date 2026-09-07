package app.apksentinel.engine.threatintel

import java.net.IDN
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Locale

/** Indicator values are deliberately exact literals: no URL patterns or wildcards are supported. */
enum class IndicatorType { HOST, IP, APK_SHA256 }

enum class ThreatConfidence { LOW, MEDIUM, HIGH }

data class ThreatIndicator(
    val type: IndicatorType,
    val value: String,
    val category: String,
    val confidence: ThreatConfidence,
    val evidenceId: String,
)

/**
 * A feed is usable only while its signature, key status, format, version and
 * time bounds have all been checked by [ThreatFeedVerifier]. It does not make
 * a safety guarantee; a match is evidence for review, not a verdict.
 */
data class VerifiedThreatFeed(
    val version: Long,
    val issuedAtMillis: Long,
    val expiresAtMillis: Long,
    val keyId: String,
    val indicators: List<ThreatIndicator>,
    val payloadSha256: String,
) {
    fun matchHost(host: String): List<ThreatIndicator> {
        val normalized = normalizeHostLiteral(host) ?: return emptyList()
        return indicators
            .asSequence()
            .filter { indicator ->
                indicator.type == IndicatorType.HOST &&
                    (normalized == indicator.value || normalized.endsWith(".${indicator.value}"))
            }
            .sortedWith(THREAT_MATCH_ORDER)
            .toList()
    }

    fun matchIp(ip: String): List<ThreatIndicator> {
        val normalized = normalizeIpLiteral(ip) ?: return emptyList()
        return indicators
            .asSequence()
            .filter { it.type == IndicatorType.IP && it.value == normalized }
            .sortedWith(THREAT_MATCH_ORDER)
            .toList()
    }

    fun matchApkSha256(hash: String): List<ThreatIndicator> {
        val normalized = normalizeApkSha256(hash) ?: return emptyList()
        return indicators
            .asSequence()
            .filter { it.type == IndicatorType.APK_SHA256 && it.value == normalized }
            .sortedWith(THREAT_MATCH_ORDER)
            .toList()
    }

    private companion object {
        val THREAT_MATCH_ORDER = compareByDescending<ThreatIndicator> { it.value.length }
            .thenBy { it.value }
            .thenBy { it.category }
            .thenBy { it.evidenceId }
    }
}

sealed interface ThreatFeedVerification {
    data class Accepted(val feed: VerifiedThreatFeed) : ThreatFeedVerification

    /** Code is safe for telemetry; [safeReason] must be suitable for the UI. */
    data class Rejected(val code: String, val safeReason: String) : ThreatFeedVerification
}

/**
 * Retired keys may keep validating a previously stored feed until that feed
 * expires. Only ACTIVE keys may install a new feed. REVOKED keys fail closed
 * for both paths as soon as the app ships the revoked keyring.
 */
enum class ThreatFeedKeyStatus { ACTIVE, RETIRED, REVOKED }

data class ThreatFeedKey(
    val keyId: String,
    val x509EcPublicKeyBase64: String,
    val status: ThreatFeedKeyStatus = ThreatFeedKeyStatus.ACTIVE,
    val validFromMillis: Long? = null,
    val validUntilMillis: Long? = null,
)

/**
 * Strict verifier for the small, line-oriented APK Sentinel feed format.
 *
 * The signature covers the exact canonical UTF-8 bytes, including the final
 * LF. The verifier deliberately has no downloader, network client, logging or
 * persistence side effect; those are composed by [ThreatFeedRepository].
 */
class ThreatFeedVerifier(
    keys: List<ThreatFeedKey>,
    private val maxIndicators: Int = DEFAULT_MAX_INDICATORS,
    private val maxPayloadBytes: Int = DEFAULT_MAX_PAYLOAD_BYTES,
    private val maxSignatureBytes: Int = DEFAULT_MAX_SIGNATURE_BYTES,
    private val maxFeedLifetimeMillis: Long = DEFAULT_MAX_FEED_LIFETIME_MILLIS,
    private val futureClockSkewMillis: Long = DEFAULT_FUTURE_CLOCK_SKEW_MILLIS,
) {
    private val keyring: Map<String, LoadedKey>
    private val duplicateKeyIds: Set<String>

    init {
        require(maxIndicators in 1..MAX_SUPPORTED_INDICATORS) { "maxIndicators is outside the supported range." }
        require(maxPayloadBytes in 1..MAX_SUPPORTED_PAYLOAD_BYTES) { "maxPayloadBytes is outside the supported range." }
        require(maxSignatureBytes in 8..MAX_SUPPORTED_SIGNATURE_BYTES) { "maxSignatureBytes is outside the supported range." }
        require(maxFeedLifetimeMillis in 1..MAX_SUPPORTED_FEED_LIFETIME_MILLIS) {
            "maxFeedLifetimeMillis is outside the supported range."
        }
        require(futureClockSkewMillis in 0..MAX_SUPPORTED_CLOCK_SKEW_MILLIS) {
            "futureClockSkewMillis is outside the supported range."
        }

        val grouped = keys.groupBy { it.keyId }
        duplicateKeyIds = grouped.filterValues { it.size != 1 }.keys
        keyring = grouped.mapValues { (_, definitions) ->
            // Never crash an app process because a packaged keyring is bad.
            // Duplicate IDs are rejected explicitly during verification.
            val definition = definitions.first()
            LoadedKey(definition, decodeP256PublicKey(definition.x509EcPublicKeyBase64))
        }
    }

    /** Verifies a candidate that would replace the locally activated feed. */
    fun verify(
        canonicalPayload: ByteArray,
        signatureBase64: String,
        nowMillis: Long,
        activatedVersion: Long?,
    ): ThreatFeedVerification = verifyInternal(
        canonicalPayload = canonicalPayload,
        signatureBase64 = signatureBase64,
        nowMillis = nowMillis,
        minimumAcceptedVersion = activatedVersion,
        purpose = VerificationPurpose.CANDIDATE,
    )

    /**
     * Rechecks a feed recovered from local storage. Retired keys are allowed
     * here only so a previously verified feed can remain useful until expiry.
     */
    fun verifyStored(
        canonicalPayload: ByteArray,
        signatureBase64: String,
        nowMillis: Long,
    ): ThreatFeedVerification = verifyInternal(
        canonicalPayload = canonicalPayload,
        signatureBase64 = signatureBase64,
        nowMillis = nowMillis,
        minimumAcceptedVersion = null,
        purpose = VerificationPurpose.STORED,
    )

    private fun verifyInternal(
        canonicalPayload: ByteArray,
        signatureBase64: String,
        nowMillis: Long,
        minimumAcceptedVersion: Long?,
        purpose: VerificationPurpose,
    ): ThreatFeedVerification {
        if (canonicalPayload.isEmpty() || canonicalPayload.size > maxPayloadBytes) {
            return reject("PAYLOAD_SIZE", "Threat data is empty or exceeds the verified size limit.")
        }
        if (nowMillis < 0L) {
            return reject("CLOCK", "Device time is not usable for threat data verification.")
        }

        val parsed = parseCanonicalPayload(canonicalPayload) ?: return reject(
            "FORMAT",
            "Threat data is not in the required signed format.",
        )
        if (parsed.indicatorLines.size > maxIndicators) {
            return reject("ENTRY_LIMIT", "Threat data has too many indicators.")
        }
        if (parsed.version <= 0L || parsed.issuedAtMillis <= 0L || parsed.expiresAtMillis <= parsed.issuedAtMillis) {
            return reject("TIME_VERSION", "Threat data time or version range is invalid.")
        }
        if (parsed.expiresAtMillis - parsed.issuedAtMillis > maxFeedLifetimeMillis) {
            return reject("LIFETIME", "Threat data validity period is too long.")
        }
        val latestAllowedIssueTime = safeAdd(nowMillis, futureClockSkewMillis)
        if (parsed.issuedAtMillis > latestAllowedIssueTime) {
            return reject("FUTURE", "Threat data is future-dated.")
        }
        if (parsed.expiresAtMillis <= nowMillis) {
            return reject("EXPIRED", "Threat data has expired.")
        }
        if (minimumAcceptedVersion != null && parsed.version <= minimumAcceptedVersion) {
            return reject("ROLLBACK", "Threat data is not newer than the highest accepted version.")
        }

        val loadedKey = keyring[parsed.keyId]
            ?: return reject("KEY", "Threat data signing key is unknown or revoked.")
        if (parsed.keyId in duplicateKeyIds) {
            return reject("KEY_CONFIG", "Threat data signing key configuration is invalid.")
        }
        val key = loadedKey.definition
        val publicKey = loadedKey.publicKey ?: return reject(
            "KEY_CONFIG",
            "Threat data signing key configuration is invalid.",
        )
        if (key.status == ThreatFeedKeyStatus.REVOKED) {
            return reject("KEY_REVOKED", "Threat data signing key is unknown or revoked.")
        }
        if (purpose == VerificationPurpose.CANDIDATE && key.status != ThreatFeedKeyStatus.ACTIVE) {
            return reject("KEY_RETIRED", "Threat data must use an active signing key.")
        }
        if (!keyAllowsIssuedAt(key, parsed.issuedAtMillis)) {
            return reject("KEY_VALIDITY", "Threat data was issued outside its signing key validity period.")
        }

        val signatureBytes = decodeCanonicalBase64(signatureBase64, maxSignatureBytes)
            ?: return reject("SIGNATURE_ENCODING", "Threat data signature is malformed.")
        val signatureValid = runCatching {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(canonicalPayload)
                verify(signatureBytes)
            }
        }.getOrDefault(false)
        if (!signatureValid) {
            return reject("SIGNATURE", "Threat data signature verification failed.")
        }

        if (parsed.indicatorLines.isEmpty()) {
            return reject("ENTRY_EMPTY", "Threat data contains no indicators.")
        }
        val indicators = ArrayList<ThreatIndicator>(parsed.indicatorLines.size)
        val seen = HashSet<ThreatIndicator>(parsed.indicatorLines.size)
        parsed.indicatorLines.forEachIndexed { index, line ->
            val indicator = parseIndicator(line) ?: return reject(
                "ENTRY",
                "Threat data contains an invalid indicator at position ${index + 1}.",
            )
            if (!seen.add(indicator)) {
                return reject("DUPLICATE_ENTRY", "Threat data contains a duplicate indicator.")
            }
            indicators += indicator
        }
        return ThreatFeedVerification.Accepted(
            VerifiedThreatFeed(
                version = parsed.version,
                issuedAtMillis = parsed.issuedAtMillis,
                expiresAtMillis = parsed.expiresAtMillis,
                keyId = parsed.keyId,
                indicators = indicators.toList(),
                payloadSha256 = sha256Hex(canonicalPayload),
            ),
        )
    }

    private fun parseCanonicalPayload(bytes: ByteArray): ParsedPayload? {
        val text = decodeUtf8Strictly(bytes) ?: return null
        if (!text.endsWith('\n') || text.contains('\r') || text.startsWith('\uFEFF')) return null
        if (text.any { character -> character.isISOControl() && character != '\n' }) return null

        val lines = text.dropLast(1).split('\n')
        if (lines.size < HEADER_LINE_COUNT || lines.any { it.isEmpty() }) return null
        if (lines[0] != FORMAT_MARKER || lines[5] != ENTRIES_MARKER) return null
        val version = parseCanonicalLongLine(lines[1], "version=") ?: return null
        val issuedAtMillis = parseCanonicalLongLine(lines[2], "issuedAtMillis=") ?: return null
        val expiresAtMillis = parseCanonicalLongLine(lines[3], "expiresAtMillis=") ?: return null
        val keyId = lines[4].removePrefix("keyId=")
        if (!lines[4].startsWith("keyId=") || !KEY_ID_PATTERN.matches(keyId)) return null
        return ParsedPayload(
            version = version,
            issuedAtMillis = issuedAtMillis,
            expiresAtMillis = expiresAtMillis,
            keyId = keyId,
            indicatorLines = lines.drop(HEADER_LINE_COUNT),
        )
    }

    private fun parseCanonicalLongLine(line: String, prefix: String): Long? {
        if (!line.startsWith(prefix)) return null
        val raw = line.removePrefix(prefix)
        if (!CANONICAL_POSITIVE_LONG.matches(raw)) return null
        return raw.toLongOrNull()
    }

    private fun parseIndicator(line: String): ThreatIndicator? {
        val parts = line.split('|')
        if (parts.size != INDICATOR_FIELD_COUNT || parts.any { it.isEmpty() || it.length > MAX_INDICATOR_FIELD_LENGTH }) {
            return null
        }
        val type = runCatching { IndicatorType.valueOf(parts[0]) }.getOrNull() ?: return null
        val confidence = runCatching { ThreatConfidence.valueOf(parts[3]) }.getOrNull() ?: return null
        val value = when (type) {
            IndicatorType.HOST -> parts[1].takeIf { raw -> raw == normalizeHostLiteral(raw) }
            IndicatorType.IP -> parts[1].takeIf { raw -> raw == normalizeIpLiteral(raw) }
            IndicatorType.APK_SHA256 -> parts[1].takeIf { raw -> raw == normalizeApkSha256(raw) }
        } ?: return null
        if (!CATEGORY_PATTERN.matches(parts[2]) || !EVIDENCE_ID_PATTERN.matches(parts[4])) return null
        return ThreatIndicator(type, value, parts[2], confidence, parts[4])
    }

    private fun keyAllowsIssuedAt(key: ThreatFeedKey, issuedAtMillis: Long): Boolean {
        val validFrom = key.validFromMillis
        val validUntil = key.validUntilMillis
        if (validFrom != null && validFrom < 0L) return false
        if (validUntil != null && validUntil < 0L) return false
        if (validFrom != null && validUntil != null && validUntil < validFrom) return false
        return (validFrom == null || issuedAtMillis >= validFrom) &&
            (validUntil == null || issuedAtMillis <= validUntil)
    }

    private fun reject(code: String, reason: String): ThreatFeedVerification.Rejected =
        ThreatFeedVerification.Rejected(code, reason)

    private data class LoadedKey(
        val definition: ThreatFeedKey,
        val publicKey: ECPublicKey?,
    )

    private data class ParsedPayload(
        val version: Long,
        val issuedAtMillis: Long,
        val expiresAtMillis: Long,
        val keyId: String,
        val indicatorLines: List<String>,
    )

    private enum class VerificationPurpose { CANDIDATE, STORED }

    private companion object {
        const val FORMAT_MARKER = "APK_SENTINEL_FEED_V1"
        const val ENTRIES_MARKER = "entries:"
        const val HEADER_LINE_COUNT = 6
        const val INDICATOR_FIELD_COUNT = 5
        const val MAX_INDICATOR_FIELD_LENGTH = 512
        const val DEFAULT_MAX_INDICATORS = 25_000
        const val DEFAULT_MAX_PAYLOAD_BYTES = 1_000_000
        const val DEFAULT_MAX_SIGNATURE_BYTES = 1_024
        const val DEFAULT_MAX_FEED_LIFETIME_MILLIS = 31L * 24L * 60L * 60L * 1_000L
        const val DEFAULT_FUTURE_CLOCK_SKEW_MILLIS = 5L * 60L * 1_000L
        const val MAX_SUPPORTED_INDICATORS = 50_000
        const val MAX_SUPPORTED_PAYLOAD_BYTES = 1_000_000
        const val MAX_SUPPORTED_SIGNATURE_BYTES = 4_096
        const val MAX_SUPPORTED_FEED_LIFETIME_MILLIS = 90L * 24L * 60L * 60L * 1_000L
        const val MAX_SUPPORTED_CLOCK_SKEW_MILLIS = 60L * 60L * 1_000L
        val KEY_ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
        val CANONICAL_POSITIVE_LONG = Regex("^[1-9][0-9]{0,18}$")
        val CATEGORY_PATTERN = Regex("^[a-z][a-z0-9_.-]{0,63}$")
        val EVIDENCE_ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
    }
}

private fun decodeUtf8Strictly(bytes: ByteArray): String? = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (_: CharacterCodingException) {
    null
}

private fun decodeCanonicalBase64(value: String, maxDecodedBytes: Int): ByteArray? {
    if (value.isEmpty() || value.length > maxDecodedBytes * 2) return null
    if (!BASE64_PATTERN.matches(value)) return null
    return try {
        val decoded = Base64.getDecoder().decode(value)
        if (decoded.isEmpty() || decoded.size > maxDecodedBytes) {
            null
        } else if (Base64.getEncoder().encodeToString(decoded) == value) {
            decoded
        } else {
            null
        }
    } catch (_: IllegalArgumentException) {
        null
    }
}

private fun decodeP256PublicKey(encoded: String): ECPublicKey? {
    val keyBytes = decodeCanonicalBase64(encoded, MAX_PUBLIC_KEY_BYTES) ?: return null
    return try {
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(keyBytes)) as? ECPublicKey
        if (key != null && isNistP256(key)) key else null
    } catch (_: Exception) {
        null
    }
}

/**
 * Field/order bit length alone accepts other 256-bit curves. Feed keys are
 * restricted to the standard NIST P-256 domain parameters used by the signed
 * feed contract.
 */
private fun isNistP256(key: ECPublicKey): Boolean {
    val expected = NIST_P256_PARAMETERS ?: return false
    val actual = key.params
    return actual.curve == expected.curve &&
        actual.generator == expected.generator &&
        actual.order == expected.order &&
        actual.cofactor == expected.cofactor
}

private val NIST_P256_PARAMETERS: ECParameterSpec? by lazy {
    runCatching {
        AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
    }.getOrNull()
}

private fun sha256Hex(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
    .digest(value)
    .joinToString(separator = "") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

internal fun safeAdd(left: Long, right: Long): Long = when {
    right > 0L && left > Long.MAX_VALUE - right -> Long.MAX_VALUE
    right < 0L && left < Long.MIN_VALUE - right -> Long.MIN_VALUE
    else -> left + right
}

/** Input may be Unicode; stored feed values must already be lower-case ASCII/Punycode. */
private fun normalizeHostLiteral(host: String): String? {
    val candidate = host.trim().trimEnd('.')
    if (candidate.isEmpty() || candidate.length > MAX_HOST_INPUT_LENGTH || candidate.contains(':')) return null
    val ascii = try {
        IDN.toASCII(candidate, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
    } catch (_: IllegalArgumentException) {
        return null
    }
    if (ascii.length !in 3..253 || normalizeIpLiteral(ascii) != null) return null
    val labels = ascii.split('.')
    if (labels.size < 2 || labels.any { label -> !HOST_LABEL_PATTERN.matches(label) }) return null
    return ascii
}

private fun normalizeApkSha256(value: String): String? {
    val normalized = value.trim().lowercase(Locale.ROOT)
    return normalized.takeIf { APK_SHA256_PATTERN.matches(it) }
}

/**
 * Parses literal IP addresses without host-name resolution. IPv4-mapped IPv6
 * spellings with a dotted suffix are deliberately rejected; feed publishers
 * must use canonical hexadecimal IPv6 or canonical dotted-decimal IPv4.
 */
private fun normalizeIpLiteral(value: String): String? {
    val candidate = value.trim()
    return when {
        candidate.isEmpty() || candidate.contains('%') || candidate.startsWith('[') || candidate.endsWith(']') -> null
        candidate.contains(':') -> parseIpv6(candidate)?.let(::renderIpv6)
        else -> parseIpv4(candidate)?.joinToString(".") { (it.toInt() and 0xff).toString() }
    }
}

private fun parseIpv4(value: String): ByteArray? {
    val parts = value.split('.')
    if (parts.size != 4) return null
    val result = ByteArray(4)
    parts.forEachIndexed { index, part ->
        if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) return null
        if (part.length > 1 && part.startsWith('0')) return null
        val parsed = part.toIntOrNull() ?: return null
        if (parsed !in 0..255) return null
        result[index] = parsed.toByte()
    }
    return result
}

private fun parseIpv6(value: String): ByteArray? {
    if (value.contains('.') || value.count { it == ':' } < 2) return null
    val compressionIndex = value.indexOf("::")
    if (compressionIndex >= 0 && value.indexOf("::", compressionIndex + 2) >= 0) return null
    val leftParts = when {
        compressionIndex < 0 -> value.split(':')
        compressionIndex == 0 -> emptyList()
        else -> value.substring(0, compressionIndex).split(':')
    }
    val rightParts = when {
        compressionIndex < 0 -> emptyList()
        compressionIndex + 2 == value.length -> emptyList()
        else -> value.substring(compressionIndex + 2).split(':')
    }
    val allParts = leftParts + rightParts
    if (allParts.any { it.isEmpty() || it.length > 4 || !it.all { char -> char.digitToIntOrNull(16) != null } }) {
        return null
    }
    if (compressionIndex < 0 && allParts.size != IPV6_GROUP_COUNT) return null
    if (compressionIndex >= 0 && allParts.size >= IPV6_GROUP_COUNT) return null

    val groups = IntArray(IPV6_GROUP_COUNT)
    var outputIndex = 0
    leftParts.forEach { part -> groups[outputIndex++] = part.toInt(16) }
    outputIndex += IPV6_GROUP_COUNT - allParts.size
    rightParts.forEach { part -> groups[outputIndex++] = part.toInt(16) }
    return ByteArray(16).also { bytes ->
        groups.forEachIndexed { index, group ->
            bytes[index * 2] = (group ushr 8).toByte()
            bytes[index * 2 + 1] = group.toByte()
        }
    }
}

private fun renderIpv6(bytes: ByteArray): String {
    val groups = IntArray(IPV6_GROUP_COUNT) { index ->
        ((bytes[index * 2].toInt() and 0xff) shl 8) or (bytes[index * 2 + 1].toInt() and 0xff)
    }
    var bestStart = -1
    var bestLength = 0
    var index = 0
    while (index < groups.size) {
        if (groups[index] != 0) {
            index += 1
            continue
        }
        val start = index
        while (index < groups.size && groups[index] == 0) index += 1
        val length = index - start
        if (length >= 2 && length > bestLength) {
            bestStart = start
            bestLength = length
        }
    }
    if (bestStart < 0) return groups.joinToString(":") { it.toString(16) }
    val left = groups.take(bestStart).joinToString(":") { it.toString(16) }
    val right = groups.drop(bestStart + bestLength).joinToString(":") { it.toString(16) }
    return when {
        left.isEmpty() && right.isEmpty() -> "::"
        left.isEmpty() -> "::$right"
        right.isEmpty() -> "$left::"
        else -> "$left::$right"
    }
}

private const val MAX_PUBLIC_KEY_BYTES = 1_024
private const val MAX_HOST_INPUT_LENGTH = 253
private const val IPV6_GROUP_COUNT = 8
private val BASE64_PATTERN = Regex("^[A-Za-z0-9+/]+={0,2}$")
private val HOST_LABEL_PATTERN = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
private val APK_SHA256_PATTERN = Regex("^[0-9a-f]{64}$")
