package app.apksentinel.engine.url

import java.net.IDN
import java.net.URI
import java.util.Locale

enum class UrlVerdict { NO_KNOWN_WARNING, REVIEW, BLOCKED_LOCAL_MATCH, INVALID }
enum class UrlFindingKind { LOCAL_THREAT_MATCH, NON_WEB_SCHEME, CREDENTIALS_IN_URL, IP_LITERAL, PUNYCODE, MIXED_SCRIPT, SHORTENER, BIDI_CONTROL, SENSITIVE_QUERY, INVALID_HOST }
enum class UrlFindingMessage {
    INVALID_WEB_ADDRESS,
    HTTP_HTTPS_ONLY,
    NO_VALID_HOSTNAME,
    HOSTNAME_NORMALIZATION_FAILED,
    BIDI_REMOVED_BEFORE_DISPLAY,
    BIDI_REMOVED_BEFORE_VALIDATION,
    CREDENTIALS_IN_URL,
    LOCAL_THREAT_MATCH,
    IP_LITERAL,
    PUNYCODE,
    MIXED_SCRIPT,
    SHORTENER,
    SENSITIVE_QUERY,
}
enum class UrlFindingConfidence { CERTAIN, HIGH, MEDIUM }
enum class UrlInspectionLimitation { NO_REMOTE_REPUTATION_OR_REDIRECT_LOOKUP }

data class UrlFinding(
    val kind: UrlFindingKind,
    val message: UrlFindingMessage,
    val confidence: UrlFindingConfidence,
)

data class UrlInspection(
    val original: String,
    val normalizedUrl: String?,
    val displayHost: String?,
    val asciiHost: String?,
    val verdict: UrlVerdict,
    val findings: List<UrlFinding>,
    val limitation: UrlInspectionLimitation = UrlInspectionLimitation.NO_REMOTE_REPUTATION_OR_REDIRECT_LOOKUP,
)

class UrlSafetyAnalyzer(
    localThreatHosts: Set<String> = emptySet(),
    private val shorteners: Set<String> = DEFAULT_SHORTENERS,
) {
    private val threats = localThreatHosts.map(::canonicalHost).toSet()

    fun inspect(rawInput: String): UrlInspection {
        val raw = rawInput.trim()
        val bidi = raw.any { it in BIDI_CONTROLS }
        val cleaned = raw.filterNot { it.isISOControl() || it in BIDI_CONTROLS }
        val candidate = if (SCHEME.containsMatchIn(cleaned)) cleaned else "https://$cleaned"
        val uri = runCatching { URI(candidate) }.getOrNull()
            ?: return invalid(raw, bidi, UrlFindingMessage.INVALID_WEB_ADDRESS)
        if (uri.scheme?.lowercase(Locale.ROOT) !in setOf("http", "https")) {
            return UrlInspection(raw, null, null, null, UrlVerdict.INVALID, listOf(UrlFinding(UrlFindingKind.NON_WEB_SCHEME, UrlFindingMessage.HTTP_HTTPS_ONLY, UrlFindingConfidence.CERTAIN)))
        }
        val unicodeHost = uri.host?.let { IDN.toUnicode(it).lowercase(Locale.ROOT).trimEnd('.') }
            ?: return invalid(raw, bidi, UrlFindingMessage.NO_VALID_HOSTNAME)
        val asciiHost = runCatching { canonicalHost(unicodeHost) }.getOrNull()
            ?: return invalid(raw, bidi, UrlFindingMessage.HOSTNAME_NORMALIZATION_FAILED)
        val findings = buildList {
            if (bidi) add(UrlFinding(UrlFindingKind.BIDI_CONTROL, UrlFindingMessage.BIDI_REMOVED_BEFORE_DISPLAY, UrlFindingConfidence.CERTAIN))
            if (uri.userInfo != null) add(UrlFinding(UrlFindingKind.CREDENTIALS_IN_URL, UrlFindingMessage.CREDENTIALS_IN_URL, UrlFindingConfidence.CERTAIN))
            if (threats.any { threat -> asciiHost == threat || asciiHost.endsWith(".$threat") }) {
                add(UrlFinding(UrlFindingKind.LOCAL_THREAT_MATCH, UrlFindingMessage.LOCAL_THREAT_MATCH, UrlFindingConfidence.HIGH))
            }
            if (isIpLiteral(asciiHost)) add(UrlFinding(UrlFindingKind.IP_LITERAL, UrlFindingMessage.IP_LITERAL, UrlFindingConfidence.CERTAIN))
            if (asciiHost.split('.').any { it.startsWith("xn--") }) add(UrlFinding(UrlFindingKind.PUNYCODE, UrlFindingMessage.PUNYCODE, UrlFindingConfidence.CERTAIN))
            if (hasMixedScripts(unicodeHost)) add(UrlFinding(UrlFindingKind.MIXED_SCRIPT, UrlFindingMessage.MIXED_SCRIPT, UrlFindingConfidence.MEDIUM))
            if (asciiHost in shorteners || shorteners.any { asciiHost.endsWith(".$it") }) add(UrlFinding(UrlFindingKind.SHORTENER, UrlFindingMessage.SHORTENER, UrlFindingConfidence.HIGH))
            val query = uri.rawQuery.orEmpty().lowercase(Locale.ROOT)
            if (SENSITIVE_KEYS.any { query.contains("$it=") }) add(UrlFinding(UrlFindingKind.SENSITIVE_QUERY, UrlFindingMessage.SENSITIVE_QUERY, UrlFindingConfidence.MEDIUM))
        }
        val normalized = URI(uri.scheme.lowercase(Locale.ROOT), uri.userInfo, asciiHost, uri.port, uri.rawPath.ifBlank { "/" }, uri.rawQuery, uri.rawFragment).toASCIIString()
        val verdict = when {
            findings.any { it.kind == UrlFindingKind.LOCAL_THREAT_MATCH } -> UrlVerdict.BLOCKED_LOCAL_MATCH
            findings.isNotEmpty() -> UrlVerdict.REVIEW
            else -> UrlVerdict.NO_KNOWN_WARNING
        }
        return UrlInspection(raw, normalized, unicodeHost, asciiHost, verdict, findings)
    }

    private fun invalid(raw: String, bidi: Boolean, message: UrlFindingMessage): UrlInspection {
        val findings = buildList {
            if (bidi) add(UrlFinding(UrlFindingKind.BIDI_CONTROL, UrlFindingMessage.BIDI_REMOVED_BEFORE_VALIDATION, UrlFindingConfidence.CERTAIN))
            add(UrlFinding(UrlFindingKind.INVALID_HOST, message, UrlFindingConfidence.CERTAIN))
        }
        return UrlInspection(raw, null, null, null, UrlVerdict.INVALID, findings)
    }

    private fun canonicalHost(value: String): String = IDN.toASCII(value.lowercase(Locale.ROOT).trimEnd('.'), IDN.USE_STD3_ASCII_RULES)

    private fun isIpLiteral(host: String): Boolean = IPV4.matches(host) || host.contains(':')

    private fun hasMixedScripts(host: String): Boolean = host.split('.').any { label ->
        label.asSequence().filter(Char::isLetter).map { Character.UnicodeScript.of(it.code) }
            .filterNot { it == Character.UnicodeScript.COMMON || it == Character.UnicodeScript.INHERITED }
            .distinct().take(2).count() > 1
    }

    private companion object {
        val SCHEME = Regex("^[A-Za-z][A-Za-z0-9+.-]*://")
        val IPV4 = Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")
        val BIDI_CONTROLS = setOf('\u061C', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069')
        val SENSITIVE_KEYS = setOf("token", "access_token", "code", "email", "phone", "session", "auth")
        val DEFAULT_SHORTENERS = setOf("bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "rb.gy")
    }
}
