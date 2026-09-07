package app.apksentinel.core.security

import app.apksentinel.core.model.AuditMetadata
import app.apksentinel.core.model.RedactionLevel
import app.apksentinel.core.model.RedactionPolicy
import app.apksentinel.core.model.SensitiveDataCategory
import java.util.Locale

/**
 * Deterministic redaction helpers for exports, audits, and controlled logs.
 * Callers should apply a policy before serializing any user or device data.
 * These helpers reduce accidental disclosure; they do not classify every
 * possible secret format.
 */
object RedactionHelpers {
    fun redactText(
        value: String,
        policy: RedactionPolicy = RedactionPolicy.Standard,
    ): String {
        if (policy.level == RedactionLevel.NONE) {
            return value
        }
        if (SensitiveDataCategory.USER_CONTENT in policy.categories) {
            return policy.replacement
        }

        var redacted = value
        if (SensitiveDataCategory.AUTHENTICATION_MATERIAL in policy.categories) {
            redacted = NAMED_SECRET.replace(redacted) { match ->
                match.groupValues[1] + match.groupValues[2] + policy.replacement
            }
            redacted = BEARER_TOKEN.replace(redacted, "Bearer " + policy.replacement)
            redacted = JWT.replace(redacted, policy.replacement)
        }
        if (SensitiveDataCategory.CONTACT_DETAIL in policy.categories) {
            redacted = EMAIL.replace(redacted, policy.replacement)
            redacted = PHONE_NUMBER.replace(redacted, policy.replacement)
        }
        if (SensitiveDataCategory.NETWORK_ADDRESS in policy.categories) {
            redacted = IPV4_ADDRESS.replace(redacted, policy.replacement)
        }
        if (SensitiveDataCategory.NETWORK_DESTINATION in policy.categories) {
            redacted = URL.replace(redacted, policy.replacement)
        }
        if (SensitiveDataCategory.FILESYSTEM_PATH in policy.categories) {
            redacted = WINDOWS_PATH.replace(redacted, policy.replacement)
            redacted = UNIX_PATH.replace(redacted, policy.replacement)
        }
        if (SensitiveDataCategory.DEVICE_IDENTIFIER in policy.categories) {
            redacted = DEVICE_IDENTIFIER.replace(redacted) { match ->
                match.groupValues[1] + match.groupValues[2] + policy.replacement
            }
        }
        if (SensitiveDataCategory.APP_IDENTIFIER in policy.categories) {
            redacted = PACKAGE_NAME.replace(redacted, policy.replacement)
        }
        return redacted
    }

    /**
     * Returns a stable key order so textual export and audit output does not
     * vary with map insertion order.
     */
    fun redactMetadata(
        metadata: Map<String, String>,
        policy: RedactionPolicy = RedactionPolicy.Standard,
    ): Map<String, String> {
        if (metadata.isEmpty()) {
            return emptyMap()
        }
        return metadata.toSortedMap().mapValues { (key, value) ->
            val category = categoryForKey(key)
            if (policy.level != RedactionLevel.NONE && category != null && category in policy.categories) {
                policy.replacement
            } else {
                redactText(value, policy)
            }
        }
    }

    /**
     * Builds metadata that is bounded and suitable for audit records. Keys are
     * normalized, values are redacted, controls are removed, and duplicate
     * normalized keys receive a deterministic numeric suffix.
     */
    fun redactAuditMetadata(
        metadata: Map<String, String>,
        policy: RedactionPolicy = RedactionPolicy.Standard,
    ): AuditMetadata {
        require(metadata.size <= MAX_AUDIT_FIELDS) { "Too many audit metadata fields." }
        val redacted = redactMetadata(metadata, policy)
        val output = LinkedHashMap<String, String>()
        redacted.forEach { (key, value) ->
            val normalizedKey = uniqueAuditKey(normalizeAuditKey(key), output)
            output[normalizedKey] = value
                .filterNot(Char::isISOControl)
                .take(MAX_AUDIT_VALUE_LENGTH)
        }
        return AuditMetadata.fromPublicFields(output)
    }

    private fun categoryForKey(key: String): SensitiveDataCategory? {
        val normalized = key.lowercase(Locale.ROOT)
        return when {
            SECRET_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.AUTHENTICATION_MATERIAL
            CONTACT_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.CONTACT_DETAIL
            DEVICE_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.DEVICE_IDENTIFIER
            PATH_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.FILESYSTEM_PATH
            ADDRESS_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.NETWORK_ADDRESS
            DESTINATION_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.NETWORK_DESTINATION
            APP_KEY.containsMatchIn(normalized) -> SensitiveDataCategory.APP_IDENTIFIER
            else -> null
        }
    }

    private fun normalizeAuditKey(raw: String): String {
        val lower = raw.lowercase(Locale.ROOT)
        val normalized = buildString(lower.length) {
            lower.forEach { character ->
                append(
                    when {
                        character in 'a'..'z' || character in '0'..'9' -> character
                        else -> '_'
                    },
                )
            }
        }.trim('_').take(MAX_AUDIT_KEY_LENGTH)
        return when {
            normalized.isBlank() -> "field"
            normalized.first() in 'a'..'z' -> normalized
            else -> "field_" + normalized
        }.take(MAX_AUDIT_KEY_LENGTH)
    }

    private fun uniqueAuditKey(candidate: String, output: Map<String, String>): String {
        if (candidate !in output) {
            return candidate
        }
        var index = 2
        while (true) {
            val suffix = "_" + index
            val base = candidate.take(MAX_AUDIT_KEY_LENGTH - suffix.length)
            val alternate = base + suffix
            if (alternate !in output) {
                return alternate
            }
            index += 1
        }
    }

    private const val MAX_AUDIT_FIELDS = 24
    private const val MAX_AUDIT_KEY_LENGTH = 64
    private const val MAX_AUDIT_VALUE_LENGTH = 256

    private val SECRET_KEY = Regex("(?i)(token|secret|password|authorization|cookie|api[_-]?key)")
    private val CONTACT_KEY = Regex("(?i)(email|phone|contact)")
    private val DEVICE_KEY = Regex("(?i)(imei|android[_-]?id|device[_-]?id|advertising[_-]?id)")
    private val PATH_KEY = Regex("(?i)(path|file|directory)")
    private val ADDRESS_KEY = Regex("(?i)(ip|address)")
    private val DESTINATION_KEY = Regex("(?i)(url|host|domain|destination)")
    private val APP_KEY = Regex("(?i)(package|application[_-]?id|app[_-]?id)")

    private val NAMED_SECRET = Regex(
        "(?i)\\b(token|secret|password|authorization|cookie|api[_-]?key)\\s*([:=])\\s*(?:bearer\\s+)?[^\\s,;]+",
    )
    private val BEARER_TOKEN = Regex("(?i)bearer\\s+[A-Za-z0-9._~+/-]+=*")
    private val JWT = Regex("\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b")
    private val EMAIL = Regex("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b")
    private val PHONE_NUMBER = Regex("\\b(?:\\+?[0-9][0-9 .()-]{7,}[0-9])\\b")
    private val IPV4_ADDRESS = Regex("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b")
    private val URL = Regex("(?i)\\b(?:https?|wss?)://[^\\s]+")
    private val WINDOWS_PATH = Regex("(?i)\\b[A-Z]:\\\\[^\\s]+")
    private val UNIX_PATH = Regex("(?<![A-Za-z0-9])/(?:[^\\s/]+/)*[^\\s/]+")
    private val DEVICE_IDENTIFIER = Regex(
        "(?i)\\b(imei|android[_-]?id|device[_-]?id|advertising[_-]?id)\\s*([:=])\\s*[^\\s,;]+",
    )
    private val PACKAGE_NAME = Regex("\\b[a-zA-Z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*){2,}\\b")
}
