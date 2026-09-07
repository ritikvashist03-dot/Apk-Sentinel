package app.apksentinel.core.model

/**
 * Consent is always recorded against one explicit purpose. Do not reuse a
 * receipt granted for one purpose to unlock another purpose.
 */
enum class ConsentPurpose {
    APP_INVENTORY,
    APK_ANALYSIS,
    NETWORK_MONITORING,
    NETWORK_PROTECTION,
    OPTIONAL_REPUTATION_LOOKUP,
    SENSITIVE_EXPORT,
    DIAGNOSTIC_SHARING,
}

enum class ConsentDecision {
    GRANTED,
    DECLINED,
    REVOKED,
}

@JvmInline
value class ConsentReceiptId(val value: String) {
    init {
        require(ID_PATTERN.matches(value)) { "Receipt IDs must be stable, non-empty identifiers." }
    }

    override fun toString(): String = value

    private companion object {
        val ID_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$")
    }
}

@JvmInline
value class ConsentScope(val value: String) : Comparable<ConsentScope> {
    init {
        require(SCOPE_PATTERN.matches(value)) { "Consent scopes must be machine-readable identifiers." }
    }

    override fun compareTo(other: ConsentScope): Int = value.compareTo(other.value)

    override fun toString(): String = value

    private companion object {
        val SCOPE_PATTERN = Regex("^[a-z][a-z0-9_.-]{1,79}$")
    }
}

/**
 * An immutable record of a decision after an explicit disclosure. The
 * disclosure revision is an application-defined version or digest, not a
 * promise that a remote service has stored the full disclosure text.
 */
data class ConsentReceipt(
    val id: ConsentReceiptId,
    val purpose: ConsentPurpose,
    val decision: ConsentDecision,
    val disclosureRevision: String,
    val policyRevision: String,
    val scopes: Set<ConsentScope>,
    val presentedAtEpochMillis: Long,
    val decidedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long? = null,
) {
    init {
        require(disclosureRevision.isNotBlank() && disclosureRevision.length <= MAX_REVISION_LENGTH) {
            "A disclosure revision is required."
        }
        require(policyRevision.isNotBlank() && policyRevision.length <= MAX_REVISION_LENGTH) {
            "A policy revision is required."
        }
        require(scopes.isNotEmpty()) { "At least one explicit consent scope is required." }
        require(presentedAtEpochMillis >= 0) { "presentedAtEpochMillis cannot be negative." }
        require(decidedAtEpochMillis >= presentedAtEpochMillis) {
            "A decision cannot precede the disclosure."
        }
        require(expiresAtEpochMillis == null || expiresAtEpochMillis >= decidedAtEpochMillis) {
            "Receipt expiry cannot precede the decision."
        }
    }

    val canonicalScopes: List<ConsentScope>
        get() = scopes.sorted()

    fun isGrantedAt(atEpochMillis: Long): Boolean {
        require(atEpochMillis >= 0) { "atEpochMillis cannot be negative." }
        return decision == ConsentDecision.GRANTED &&
            atEpochMillis >= decidedAtEpochMillis &&
            (expiresAtEpochMillis == null || atEpochMillis < expiresAtEpochMillis)
    }

    private companion object {
        const val MAX_REVISION_LENGTH = 160
    }
}
