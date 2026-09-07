package app.apksentinel.core.security

import app.apksentinel.core.model.ConsentPurpose
import app.apksentinel.core.model.ConsentScope

/**
 * Sensitive features need a short-lived, session-scoped grant in addition to
 * their purpose-specific consent. The consent purpose is fixed by the feature.
 */
enum class SensitiveFeature(
    val requiredConsentPurpose: ConsentPurpose,
) {
    NETWORK_PROTECTION(ConsentPurpose.NETWORK_PROTECTION),
    OPTIONAL_REPUTATION_LOOKUP(ConsentPurpose.OPTIONAL_REPUTATION_LOOKUP),
    SENSITIVE_EXPORT(ConsentPurpose.SENSITIVE_EXPORT),
    DIAGNOSTIC_SHARING(ConsentPurpose.DIAGNOSTIC_SHARING),
}

/**
 * Session values are opaque and must not be written to application logs.
 */
@JvmInline
value class SensitiveSessionId(val value: String) {
    init {
        require(value.isNotBlank() && value.length <= MAX_LENGTH && value.none(Char::isISOControl)) {
            "A bounded opaque session identifier is required."
        }
    }

    override fun toString(): String = "[redacted-session]"

    private companion object {
        const val MAX_LENGTH = 256
    }
}

/**
 * A grant ID is a bearer-like capability. Only the caller holding it may
 * request status or use it with the matching session.
 */
@JvmInline
value class SensitiveGrantId(val value: String) {
    init {
        require(ID_PATTERN.matches(value)) { "Grant identifiers must be opaque URL-safe values." }
    }

    override fun toString(): String = "[redacted-grant]"

    private companion object {
        val ID_PATTERN = Regex("^[A-Za-z0-9_-]{16,128}$")
    }
}

data class SensitiveFeatureGrantRequest(
    val sessionId: SensitiveSessionId,
    val feature: SensitiveFeature,
    val requiredScopes: Set<ConsentScope>,
    val expiresAtEpochMillis: Long,
) {
    init {
        require(requiredScopes.isNotEmpty()) { "At least one required scope is required." }
        require(expiresAtEpochMillis >= 0) { "expiresAtEpochMillis cannot be negative." }
    }
}

data class SessionGrant(
    val id: SensitiveGrantId,
    val sessionId: SensitiveSessionId,
    val feature: SensitiveFeature,
    val requiredScopes: Set<ConsentScope>,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
) {
    init {
        require(requiredScopes.isNotEmpty()) { "At least one required scope is required." }
        require(issuedAtEpochMillis >= 0) { "issuedAtEpochMillis cannot be negative." }
        require(expiresAtEpochMillis > issuedAtEpochMillis) {
            "Grant expiry must be after issue time."
        }
    }

    override fun toString(): String =
        "SessionGrant(id=[redacted-grant], sessionId=[redacted-session], feature=" + feature +
            ", issuedAtEpochMillis=" + issuedAtEpochMillis +
            ", expiresAtEpochMillis=" + expiresAtEpochMillis + ")"
}

enum class SensitiveGrantState {
    ACTIVE,
    REVOKED,
    EXPIRED,
    NOT_FOUND,
}

data class SensitiveGrantStatus(
    val state: SensitiveGrantState,
    val feature: SensitiveFeature? = null,
    val expiresAtEpochMillis: Long? = null,
)

sealed interface SensitiveGrantIssueResult {
    data class Granted(val grant: SessionGrant) : SensitiveGrantIssueResult

    data class Denied(val reason: SensitiveGrantDenial) : SensitiveGrantIssueResult
}

enum class SensitiveGrantDenial {
    CONSENT_NOT_GRANTED,
    EXPIRY_NOT_IN_FUTURE,
    EXPIRY_EXCEEDS_SESSION_LIMIT,
    IDENTIFIER_UNAVAILABLE,
    IDENTIFIER_COLLISION,
}

/**
 * Thread-safe session grant manager. A grant is permanently invalidated when
 * it expires, is revoked, or its supporting consent is no longer effective.
 */
class SensitiveFeatureGrantManager(
    private val consentLedger: ConsentLedger,
    private val clock: EpochClock = SystemEpochClock,
    private val idGenerator: OpaqueIdGenerator = SecureOpaqueIdGenerator(),
    private val maximumGrantDurationMillis: Long = DEFAULT_MAXIMUM_GRANT_DURATION_MILLIS,
) {
    private val lock = Any()
    private val records = LinkedHashMap<SensitiveGrantId, GrantRecord>()

    init {
        require(maximumGrantDurationMillis > 0) { "maximumGrantDurationMillis must be positive." }
    }

    fun issue(request: SensitiveFeatureGrantRequest): SensitiveGrantIssueResult {
        val now = now()
        if (request.expiresAtEpochMillis <= now) {
            return SensitiveGrantIssueResult.Denied(SensitiveGrantDenial.EXPIRY_NOT_IN_FUTURE)
        }
        if (request.expiresAtEpochMillis - now > maximumGrantDurationMillis) {
            return SensitiveGrantIssueResult.Denied(SensitiveGrantDenial.EXPIRY_EXCEEDS_SESSION_LIMIT)
        }
        if (!consentLedger.isGranted(request.feature.requiredConsentPurpose, request.requiredScopes, now)) {
            return SensitiveGrantIssueResult.Denied(SensitiveGrantDenial.CONSENT_NOT_GRANTED)
        }

        val grantId = try {
            SensitiveGrantId(idGenerator.nextId())
        } catch (_: RuntimeException) {
            return SensitiveGrantIssueResult.Denied(SensitiveGrantDenial.IDENTIFIER_UNAVAILABLE)
        }

        return synchronized(lock) {
            if (records.containsKey(grantId)) {
                return@synchronized SensitiveGrantIssueResult.Denied(
                    SensitiveGrantDenial.IDENTIFIER_COLLISION,
                )
            }
            val grant = SessionGrant(
                id = grantId,
                sessionId = request.sessionId,
                feature = request.feature,
                requiredScopes = request.requiredScopes.toSet(),
                issuedAtEpochMillis = now,
                expiresAtEpochMillis = request.expiresAtEpochMillis,
            )
            records[grant.id] = GrantRecord(grant)
            SensitiveGrantIssueResult.Granted(grant)
        }
    }

    fun status(grantId: SensitiveGrantId, sessionId: SensitiveSessionId): SensitiveGrantStatus =
        synchronized(lock) {
            val record = records[grantId]
            if (record == null || record.grant.sessionId != sessionId) {
                return@synchronized SensitiveGrantStatus(SensitiveGrantState.NOT_FOUND)
            }
            evaluate(record, now())
            record.status()
        }

    fun isActive(
        grantId: SensitiveGrantId,
        sessionId: SensitiveSessionId,
        feature: SensitiveFeature,
    ): Boolean {
        val current = status(grantId, sessionId)
        return current.state == SensitiveGrantState.ACTIVE && current.feature == feature
    }

    fun revoke(grantId: SensitiveGrantId, sessionId: SensitiveSessionId): SensitiveGrantStatus =
        synchronized(lock) {
            val record = records[grantId]
            if (record == null || record.grant.sessionId != sessionId) {
                return@synchronized SensitiveGrantStatus(SensitiveGrantState.NOT_FOUND)
            }
            evaluate(record, now())
            if (record.state == SensitiveGrantState.ACTIVE) {
                record.state = SensitiveGrantState.REVOKED
            }
            record.status()
        }

    fun revokeSession(sessionId: SensitiveSessionId): Int = synchronized(lock) {
        val now = now()
        var revokedCount = 0
        records.values.forEach { record ->
            if (record.grant.sessionId == sessionId) {
                evaluate(record, now)
                if (record.state == SensitiveGrantState.ACTIVE) {
                    record.state = SensitiveGrantState.REVOKED
                    revokedCount += 1
                }
            }
        }
        revokedCount
    }

    private fun evaluate(record: GrantRecord, atEpochMillis: Long) {
        if (record.state != SensitiveGrantState.ACTIVE) {
            return
        }
        if (atEpochMillis >= record.grant.expiresAtEpochMillis) {
            record.state = SensitiveGrantState.EXPIRED
            return
        }
        if (!consentLedger.isGranted(
                record.grant.feature.requiredConsentPurpose,
                record.grant.requiredScopes,
                atEpochMillis,
            )
        ) {
            record.state = SensitiveGrantState.REVOKED
        }
    }

    private fun now(): Long {
        val now = clock.nowEpochMillis()
        require(now >= 0) { "EpochClock returned a negative value." }
        return now
    }

    private class GrantRecord(
        val grant: SessionGrant,
        var state: SensitiveGrantState = SensitiveGrantState.ACTIVE,
    ) {
        fun status(): SensitiveGrantStatus = SensitiveGrantStatus(
            state = state,
            feature = grant.feature,
            expiresAtEpochMillis = grant.expiresAtEpochMillis,
        )
    }

    private companion object {
        const val DEFAULT_MAXIMUM_GRANT_DURATION_MILLIS = 15 * 60 * 1_000L
    }
}
