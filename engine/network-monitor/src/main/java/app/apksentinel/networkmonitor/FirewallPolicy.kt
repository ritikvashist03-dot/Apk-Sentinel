package app.apksentinel.networkmonitor

import app.apksentinel.core.security.HostValidation
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.LinkedHashMap
import java.util.Locale

/**
 * Durable, local firewall-policy foundation. This is deliberately an engine
 * model: [FirewallPolicySecureStore] receives plaintext only after a host has
 * authenticated and decrypted it with Android Keystore-backed encryption.
 * The default monitor runtime still uses [InMemoryFirewallRuleProvider]; a
 * host must explicitly compose a [FirewallPolicyController] to opt in.
 */

enum class FirewallPolicyAction { ALLOW, BLOCK }

enum class FirewallPolicyUnsupportedScope {
    COUNTRY,
    ASN,
    URL_PATH,
    TLS_SNI,
    PROCESS_NAME,
    WIFI_NETWORK,
    /** No authenticated receiver currently proves DNS-to-flow destination pinning. */
    DOMAIN_DESTINATION_UNAVAILABLE,
    UNKNOWN,
}

enum class FirewallPolicySafetyMode {
    /** A broad blocking rule cannot activate until an integration can classify critical flows. */
    REQUIRE_CLASSIFIED_NORMAL_FOR_BROAD_BLOCK,

    /** A specifically attributed third-party app is eligible without broad-flow classification. */
    ATTRIBUTED_APP_ONLY,
}

enum class FirewallPolicyLimitation {
    UNSUPPORTED_SCOPE,
    SYSTEM_CRITICAL_UID_REQUIRES_HOST_CLASSIFICATION,
    BROAD_BLOCK_REQUIRES_CAPTIVE_PORTAL_AND_SYSTEM_CRITICAL_CLASSIFICATION,
    DOMAIN_SIGNAL_REQUIRED,
    APP_UID_ATTRIBUTION_REQUIRED,
    APP_PACKAGE_ATTRIBUTION_REQUIRED,
    CLOCK_UNAVAILABLE,
    CLOCK_ROLLBACK,
    TEMPORARY_ALLOW_NOT_ACTIVE_WITH_UNTRUSTED_CLOCK,
}

enum class FirewallPolicyActivity {
    ACTIVE,
    ACTIVE_BLOCK_RETAINED_WITH_UNTRUSTED_CLOCK,
    DISABLED,
    EXPIRED,
    EMERGENCY_RELEASE,
    UNSUPPORTED_SCOPE,
    SYSTEM_CRITICAL_SCOPE_LIMITATION,
    BROAD_BLOCK_SAFETY_LIMITATION,
    TEMPORARY_ALLOW_CLOCK_LIMITATION,
}

enum class FirewallPolicySaveState {
    SAVED,
    NOT_SAVED,
    STORAGE_UNAVAILABLE,
    STORAGE_REJECTED,
    STORAGE_CORRUPT,
}

enum class FirewallPolicyValidationCode {
    INVALID_ID,
    DUPLICATE_ID,
    TOO_MANY_RULES,
    INVALID_UTF8,
    INVALID_PACKAGE_NAME,
    INVALID_DOMAIN,
    INVALID_UID,
    INVALID_CIDR,
    INVALID_PORT_RANGE,
    INVALID_EXPIRY,
    TOO_MANY_VALUES,
    INVALID_UNSUPPORTED_SCOPE,
}

enum class FirewallPolicyMutationCode {
    APPLIED,
    VALIDATION_FAILED,
    RULE_NOT_FOUND,
    STORAGE_UNAVAILABLE,
    STORAGE_REJECTED,
    UNDO_STALE,
    UNDO_NOT_FOUND,
}

enum class FirewallPolicyHitCode {
    RECORDED,
    NOT_A_CONFIRMED_MATCH,
    RULE_NOT_FOUND,
}

data class FirewallPolicyRuleDraft(
    val id: String,
    val action: FirewallPolicyAction,
    val priority: Int = 0,
    val enabled: Boolean = true,
    val appUids: Set<Int> = emptySet(),
    val appPackageNames: Set<String> = emptySet(),
    val destinationCidrs: Set<String> = emptySet(),
    val domainNames: Set<String> = emptySet(),
    val protocols: Set<TransportProtocol> = emptySet(),
    val destinationPortRange: IntRange? = null,
    val expiresAtMillis: Long? = null,
    val unsupportedScopes: Set<FirewallPolicyUnsupportedScope> = emptySet(),
    val safetyMode: FirewallPolicySafetyMode = FirewallPolicySafetyMode.REQUIRE_CLASSIFIED_NORMAL_FOR_BROAD_BLOCK,
)

/** A validated, serializable policy rule. It is intentionally separate from [FirewallRule]. */
data class FirewallPolicyRule(
    val id: String,
    val action: FirewallPolicyAction,
    val priority: Int,
    val enabled: Boolean,
    val appUids: Set<Int>,
    val appPackageNames: Set<String>,
    val destinationCidrs: Set<IpCidr>,
    val domainNames: Set<String>,
    val protocols: Set<TransportProtocol>,
    val destinationPortRange: IntRange?,
    val expiresAtMillis: Long?,
    val unsupportedScopes: Set<FirewallPolicyUnsupportedScope>,
    val safetyMode: FirewallPolicySafetyMode,
)

data class FirewallPolicyRuleStatus(
    val ruleId: String,
    /** The user's saved enable switch, without implying that a rule is enforceable. */
    val enabled: Boolean,
    /** Whether this policy version made it to the secure store. */
    val saved: FirewallPolicySaveState,
    /** Current eligibility for conversion to an active forwarding rule. */
    val active: Boolean,
    val activity: FirewallPolicyActivity,
    /** Incremented only from a forwarder-confirmed matching outcome. */
    val confirmedHitCount: Long,
    val lastConfirmedHitAtMillis: Long?,
    val limitations: Set<FirewallPolicyLimitation>,
)

data class FirewallPolicySnapshot(
    val rules: List<FirewallPolicyRule>,
    val statuses: List<FirewallPolicyRuleStatus>,
    val emergencyReleaseActive: Boolean,
    val saveState: FirewallPolicySaveState,
)

class FirewallPolicyUndoToken internal constructor(
    val value: String,
    internal val appliedRevision: Long,
)

data class FirewallPolicyMutationResult(
    val code: FirewallPolicyMutationCode,
    val validation: Set<FirewallPolicyValidationCode> = emptySet(),
    val undoToken: FirewallPolicyUndoToken? = null,
)

data class FirewallPolicyHitResult(
    val code: FirewallPolicyHitCode,
    val ruleId: String? = null,
)

sealed interface FirewallPolicySecureStoreRead {
    object Missing : FirewallPolicySecureStoreRead
    data class Available(val plaintext: ByteArray) : FirewallPolicySecureStoreRead
    object Unavailable : FirewallPolicySecureStoreRead
    object Corrupt : FirewallPolicySecureStoreRead
}

enum class FirewallPolicySecureStoreWrite { WRITTEN, UNAVAILABLE, REJECTED }

enum class FirewallPolicySecureStoreErase { ERASED, UNAVAILABLE, REJECTED }

/**
 * Android-facing implementations must decrypt only after Keystore authentication
 * and encrypt/authenticate bytes before durable write. The engine never supplies
 * a plaintext SharedPreferences implementation.
 */
interface FirewallPolicySecureStore {
    fun read(): FirewallPolicySecureStoreRead
    fun write(plaintext: ByteArray): FirewallPolicySecureStoreWrite
    /** Removes the encrypted policy and its dedicated key when the host supports key erasure. */
    fun erase(): FirewallPolicySecureStoreErase
}

/** Test and preview store only; it is intentionally process-local and not encrypted. */
class InMemoryFirewallPolicySecureStore(initialPlaintext: ByteArray? = null) : FirewallPolicySecureStore {
    private val lock = Any()
    private var bytes: ByteArray? = initialPlaintext?.copyOf()

    override fun read(): FirewallPolicySecureStoreRead = synchronized(lock) {
        bytes?.copyOf()?.let(FirewallPolicySecureStoreRead::Available) ?: FirewallPolicySecureStoreRead.Missing
    }

    override fun write(plaintext: ByteArray): FirewallPolicySecureStoreWrite = synchronized(lock) {
        bytes = plaintext.copyOf()
        FirewallPolicySecureStoreWrite.WRITTEN
    }

    override fun erase(): FirewallPolicySecureStoreErase = synchronized(lock) {
        bytes?.fill(0)
        bytes = null
        FirewallPolicySecureStoreErase.ERASED
    }
}

private data class FirewallPolicyDocument(
    val rules: List<FirewallPolicyRule> = emptyList(),
    val emergencyRelease: Boolean = false,
    val lastTrustedClockMillis: Long? = null,
)

sealed interface FirewallPolicyClockReading {
    data class Available(val millis: Long) : FirewallPolicyClockReading
    object Unavailable : FirewallPolicyClockReading
}

/**
 * A host may supply this only when it can prove authenticated, packet-bound
 * domain attribution at enforcement time. A resolver result alone is not this
 * capability and must never be adapted into one.
 */
fun interface AuthenticatedDomainDestinationCapability {
    fun isAuthenticatedAndPacketBound(domains: Set<String>): Boolean
}

fun interface FirewallPolicyClock {
    fun read(): FirewallPolicyClockReading
}

object SystemFirewallPolicyClock : FirewallPolicyClock {
    override fun read(): FirewallPolicyClockReading = runCatching {
        System.currentTimeMillis().takeIf { it > 0L }?.let(FirewallPolicyClockReading::Available)
            ?: FirewallPolicyClockReading.Unavailable
    }.getOrDefault(FirewallPolicyClockReading.Unavailable)
}

/**
 * A durable policy controller which is also a [FirewallRuleProvider]. Passing
 * this controller to a monitor dependency is an explicit opt-in; it does not
 * alter the runtime's default process-local provider.
 */
class FirewallPolicyController(
    private val secureStore: FirewallPolicySecureStore,
    private val clock: FirewallPolicyClock = SystemFirewallPolicyClock,
    private val tokenSource: () -> String = { java.util.UUID.randomUUID().toString() },
    private val domainDestinationCapability: AuthenticatedDomainDestinationCapability? = null,
) : FirewallRuleProvider {
    private val lock = Any()
    private var document: FirewallPolicyDocument
    private var saveState: FirewallPolicySaveState
    private var revision = 0L
    private var lastObservedTrustedClockMillis: Long? = null
    private val undoByToken = LinkedHashMap<String, FirewallPolicyDocument>()
    private val hitByRuleId = LinkedHashMap<String, FirewallPolicyHit>()

    init {
        val loaded = loadDocument(secureStore.read())
        document = loaded.document.copy(rules = loaded.document.rules.map(::withDomainAvailability))
        saveState = loaded.saveState
        lastObservedTrustedClockMillis = document.lastTrustedClockMillis
    }

    override fun snapshot(): List<FirewallRule> = synchronized(lock) {
        rulesForForwarderLocked().map { it.toForwardingRule() }
    }

    fun current(): FirewallPolicySnapshot = synchronized(lock) {
        val status = statusByRuleLocked()
        FirewallPolicySnapshot(
            rules = document.rules,
            statuses = document.rules.map { status.getValue(it.id) },
            emergencyReleaseActive = document.emergencyRelease,
            saveState = saveState,
        )
    }

    fun upsert(draft: FirewallPolicyRuleDraft): FirewallPolicyMutationResult = synchronized(lock) {
        val converted = convertDraft(draft)
        if (converted is DraftConversion.Invalid) {
            return@synchronized FirewallPolicyMutationResult(
                FirewallPolicyMutationCode.VALIDATION_FAILED,
                converted.codes,
            )
        }
        val rule = (converted as DraftConversion.Valid).rule
        val replacing = document.rules.any { it.id == rule.id }
        if (!replacing && document.rules.size >= MAX_RULES) {
            return@synchronized FirewallPolicyMutationResult(
                FirewallPolicyMutationCode.VALIDATION_FAILED,
                setOf(FirewallPolicyValidationCode.TOO_MANY_RULES),
            )
        }
        persistMutationLocked(document.copy(rules = (document.rules.filterNot { it.id == rule.id } + rule).sortedBy { it.id }))
    }

    fun remove(ruleId: String): FirewallPolicyMutationResult = synchronized(lock) {
        if (document.rules.none { it.id == ruleId }) {
            return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.RULE_NOT_FOUND)
        }
        persistMutationLocked(document.copy(rules = document.rules.filterNot { it.id == ruleId })).also {
            if (it.code == FirewallPolicyMutationCode.APPLIED) hitByRuleId.remove(ruleId)
        }
    }

    /** Persisted emergency release: no policy rule is converted to a forwarder rule. */
    fun emergencyRelease(): FirewallPolicyMutationResult = synchronized(lock) {
        if (document.emergencyRelease) return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.APPLIED)
        persistMutationLocked(document.copy(emergencyRelease = true))
    }

    fun clearEmergencyRelease(): FirewallPolicyMutationResult = synchronized(lock) {
        if (!document.emergencyRelease) return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.APPLIED)
        persistMutationLocked(document.copy(emergencyRelease = false))
    }

    /** Persistently turns off rules but preserves them for inspection and a single undo. */
    fun disableAll(): FirewallPolicyMutationResult = synchronized(lock) {
        if (document.rules.none(FirewallPolicyRule::enabled)) return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.APPLIED)
        persistMutationLocked(document.copy(rules = document.rules.map { it.copy(enabled = false) }))
    }

    /**
     * Privacy-only erase. A host store must confirm removal of both its ciphertext
     * and dedicated encryption key before this controller drops the in-memory policy.
     */
    fun eraseForPrivacy(): Boolean = synchronized(lock) {
        when (secureStore.erase()) {
            FirewallPolicySecureStoreErase.ERASED -> {
                document = FirewallPolicyDocument()
                saveState = FirewallPolicySaveState.NOT_SAVED
                lastObservedTrustedClockMillis = null
                undoByToken.clear()
                hitByRuleId.clear()
                revision += 1L
                true
            }
            FirewallPolicySecureStoreErase.UNAVAILABLE,
            FirewallPolicySecureStoreErase.REJECTED -> false
        }
    }

    /** Undo is intentionally single-revision: it never overwrites a later policy change. */
    fun undo(token: FirewallPolicyUndoToken): FirewallPolicyMutationResult = synchronized(lock) {
        val previous = undoByToken[token.value]
            ?: return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.UNDO_NOT_FOUND)
        if (revision != token.appliedRevision) {
            return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.UNDO_STALE)
        }
        val encoded = FirewallPolicyCodec.encode(previous)
            ?: return@synchronized FirewallPolicyMutationResult(FirewallPolicyMutationCode.STORAGE_REJECTED)
        when (secureStore.write(encoded)) {
            FirewallPolicySecureStoreWrite.WRITTEN -> {
                encoded.fill(0)
                document = previous
                revision += 1
                undoByToken.remove(token.value)
                FirewallPolicyMutationResult(FirewallPolicyMutationCode.APPLIED)
            }
            FirewallPolicySecureStoreWrite.UNAVAILABLE -> {
                encoded.fill(0)
                saveState = FirewallPolicySaveState.STORAGE_UNAVAILABLE
                FirewallPolicyMutationResult(FirewallPolicyMutationCode.STORAGE_UNAVAILABLE)
            }
            FirewallPolicySecureStoreWrite.REJECTED -> {
                encoded.fill(0)
                saveState = FirewallPolicySaveState.STORAGE_REJECTED
                FirewallPolicyMutationResult(FirewallPolicyMutationCode.STORAGE_REJECTED)
            }
        }
    }

    /**
     * Records a hit only after the caller supplies both the original decision
     * and its matching forwarder result. A requested decision alone is never a
     * firewall-hit claim.
     */
    fun recordConfirmedOutcome(
        decision: FirewallDecision,
        result: FirewallEnforcementResult,
        atMillis: Long? = null,
    ): FirewallPolicyHitResult = synchronized(lock) {
        if (decision.directiveId != result.directiveId) {
            return@synchronized FirewallPolicyHitResult(FirewallPolicyHitCode.NOT_A_CONFIRMED_MATCH)
        }
        val legacyId = decision.matchedRuleId ?: return@synchronized FirewallPolicyHitResult(FirewallPolicyHitCode.NOT_A_CONFIRMED_MATCH)
        val ruleId = fromForwardingRuleId(legacyId) ?: return@synchronized FirewallPolicyHitResult(FirewallPolicyHitCode.NOT_A_CONFIRMED_MATCH)
        val expected = when (decision.requestedAction) {
            FirewallAction.BLOCK -> FirewallEnforcementOutcome.BLOCKED
            FirewallAction.ALLOW -> FirewallEnforcementOutcome.ALLOWED
        }
        if (result.outcome != expected) {
            return@synchronized FirewallPolicyHitResult(FirewallPolicyHitCode.NOT_A_CONFIRMED_MATCH)
        }
        if (document.rules.none { it.id == ruleId }) {
            return@synchronized FirewallPolicyHitResult(FirewallPolicyHitCode.RULE_NOT_FOUND, ruleId)
        }
        val confirmedAtMillis = atMillis ?: currentTrustedMillis()
        val old = hitByRuleId[ruleId] ?: FirewallPolicyHit()
        hitByRuleId[ruleId] = old.copy(
            count = if (old.count == Long.MAX_VALUE) Long.MAX_VALUE else old.count + 1L,
            lastAtMillis = confirmedAtMillis?.takeIf { it > 0L },
        )
        FirewallPolicyHitResult(FirewallPolicyHitCode.RECORDED, ruleId)
    }

    private fun persistMutationLocked(next: FirewallPolicyDocument): FirewallPolicyMutationResult {
        val withClock = next.withUpdatedTrustedClock(clock.read())
        val encoded = FirewallPolicyCodec.encode(withClock)
            ?: return FirewallPolicyMutationResult(FirewallPolicyMutationCode.STORAGE_REJECTED)
        return when (secureStore.write(encoded)) {
            FirewallPolicySecureStoreWrite.WRITTEN -> {
                encoded.fill(0)
                val previous = document
                document = withClock
                saveState = FirewallPolicySaveState.SAVED
                revision += 1L
                val tokenValue = tokenSource().takeIf(::isSafeToken) ?: return FirewallPolicyMutationResult(FirewallPolicyMutationCode.APPLIED)
                undoByToken[tokenValue] = previous
                while (undoByToken.size > MAX_UNDO_ENTRIES) undoByToken.remove(undoByToken.entries.first().key)
                FirewallPolicyMutationResult(
                    FirewallPolicyMutationCode.APPLIED,
                    undoToken = FirewallPolicyUndoToken(tokenValue, revision),
                )
            }
            FirewallPolicySecureStoreWrite.UNAVAILABLE -> {
                encoded.fill(0)
                saveState = FirewallPolicySaveState.STORAGE_UNAVAILABLE
                FirewallPolicyMutationResult(FirewallPolicyMutationCode.STORAGE_UNAVAILABLE)
            }
            FirewallPolicySecureStoreWrite.REJECTED -> {
                encoded.fill(0)
                saveState = FirewallPolicySaveState.STORAGE_REJECTED
                FirewallPolicyMutationResult(FirewallPolicyMutationCode.STORAGE_REJECTED)
            }
        }
    }

    private fun rulesForForwarderLocked(): List<FirewallPolicyRule> {
        if (document.emergencyRelease) return emptyList()
        val time = clockStateLocked()
        return document.rules.filter { statusForRuleLocked(it, time).active }
    }

    private fun statusByRuleLocked(): Map<String, FirewallPolicyRuleStatus> {
        val time = clockStateLocked()
        return document.rules.associate { it.id to statusForRuleLocked(it, time) }
    }

    private fun statusForRuleLocked(
        rule: FirewallPolicyRule,
        time: PolicyClockState,
    ): FirewallPolicyRuleStatus {
        val hit = hitByRuleId[rule.id] ?: FirewallPolicyHit()
        val limitations = linkedSetOf<FirewallPolicyLimitation>()
        val activity = when {
            !rule.enabled -> FirewallPolicyActivity.DISABLED
            document.emergencyRelease -> FirewallPolicyActivity.EMERGENCY_RELEASE
            rule.domainNames.isNotEmpty() && !domainDestinationAvailable(rule.domainNames) -> {
                limitations += FirewallPolicyLimitation.UNSUPPORTED_SCOPE
                FirewallPolicyActivity.UNSUPPORTED_SCOPE
            }
            rule.unsupportedScopes.isNotEmpty() -> {
                limitations += FirewallPolicyLimitation.UNSUPPORTED_SCOPE
                FirewallPolicyActivity.UNSUPPORTED_SCOPE
            }
            rule.appUids.any { it < FIRST_APPLICATION_UID } -> {
                limitations += FirewallPolicyLimitation.SYSTEM_CRITICAL_UID_REQUIRES_HOST_CLASSIFICATION
                FirewallPolicyActivity.SYSTEM_CRITICAL_SCOPE_LIMITATION
            }
            rule.action == FirewallPolicyAction.BLOCK && rule.hasBroadAppScope() -> {
                limitations += FirewallPolicyLimitation.BROAD_BLOCK_REQUIRES_CAPTIVE_PORTAL_AND_SYSTEM_CRITICAL_CLASSIFICATION
                FirewallPolicyActivity.BROAD_BLOCK_SAFETY_LIMITATION
            }
            time is PolicyClockState.Trusted && rule.expiresAtMillis != null && rule.expiresAtMillis <= time.millis ->
                FirewallPolicyActivity.EXPIRED
            time !is PolicyClockState.Trusted && rule.action == FirewallPolicyAction.ALLOW && rule.expiresAtMillis != null -> {
                limitations += FirewallPolicyLimitation.TEMPORARY_ALLOW_NOT_ACTIVE_WITH_UNTRUSTED_CLOCK
                limitations += time.toLimitation()
                FirewallPolicyActivity.TEMPORARY_ALLOW_CLOCK_LIMITATION
            }
            time !is PolicyClockState.Trusted && rule.action == FirewallPolicyAction.BLOCK -> {
                limitations += time.toLimitation()
                FirewallPolicyActivity.ACTIVE_BLOCK_RETAINED_WITH_UNTRUSTED_CLOCK
            }
            else -> FirewallPolicyActivity.ACTIVE
        }
        return FirewallPolicyRuleStatus(
            ruleId = rule.id,
            enabled = rule.enabled,
            saved = saveState,
            active = activity == FirewallPolicyActivity.ACTIVE ||
                activity == FirewallPolicyActivity.ACTIVE_BLOCK_RETAINED_WITH_UNTRUSTED_CLOCK,
            activity = activity,
            confirmedHitCount = hit.count,
            lastConfirmedHitAtMillis = hit.lastAtMillis,
            limitations = limitations,
        )
    }

    private fun currentTrustedMillis(): Long? = when (val state = clockStateLocked()) {
        is PolicyClockState.Trusted -> state.millis
        else -> null
    }

    private fun clockStateLocked(): PolicyClockState {
        val state = clockState(lastObservedTrustedClockMillis ?: document.lastTrustedClockMillis, clock.read())
        if (state is PolicyClockState.Trusted) lastObservedTrustedClockMillis = state.millis
        return state
    }

    private data class FirewallPolicyHit(val count: Long = 0L, val lastAtMillis: Long? = null)

    private data class LoadedDocument(val document: FirewallPolicyDocument, val saveState: FirewallPolicySaveState)

    private fun loadDocument(read: FirewallPolicySecureStoreRead): LoadedDocument = when (read) {
        FirewallPolicySecureStoreRead.Missing -> LoadedDocument(FirewallPolicyDocument(), FirewallPolicySaveState.NOT_SAVED)
        FirewallPolicySecureStoreRead.Unavailable -> LoadedDocument(FirewallPolicyDocument(), FirewallPolicySaveState.STORAGE_UNAVAILABLE)
        FirewallPolicySecureStoreRead.Corrupt -> LoadedDocument(FirewallPolicyDocument(), FirewallPolicySaveState.STORAGE_CORRUPT)
        is FirewallPolicySecureStoreRead.Available -> {
            val decoded = FirewallPolicyCodec.decode(read.plaintext)
            read.plaintext.fill(0)
            decoded?.let { LoadedDocument(it, FirewallPolicySaveState.SAVED) }
                ?: LoadedDocument(FirewallPolicyDocument(), FirewallPolicySaveState.STORAGE_CORRUPT)
        }
    }

    private sealed interface DraftConversion {
        data class Valid(val rule: FirewallPolicyRule) : DraftConversion
        data class Invalid(val codes: Set<FirewallPolicyValidationCode>) : DraftConversion
    }

    private fun convertDraft(draft: FirewallPolicyRuleDraft): DraftConversion {
        val validation = linkedSetOf<FirewallPolicyValidationCode>()
        if (!isSafeRuleId(draft.id)) validation += FirewallPolicyValidationCode.INVALID_ID
        if (draft.appUids.size > MAX_SCOPE_VALUES || draft.appPackageNames.size > MAX_SCOPE_VALUES ||
            draft.destinationCidrs.size > MAX_SCOPE_VALUES || draft.domainNames.size > MAX_SCOPE_VALUES ||
            draft.protocols.size > MAX_SCOPE_VALUES || draft.unsupportedScopes.size > MAX_SCOPE_VALUES
        ) validation += FirewallPolicyValidationCode.TOO_MANY_VALUES
        if (draft.appUids.any { it < 0 }) validation += FirewallPolicyValidationCode.INVALID_UID
        if (draft.appPackageNames.any { !HostValidation.isValidPackageName(it) }) validation += FirewallPolicyValidationCode.INVALID_PACKAGE_NAME
        // allowTrailingDot: this store canonicalizes a FQDN-style trailing dot away below
        // (normalizeDomain), so accepting it here is a deliberate, non-security-relevant choice —
        // see HostValidation.isValidDomain's doc and
        // FirewallPolicyControllerTest.persistedCodecRoundTripLoadsAValidatedRuleWithoutPlaintextStoreAssumptions.
        if (draft.domainNames.any { !HostValidation.isValidDomain(it, allowTrailingDot = true) }) validation += FirewallPolicyValidationCode.INVALID_DOMAIN
        if (draft.unsupportedScopes.any { it == FirewallPolicyUnsupportedScope.UNKNOWN }) {
            validation += FirewallPolicyValidationCode.INVALID_UNSUPPORTED_SCOPE
        }
        if (draft.destinationPortRange != null &&
            (draft.destinationPortRange.first !in 1..65_535 || draft.destinationPortRange.last !in 1..65_535)
        ) validation += FirewallPolicyValidationCode.INVALID_PORT_RANGE
        if (draft.expiresAtMillis != null && draft.expiresAtMillis <= 0L) validation += FirewallPolicyValidationCode.INVALID_EXPIRY
        val cidrs = draft.destinationCidrs.mapNotNull { value ->
            if (!isStrictUtf8(value)) {
                validation += FirewallPolicyValidationCode.INVALID_UTF8
                null
            } else {
                IpCidr.parse(value)?.also { if (value.length > MAX_CIDR_CHARS) validation += FirewallPolicyValidationCode.INVALID_CIDR }
                    ?: run { validation += FirewallPolicyValidationCode.INVALID_CIDR; null }
            }
        }.toSet()
        if (cidrs.size != draft.destinationCidrs.size) validation += FirewallPolicyValidationCode.INVALID_CIDR
        if (validation.isNotEmpty()) return DraftConversion.Invalid(validation)
        val normalizedDomains = draft.domainNames.map(::normalizeDomain).toSortedSet()
        val unsupportedScopes = draft.unsupportedScopes.toMutableSet().also {
            if (normalizedDomains.isNotEmpty() && !domainDestinationAvailable(normalizedDomains)) {
                it += FirewallPolicyUnsupportedScope.DOMAIN_DESTINATION_UNAVAILABLE
            }
        }
        return DraftConversion.Valid(
            FirewallPolicyRule(
                id = draft.id,
                action = draft.action,
                priority = draft.priority,
                enabled = draft.enabled,
                appUids = draft.appUids.toSortedSet(),
                appPackageNames = draft.appPackageNames.map { it.lowercase(Locale.ROOT) }.toSortedSet(),
                destinationCidrs = cidrs.toSortedSet(compareBy(IpCidr::toString)),
                domainNames = normalizedDomains,
                protocols = draft.protocols.toSortedSet(compareBy(TransportProtocol::name)),
                destinationPortRange = draft.destinationPortRange,
                expiresAtMillis = draft.expiresAtMillis,
                unsupportedScopes = unsupportedScopes.toSortedSet(compareBy(FirewallPolicyUnsupportedScope::name)),
                safetyMode = draft.safetyMode,
            ),
        )
    }

    /** Used only by the codec after it has parsed a bounded wire record. */
    internal fun decodeStoredRule(draft: FirewallPolicyRuleDraft): FirewallPolicyRule? =
        (convertDraft(draft) as? DraftConversion.Valid)?.rule

    private fun domainDestinationAvailable(domains: Set<String>): Boolean =
        domains.isEmpty() || runCatching {
            domainDestinationCapability?.isAuthenticatedAndPacketBound(domains) == true
        }.getOrDefault(false)

    private fun withDomainAvailability(rule: FirewallPolicyRule): FirewallPolicyRule {
        if (rule.domainNames.isEmpty()) return rule
        val scopes = rule.unsupportedScopes.toMutableSet()
        if (domainDestinationAvailable(rule.domainNames)) {
            scopes.remove(FirewallPolicyUnsupportedScope.DOMAIN_DESTINATION_UNAVAILABLE)
        } else {
            scopes += FirewallPolicyUnsupportedScope.DOMAIN_DESTINATION_UNAVAILABLE
        }
        return rule.copy(unsupportedScopes = scopes)
    }

    private companion object {
        const val MAX_RULES = 128
        const val MAX_SCOPE_VALUES = 32
        const val MAX_UNDO_ENTRIES = 16
        const val MAX_CIDR_CHARS = 64
        const val FIRST_APPLICATION_UID = 10_000
    }
}

/**
 * A deterministic opt-in composition. The first provider wins an accidental
 * duplicate ID; policy-generated IDs are namespaced to avoid normal collisions.
 */
class CompositeFirewallRuleProvider(
    private vararg val providers: FirewallRuleProvider,
) : FirewallRuleProvider {
    override fun snapshot(): List<FirewallRule> {
        val byId = LinkedHashMap<String, FirewallRule>()
        providers.forEach { provider -> provider.snapshot().forEach { rule -> byId.putIfAbsent(rule.id, rule) } }
        return byId.values.toList()
    }
}

private fun FirewallPolicyRule.toForwardingRule(): FirewallRule = FirewallRule(
    id = toForwardingRuleId(id),
    action = when (action) {
        FirewallPolicyAction.ALLOW -> FirewallAction.ALLOW
        FirewallPolicyAction.BLOCK -> FirewallAction.BLOCK
    },
    priority = priority,
    enabled = enabled,
    appUids = appUids,
    appPackageNames = appPackageNames,
    destinationCidrs = destinationCidrs,
    domainNames = domainNames,
    protocols = protocols,
    destinationPortRange = destinationPortRange,
    expiresAtMillis = expiresAtMillis,
)

private fun FirewallPolicyRule.hasBroadAppScope(): Boolean = appUids.isEmpty() && appPackageNames.isEmpty()

private fun toForwardingRuleId(id: String): String = "policy.$id"
private fun fromForwardingRuleId(id: String): String? = id.removePrefix("policy.").takeIf { id.startsWith("policy.") }

private sealed interface PolicyClockState {
    data class Trusted(val millis: Long) : PolicyClockState
    object Unavailable : PolicyClockState
    object RolledBack : PolicyClockState
}

private fun clockState(lastTrusted: Long?, reading: FirewallPolicyClockReading): PolicyClockState = when (reading) {
    FirewallPolicyClockReading.Unavailable -> PolicyClockState.Unavailable
    is FirewallPolicyClockReading.Available -> when {
        reading.millis <= 0L -> PolicyClockState.Unavailable
        lastTrusted != null && reading.millis < lastTrusted -> PolicyClockState.RolledBack
        else -> PolicyClockState.Trusted(reading.millis)
    }
}

private fun PolicyClockState.toLimitation(): FirewallPolicyLimitation = when (this) {
    PolicyClockState.Unavailable -> FirewallPolicyLimitation.CLOCK_UNAVAILABLE
    PolicyClockState.RolledBack -> FirewallPolicyLimitation.CLOCK_ROLLBACK
    is PolicyClockState.Trusted -> FirewallPolicyLimitation.CLOCK_UNAVAILABLE
}

private fun FirewallPolicyDocument.withUpdatedTrustedClock(reading: FirewallPolicyClockReading): FirewallPolicyDocument = when {
    reading is FirewallPolicyClockReading.Available && reading.millis > 0L &&
        (lastTrustedClockMillis == null || reading.millis >= lastTrustedClockMillis) -> copy(lastTrustedClockMillis = reading.millis)
    else -> this
}

private fun isSafeRuleId(value: String): Boolean =
    value.length in 1..64 && isStrictUtf8(value) && value.all { it.isAsciiLetterOrDigit() || it == '.' || it == '_' || it == '-' }

private fun isSafeToken(value: String): Boolean = value.length in 1..128 && isStrictUtf8(value)

private fun normalizeDomain(value: String): String = value.trim().trimEnd('.').lowercase(Locale.ROOT)

private fun Char.isAsciiLetterOrDigit(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

private fun isStrictUtf8(value: String): Boolean {
    if (value.length > MAX_TEXT_CHARS || value.any(::isDisallowedControlOrBidi)) return false
    return try {
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        encoder.encode(CharBuffer.wrap(value))
        true
    } catch (_: CharacterCodingException) {
        false
    }
}

private fun isDisallowedControlOrBidi(value: Char): Boolean =
    value.code in 0..31 || value.code == 127 || value.code in 0x202a..0x202e || value.code in 0x2066..0x2069

private object FirewallPolicyCodec {
    private const val HEADER = "APSFW1"
    private const val MAX_DOCUMENT_BYTES = 128 * 1024
    private const val MAX_FIELDS = 14
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(document: FirewallPolicyDocument): ByteArray? {
        if (document.rules.size > 128) return null
        return runCatching {
            val rows = buildList {
                add(listOf(HEADER, document.emergencyRelease.flag(), document.lastTrustedClockMillis?.toString().orEmpty()).joinToString("|"))
                document.rules.sortedBy(FirewallPolicyRule::id).forEach { rule -> add(encodeRule(rule)) }
            }
            rows.joinToString("\n").toByteArray(StandardCharsets.UTF_8).takeIf { it.size <= MAX_DOCUMENT_BYTES }
        }.getOrNull()
    }

    fun decode(bytes: ByteArray): FirewallPolicyDocument? {
        if (bytes.isEmpty() || bytes.size > MAX_DOCUMENT_BYTES) return null
        val value = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            return null
        }
        val lines = value.split('\n')
        if (lines.isEmpty() || lines.size > 129) return null
        val header = lines.first().split('|')
        if (header.size != 3 || header[0] != HEADER) return null
        val emergency = header[1].toFlag() ?: return null
        val lastTrusted = header[2].takeIf(String::isNotEmpty)?.toLongOrNull()?.takeIf { it > 0L } ?: if (header[2].isNotEmpty()) return null else null
        val rules = lines.drop(1).map(::decodeRule)
        if (rules.any { it == null }) return null
        val materialized = rules.filterNotNull().sortedBy(FirewallPolicyRule::id)
        if (materialized.map(FirewallPolicyRule::id).distinct().size != materialized.size) return null
        return FirewallPolicyDocument(materialized, emergency, lastTrusted)
    }

    private fun encodeRule(rule: FirewallPolicyRule): String = listOf(
        "R",
        text(rule.id), rule.action.name, rule.priority.toString(), rule.enabled.flag(),
        rule.appUids.joinToString(","), strings(rule.appPackageNames), strings(rule.destinationCidrs.map(IpCidr::toString)),
        strings(rule.domainNames), rule.protocols.joinToString(",") { it.name },
        rule.destinationPortRange?.let { "${it.first}-${it.last}" }.orEmpty(), rule.expiresAtMillis?.toString().orEmpty(),
        rule.unsupportedScopes.joinToString(",") { it.name }, rule.safetyMode.name,
    ).joinToString("|")

    private fun decodeRule(line: String): FirewallPolicyRule? {
        val fields = line.split('|')
        if (fields.size != MAX_FIELDS || fields[0] != "R") return null
        val id = fromText(fields[1]) ?: return null
        val action = runCatching { FirewallPolicyAction.valueOf(fields[2]) }.getOrNull() ?: return null
        val priority = fields[3].toIntOrNull() ?: return null
        val enabled = fields[4].toFlag() ?: return null
        val uids = parseSet(fields[5]) { it.toIntOrNull()?.takeIf { uid -> uid >= 0 } } ?: return null
        val packages = parseStringSet(fields[6]) ?: return null
        val cidrStrings = parseStringSet(fields[7]) ?: return null
        val domains = parseStringSet(fields[8]) ?: return null
        val protocols = parseSet(fields[9]) { name -> runCatching { TransportProtocol.valueOf(name) }.getOrNull() } ?: return null
        val ports = if (fields[10].isEmpty()) {
            null
        } else {
            parsePortRange(fields[10]) ?: return null
        }
        val expiry = fields[11].takeIf(String::isNotEmpty)?.toLongOrNull()?.takeIf { it > 0L } ?: if (fields[11].isNotEmpty()) return null else null
        val unsupported = parseSet(fields[12]) { name -> runCatching { FirewallPolicyUnsupportedScope.valueOf(name) }.getOrNull() } ?: return null
        val safety = runCatching { FirewallPolicySafetyMode.valueOf(fields[13]) }.getOrNull() ?: return null
        val draft = FirewallPolicyRuleDraft(
            id = id, action = action, priority = priority, enabled = enabled, appUids = uids,
            appPackageNames = packages, destinationCidrs = cidrStrings, domainNames = domains,
            protocols = protocols, destinationPortRange = ports, expiresAtMillis = expiry,
            unsupportedScopes = unsupported, safetyMode = safety,
        )
        return FirewallPolicyController(InMemoryFirewallPolicySecureStore()).decodeStoredRule(draft)
    }

    private fun parsePortRange(value: String): IntRange? {
        if (value.isEmpty()) return null
        val parts = value.split('-')
        if (parts.size != 2) return null
        val start = parts[0].toIntOrNull() ?: return null
        val end = parts[1].toIntOrNull() ?: return null
        return (start..end).takeIf { start in 1..65_535 && end in 1..65_535 }
    }

    private fun strings(values: Collection<String>): String = values.sorted().joinToString(",") { text(it) }
    private fun parseStringSet(value: String): Set<String>? = parseSet(value, ::fromText)
    private fun <T> parseSet(value: String, parse: (String) -> T?): Set<T>? {
        if (value.isEmpty()) return emptySet()
        val values = value.split(',')
        if (values.size > 32) return null
        val parsed = values.map(parse)
        return if (parsed.any { it == null }) null else parsed.filterNotNull().toSet()
    }

    private fun text(value: String): String = encoder.encodeToString(value.toByteArray(StandardCharsets.UTF_8))
    private fun fromText(value: String): String? = runCatching {
        val decoded = decoder.decode(value)
        if (decoded.size > MAX_TEXT_CHARS * 4) null else StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(decoded)).toString().takeIf(::isStrictUtf8)
    }.getOrNull()
    private fun Boolean.flag(): String = if (this) "1" else "0"
    private fun String.toFlag(): Boolean? = when (this) { "1" -> true; "0" -> false; else -> null }
}

private const val MAX_TEXT_CHARS = 512
