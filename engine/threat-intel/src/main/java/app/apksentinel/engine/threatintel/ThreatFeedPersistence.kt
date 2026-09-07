package app.apksentinel.engine.threatintel

import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageFailure
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64
import kotlin.math.max

/**
 * The store persists one complete encrypted snapshot so a partial update never
 * replaces the active feed. It contains only signed feed bytes and lifecycle
 * metadata; it must never be used for traffic, URLs, app inventory or users.
 */
class ThreatFeedSnapshot(
    canonicalPayload: ByteArray,
    val signatureBase64: String,
    val highestAcceptedVersion: Long,
    val activatedAtMillis: Long,
    val declaredExpiresAtMillis: Long,
) {
    private val canonicalPayloadBytes: ByteArray = canonicalPayload.copyOf()

    /** A defensive copy prevents a caller mutating a snapshot after validation. */
    val canonicalPayload: ByteArray
        get() = canonicalPayloadBytes.copyOf()

    init {
        require(canonicalPayloadBytes.isNotEmpty()) { "Threat feed snapshot payload cannot be empty." }
        require(signatureBase64.isNotBlank()) { "Threat feed snapshot signature cannot be blank." }
        require(highestAcceptedVersion > 0L) { "Threat feed snapshot version must be positive." }
        require(activatedAtMillis >= 0L) { "Threat feed snapshot activation time cannot be negative." }
        require(declaredExpiresAtMillis > activatedAtMillis) {
            "Threat feed snapshot expiry must be after activation."
        }
    }
}

enum class ThreatFeedStoreFailure { STORAGE_UNAVAILABLE, MALFORMED_SNAPSHOT, SNAPSHOT_TOO_LARGE }

sealed interface ThreatFeedStoreResult<out T> {
    data class Success<T>(val value: T) : ThreatFeedStoreResult<T>
    data class Failure(val reason: ThreatFeedStoreFailure) : ThreatFeedStoreResult<Nothing>
}

interface ThreatFeedSnapshotStore {
    fun read(): ThreatFeedStoreResult<ThreatFeedSnapshot?>

    fun write(snapshot: ThreatFeedSnapshot): ThreatFeedStoreResult<Unit>

    fun delete(): ThreatFeedStoreResult<Unit>
}

/** Test-only / process-lifetime store; production composition should use [EncryptedThreatFeedSnapshotStore]. */
class InMemoryThreatFeedSnapshotStore : ThreatFeedSnapshotStore {
    private val lock = Any()
    private var snapshot: ThreatFeedSnapshot? = null

    override fun read(): ThreatFeedStoreResult<ThreatFeedSnapshot?> = synchronized(lock) {
        ThreatFeedStoreResult.Success(snapshot?.copyForRead())
    }

    override fun write(snapshot: ThreatFeedSnapshot): ThreatFeedStoreResult<Unit> = synchronized(lock) {
        this.snapshot = snapshot.copyForRead()
        ThreatFeedStoreResult.Success(Unit)
    }

    override fun delete(): ThreatFeedStoreResult<Unit> = synchronized(lock) {
        snapshot = null
        ThreatFeedStoreResult.Success(Unit)
    }
}

/**
 * Encrypted Android-keystore-compatible snapshot adapter. Use an
 * AndroidKeystoreEncryptedStorage with a dedicated key alias at composition.
 * All values live under one key to make each update atomic at this layer.
 */
class EncryptedThreatFeedSnapshotStore(
    private val encryptedStorage: EncryptedStorage,
    private val storageKey: SecureStorageKey = DEFAULT_STORAGE_KEY,
    private val codec: ThreatFeedSnapshotCodec = ThreatFeedSnapshotCodec(),
) : ThreatFeedSnapshotStore {
    override fun read(): ThreatFeedStoreResult<ThreatFeedSnapshot?> = when (val result = encryptedStorage.read(storageKey)) {
        is SecureStorageResult.Success -> {
            val bytes = result.value ?: return ThreatFeedStoreResult.Success(null)
            codec.decode(bytes)
        }
        is SecureStorageResult.Failure -> ThreatFeedStoreResult.Failure(result.reason.toThreatFeedStoreFailure())
    }

    override fun write(snapshot: ThreatFeedSnapshot): ThreatFeedStoreResult<Unit> {
        val encoded = when (val result = codec.encode(snapshot)) {
            is ThreatFeedStoreResult.Success -> result.value
            is ThreatFeedStoreResult.Failure -> return result
        }
        return when (val result = encryptedStorage.write(storageKey, encoded)) {
            is SecureStorageResult.Success -> ThreatFeedStoreResult.Success(Unit)
            is SecureStorageResult.Failure -> ThreatFeedStoreResult.Failure(result.reason.toThreatFeedStoreFailure())
        }
    }

    override fun delete(): ThreatFeedStoreResult<Unit> = when (val result = encryptedStorage.remove(storageKey)) {
        is SecureStorageResult.Success -> ThreatFeedStoreResult.Success(Unit)
        is SecureStorageResult.Failure -> ThreatFeedStoreResult.Failure(result.reason.toThreatFeedStoreFailure())
    }

    private companion object {
        val DEFAULT_STORAGE_KEY = SecureStorageKey("threat.feed.snapshot")
    }
}

/**
 * Bounded binary codec used inside encrypted storage. It never accepts a
 * trailing byte, and checks every length before allocating memory.
 */
class ThreatFeedSnapshotCodec(
    private val maxPayloadBytes: Int = DEFAULT_MAX_PERSISTED_PAYLOAD_BYTES,
    private val maxSignatureCharacters: Int = DEFAULT_MAX_SIGNATURE_CHARACTERS,
) {
    init {
        require(maxPayloadBytes in 1..MAX_PERSISTED_PAYLOAD_BYTES) { "maxPayloadBytes is outside the supported range." }
        require(maxSignatureCharacters in 8..MAX_SIGNATURE_CHARACTERS) {
            "maxSignatureCharacters is outside the supported range."
        }
    }

    fun encode(snapshot: ThreatFeedSnapshot): ThreatFeedStoreResult<ByteArray> {
        val payload = snapshot.canonicalPayload
        if (payload.size > maxPayloadBytes || snapshot.signatureBase64.length !in 1..maxSignatureCharacters) {
            return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.SNAPSHOT_TOO_LARGE)
        }
        if (!isCanonicalBase64(snapshot.signatureBase64)) {
            return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
        }
        return try {
            val bytes = ByteArrayOutputStream(HEADER_BYTES + payload.size + snapshot.signatureBase64.length)
            DataOutputStream(bytes).use { output ->
                output.writeInt(MAGIC)
                output.writeInt(FORMAT_VERSION)
                output.writeLong(snapshot.highestAcceptedVersion)
                output.writeLong(snapshot.activatedAtMillis)
                output.writeLong(snapshot.declaredExpiresAtMillis)
                output.writeInt(payload.size)
                output.write(payload)
                val signatureBytes = snapshot.signatureBase64.toByteArray(Charsets.US_ASCII)
                output.writeInt(signatureBytes.size)
                output.write(signatureBytes)
            }
            ThreatFeedStoreResult.Success(bytes.toByteArray())
        } catch (_: RuntimeException) {
            ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
        }
    }

    fun decode(bytes: ByteArray): ThreatFeedStoreResult<ThreatFeedSnapshot?> {
        if (bytes.isEmpty()) return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
        if (bytes.size > maximumEncodedBytes()) return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.SNAPSHOT_TOO_LARGE)
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                if (input.readInt() != MAGIC || input.readInt() != FORMAT_VERSION) {
                    return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
                }
                val highestVersion = input.readLong()
                val activatedAtMillis = input.readLong()
                val declaredExpiresAtMillis = input.readLong()
                val payload = input.readBoundedBytes(maxPayloadBytes) ?: return ThreatFeedStoreResult.Failure(
                    ThreatFeedStoreFailure.MALFORMED_SNAPSHOT,
                )
                val signatureBytes = input.readBoundedBytes(maxSignatureCharacters) ?: return ThreatFeedStoreResult.Failure(
                    ThreatFeedStoreFailure.MALFORMED_SNAPSHOT,
                )
                if (input.available() != 0) return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
                val signature = signatureBytes.toString(Charsets.US_ASCII)
                if (signature.toByteArray(Charsets.US_ASCII).contentEquals(signatureBytes).not() || !isCanonicalBase64(signature)) {
                    return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
                }
                if (highestVersion <= 0L || activatedAtMillis < 0L || declaredExpiresAtMillis <= 0L) {
                    return ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
                }
                ThreatFeedStoreResult.Success(
                    ThreatFeedSnapshot(
                        canonicalPayload = payload,
                        signatureBase64 = signature,
                        highestAcceptedVersion = highestVersion,
                        activatedAtMillis = activatedAtMillis,
                        declaredExpiresAtMillis = declaredExpiresAtMillis,
                    ),
                )
            }
        } catch (_: Exception) {
            ThreatFeedStoreResult.Failure(ThreatFeedStoreFailure.MALFORMED_SNAPSHOT)
        }
    }

    private fun maximumEncodedBytes(): Int = HEADER_BYTES + maxPayloadBytes + maxSignatureCharacters

    private companion object {
        const val MAGIC = 0x41534631 // ASF1
        const val FORMAT_VERSION = 1
        const val HEADER_BYTES = 4 + 4 + 8 + 8 + 8 + 4 + 4
        const val DEFAULT_MAX_PERSISTED_PAYLOAD_BYTES = 900_000
        const val DEFAULT_MAX_SIGNATURE_CHARACTERS = 1_024
        const val MAX_PERSISTED_PAYLOAD_BYTES = 900_000
        const val MAX_SIGNATURE_CHARACTERS = 4_096
    }
}

private fun DataInputStream.readBoundedBytes(maximum: Int): ByteArray? {
    val length = readInt()
    if (length !in 1..maximum || length > available()) return null
    val result = ByteArray(length)
    readFully(result)
    return result
}

private fun ThreatFeedSnapshot.copyForRead(): ThreatFeedSnapshot = ThreatFeedSnapshot(
    canonicalPayload = canonicalPayload,
    signatureBase64 = signatureBase64,
    highestAcceptedVersion = highestAcceptedVersion,
    activatedAtMillis = activatedAtMillis,
    declaredExpiresAtMillis = declaredExpiresAtMillis,
)

private fun SecureStorageFailure.toThreatFeedStoreFailure(): ThreatFeedStoreFailure = when (this) {
    SecureStorageFailure.INPUT_TOO_LARGE -> ThreatFeedStoreFailure.SNAPSHOT_TOO_LARGE
    SecureStorageFailure.MALFORMED_PAYLOAD -> ThreatFeedStoreFailure.MALFORMED_SNAPSHOT
    SecureStorageFailure.BACKING_STORE_FAILURE,
    SecureStorageFailure.ENCRYPTION_FAILED,
    SecureStorageFailure.DECRYPTION_FAILED -> ThreatFeedStoreFailure.STORAGE_UNAVAILABLE
}

private fun isCanonicalBase64(value: String): Boolean = try {
    value.isNotEmpty() &&
        value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '+' || it == '/' || it == '=' } &&
        Base64.getEncoder().encodeToString(Base64.getDecoder().decode(value)) == value
} catch (_: IllegalArgumentException) {
    false
}

/** Fail-closed local lifecycle result; raw feed bytes are intentionally never exposed in failures. */
sealed interface ThreatFeedLoadResult {
    object Missing : ThreatFeedLoadResult
    data class Active(val feed: VerifiedThreatFeed, val activatedAtMillis: Long) : ThreatFeedLoadResult
    data class Unavailable(val code: String, val safeReason: String) : ThreatFeedLoadResult
}

sealed interface ThreatFeedInstallResult {
    data class Installed(val feed: VerifiedThreatFeed) : ThreatFeedInstallResult
    data class Rejected(val code: String, val safeReason: String) : ThreatFeedInstallResult
    data class StorageFailure(val reason: ThreatFeedStoreFailure) : ThreatFeedInstallResult
}

enum class ThreatFeedRetentionResult { NOTHING_TO_DELETE, RETAINED, DELETED, STORAGE_FAILURE }

/**
 * Verifies before every activation and never overwrites a working snapshot
 * with a failed candidate. The repository is intentionally synchronous so a
 * caller can run it on a controlled IO dispatcher and surface an exact state.
 */
class ThreatFeedRepository(
    private val verifier: ThreatFeedVerifier,
    private val store: ThreatFeedSnapshotStore,
) {
    @Synchronized
    fun loadActive(nowMillis: Long): ThreatFeedLoadResult = when (val stored = store.read()) {
        is ThreatFeedStoreResult.Failure -> ThreatFeedLoadResult.Unavailable(
            "STORAGE",
            "Verified threat data is temporarily unavailable on this device.",
        )
        is ThreatFeedStoreResult.Success -> {
            val snapshot = stored.value ?: return ThreatFeedLoadResult.Missing
            when (val verified = verifier.verifyStored(snapshot.canonicalPayload, snapshot.signatureBase64, nowMillis)) {
                is ThreatFeedVerification.Accepted -> {
                    if (!snapshot.snapshotMatches(verified.feed)) {
                        ThreatFeedLoadResult.Unavailable(
                            "SNAPSHOT",
                            "Stored threat data is inconsistent and cannot be used.",
                        )
                    } else {
                        ThreatFeedLoadResult.Active(verified.feed, snapshot.activatedAtMillis)
                    }
                }
                is ThreatFeedVerification.Rejected -> ThreatFeedLoadResult.Unavailable(verified.code, verified.safeReason)
            }
        }
    }

    @Synchronized
    fun install(
        canonicalPayload: ByteArray,
        signatureBase64: String,
        nowMillis: Long,
    ): ThreatFeedInstallResult {
        val candidatePayload = canonicalPayload.copyOf()
        val existing = when (val result = store.read()) {
            is ThreatFeedStoreResult.Failure -> return ThreatFeedInstallResult.StorageFailure(result.reason)
            is ThreatFeedStoreResult.Success -> result.value
        }
        val highestVersion = existing?.highestAcceptedVersion
        val verified = verifier.verify(candidatePayload, signatureBase64, nowMillis, highestVersion)
        val accepted = verified as? ThreatFeedVerification.Accepted
            ?: (verified as ThreatFeedVerification.Rejected).let {
                return ThreatFeedInstallResult.Rejected(it.code, it.safeReason)
            }
        val snapshot = ThreatFeedSnapshot(
            canonicalPayload = candidatePayload,
            signatureBase64 = signatureBase64,
            highestAcceptedVersion = max(existing?.highestAcceptedVersion ?: 0L, accepted.feed.version),
            activatedAtMillis = nowMillis,
            declaredExpiresAtMillis = accepted.feed.expiresAtMillis,
        )
        return when (val persisted = store.write(snapshot)) {
            is ThreatFeedStoreResult.Success -> ThreatFeedInstallResult.Installed(accepted.feed)
            is ThreatFeedStoreResult.Failure -> ThreatFeedInstallResult.StorageFailure(persisted.reason)
        }
    }

    /** Removes the complete app-owned encrypted snapshot, including its version marker. */
    @Synchronized
    fun erase(): ThreatFeedRetentionResult = when (store.delete()) {
        is ThreatFeedStoreResult.Success -> ThreatFeedRetentionResult.DELETED
        is ThreatFeedStoreResult.Failure -> ThreatFeedRetentionResult.STORAGE_FAILURE
    }

    /**
     * Deletes expired app-owned feed data after the configured grace period.
     * The signed payload is rechecked when read for use; this timestamp is only
     * a privacy cleanup trigger and is not a trust decision.
     */
    @Synchronized
    fun pruneExpired(nowMillis: Long, policy: ThreatFeedRetentionPolicy = ThreatFeedRetentionPolicy()): ThreatFeedRetentionResult {
        val snapshot = when (val result = store.read()) {
            is ThreatFeedStoreResult.Failure -> return ThreatFeedRetentionResult.STORAGE_FAILURE
            is ThreatFeedStoreResult.Success -> result.value ?: return ThreatFeedRetentionResult.NOTHING_TO_DELETE
        }
        val deleteAt = safeAdd(snapshot.declaredExpiresAtMillis, policy.keepExpiredForMillis)
        return if (nowMillis >= deleteAt) erase() else ThreatFeedRetentionResult.RETAINED
    }

    private fun ThreatFeedSnapshot.snapshotMatches(feed: VerifiedThreatFeed): Boolean =
        highestAcceptedVersion == feed.version &&
            declaredExpiresAtMillis == feed.expiresAtMillis
}

data class ThreatFeedRetentionPolicy(
    /** Default is fourteen days; use zero to remove a feed immediately when it expires. */
    val keepExpiredForMillis: Long = DEFAULT_KEEP_EXPIRED_FOR_MILLIS,
) {
    init {
        require(keepExpiredForMillis in 0L..MAX_KEEP_EXPIRED_FOR_MILLIS) {
            "keepExpiredForMillis is outside the supported range."
        }
    }

    private companion object {
        const val DEFAULT_KEEP_EXPIRED_FOR_MILLIS = 14L * 24L * 60L * 60L * 1_000L
        const val MAX_KEEP_EXPIRED_FOR_MILLIS = 90L * 24L * 60L * 60L * 1_000L
    }
}

/** A no-network planner: only an integration layer may turn this into scheduled work. */
enum class ThreatFeedUpdateMode { MANUAL_ONLY, USER_ENABLED_BACKGROUND }

enum class ThreatFeedUpdateReason { NO_ACTIVE_FEED, EXPIRES_SOON, ROUTINE_REFRESH }

enum class ThreatFeedUpdateUrgency { NORMAL, HIGH }

data class ThreatFeedUpdatePlan(
    val dueAtMillis: Long,
    val reason: ThreatFeedUpdateReason,
    val urgency: ThreatFeedUpdateUrgency,
    val requireUnmeteredNetwork: Boolean,
)

data class ThreatFeedRefreshPolicy(
    val mode: ThreatFeedUpdateMode = ThreatFeedUpdateMode.MANUAL_ONLY,
    val refreshIntervalMillis: Long = DEFAULT_REFRESH_INTERVAL_MILLIS,
    val expiryLeadMillis: Long = DEFAULT_EXPIRY_LEAD_MILLIS,
    val minimumRetryIntervalMillis: Long = DEFAULT_MINIMUM_RETRY_INTERVAL_MILLIS,
    val requireUnmeteredNetwork: Boolean = true,
) {
    init {
        require(refreshIntervalMillis in MIN_REFRESH_INTERVAL_MILLIS..MAX_REFRESH_INTERVAL_MILLIS) {
            "refreshIntervalMillis is outside the supported range."
        }
        require(expiryLeadMillis in 0L..MAX_EXPIRY_LEAD_MILLIS) { "expiryLeadMillis is outside the supported range." }
        require(minimumRetryIntervalMillis in MIN_RETRY_INTERVAL_MILLIS..MAX_RETRY_INTERVAL_MILLIS) {
            "minimumRetryIntervalMillis is outside the supported range."
        }
    }

    private companion object {
        const val DEFAULT_REFRESH_INTERVAL_MILLIS = 24L * 60L * 60L * 1_000L
        const val DEFAULT_EXPIRY_LEAD_MILLIS = 48L * 60L * 60L * 1_000L
        const val DEFAULT_MINIMUM_RETRY_INTERVAL_MILLIS = 6L * 60L * 60L * 1_000L
        const val MIN_REFRESH_INTERVAL_MILLIS = 60L * 60L * 1_000L
        const val MAX_REFRESH_INTERVAL_MILLIS = 14L * 24L * 60L * 60L * 1_000L
        const val MAX_EXPIRY_LEAD_MILLIS = 14L * 24L * 60L * 60L * 1_000L
        const val MIN_RETRY_INTERVAL_MILLIS = 15L * 60L * 1_000L
        const val MAX_RETRY_INTERVAL_MILLIS = 7L * 24L * 60L * 60L * 1_000L
    }
}

/**
 * The app calls this to decide when a user-authorized WorkManager job should
 * run. This module has no HTTP client, endpoint or cloud dependency.
 */
class ThreatFeedUpdatePlanner(
    private val policy: ThreatFeedRefreshPolicy = ThreatFeedRefreshPolicy(),
) {
    fun nextPlan(
        active: ThreatFeedLoadResult.Active?,
        nowMillis: Long,
        lastAttemptAtMillis: Long? = null,
    ): ThreatFeedUpdatePlan? {
        if (policy.mode == ThreatFeedUpdateMode.MANUAL_ONLY) return null
        val candidate = when {
            active == null -> ThreatFeedUpdatePlan(
                dueAtMillis = nowMillis,
                reason = ThreatFeedUpdateReason.NO_ACTIVE_FEED,
                urgency = ThreatFeedUpdateUrgency.HIGH,
                requireUnmeteredNetwork = policy.requireUnmeteredNetwork,
            )
            active.feed.expiresAtMillis <= safeAdd(nowMillis, policy.expiryLeadMillis) -> ThreatFeedUpdatePlan(
                dueAtMillis = nowMillis,
                reason = ThreatFeedUpdateReason.EXPIRES_SOON,
                urgency = ThreatFeedUpdateUrgency.HIGH,
                requireUnmeteredNetwork = policy.requireUnmeteredNetwork,
            )
            else -> ThreatFeedUpdatePlan(
                dueAtMillis = minOf(
                    safeAdd(active.activatedAtMillis, policy.refreshIntervalMillis),
                    active.feed.expiresAtMillis - policy.expiryLeadMillis,
                ).coerceAtLeast(nowMillis),
                reason = ThreatFeedUpdateReason.ROUTINE_REFRESH,
                urgency = ThreatFeedUpdateUrgency.NORMAL,
                requireUnmeteredNetwork = policy.requireUnmeteredNetwork,
            )
        }
        val retryFloor = lastAttemptAtMillis?.let { safeAdd(it, policy.minimumRetryIntervalMillis) } ?: Long.MIN_VALUE
        return candidate.copy(dueAtMillis = max(candidate.dueAtMillis, retryFloor))
    }
}

/**
 * App-owned adapter boundary for WorkManager (or an equivalent scheduler).
 * Implementations must create unique replaceable work and must never schedule
 * a network request unless the user chose USER_ENABLED_BACKGROUND.
 */
interface ThreatFeedUpdateScheduler {
    fun scheduleUnique(plan: ThreatFeedUpdatePlan)

    fun cancelUnique()
}
