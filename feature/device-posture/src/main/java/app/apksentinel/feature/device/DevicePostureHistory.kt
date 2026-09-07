package app.apksentinel.feature.device

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.nio.charset.StandardCharsets

/** Deliberately excludes setting values, package names, and explanatory text. */
data class PostureObservation(
    val checkId: String,
    val state: CheckState,
    val evidenceMode: PostureEvidenceMode,
    val observedAtMillis: Long,
)

enum class PostureComparison { CHANGED, UNCHANGED, UNVERIFIABLE }
enum class PostureHistoryFailure { NONE, CLOCK_UNTRUSTWORTHY, READ_UNAVAILABLE, CORRUPT, WRITE_UNAVAILABLE }

data class PostureHistoryResult(
    val comparisons: List<PostureComparison>,
    val failure: PostureHistoryFailure,
) {
    val changedCount get() = comparisons.count { it == PostureComparison.CHANGED }
    val unchangedCount get() = comparisons.count { it == PostureComparison.UNCHANGED }
    val unverifiableCount get() = comparisons.count { it == PostureComparison.UNVERIFIABLE }
}

/** Strict, versioned plaintext codec; callers encrypt its output before persistence. */
internal object PostureHistoryCodec {
    const val MAX_RECORDS = 180
    const val MAX_BYTES = 24 * 1024
    const val MAX_AGE_MILLIS = 180L * 24 * 60 * 60 * 1000
    private const val VERSION = "v1"
    private val idPattern = Regex("^[a-z][a-z0-9_]{0,63}$")

    fun encode(records: List<PostureObservation>): ByteArray? {
        if (records.size > MAX_RECORDS || records.any { !isValid(it) }) return null
        val text = buildString {
            append(VERSION).append('\n')
            records.forEach { append(it.observedAtMillis).append('|').append(it.checkId).append('|').append(it.state.name).append('|').append(it.evidenceMode.name).append('\n') }
        }
        return text.toByteArray(StandardCharsets.UTF_8).takeIf { it.size <= MAX_BYTES }
    }

    fun decode(bytes: ByteArray, nowMillis: Long): List<PostureObservation>? {
        if (bytes.size > MAX_BYTES || nowMillis <= 0L) return null
        val lines = runCatching { String(bytes, StandardCharsets.UTF_8).split('\n') }.getOrNull() ?: return null
        if (lines.firstOrNull() != VERSION || lines.size > MAX_RECORDS + 2) return null
        val records = lines.drop(1).filter { it.isNotBlank() }.map { line ->
            val p = line.split('|')
            if (p.size != 4) return null
            val time = p[0].toLongOrNull() ?: return null
            val record = runCatching { PostureObservation(p[1], CheckState.valueOf(p[2]), PostureEvidenceMode.valueOf(p[3]), time) }.getOrNull() ?: return null
            if (!isValid(record) || time > nowMillis + MAX_FUTURE_SKEW_MILLIS) return null
            record
        }
        return records.filter { nowMillis - it.observedAtMillis in 0..MAX_AGE_MILLIS }
    }

    private fun isValid(record: PostureObservation): Boolean = idPattern.matches(record.checkId) && record.observedAtMillis > 0L
    private const val MAX_FUTURE_SKEW_MILLIS = 5 * 60 * 1000L
}

class DevicePostureHistoryController(
    private val storage: EncryptedStorage,
    private val deleteEncryptionKey: () -> Boolean = { true },
) {
    /** Call from a background dispatcher. */
    fun compareAndRecord(snapshot: DevicePostureSnapshot, nowMillis: Long = snapshot.generatedAtMillis): PostureHistoryResult {
        if (nowMillis <= 0L || snapshot.generatedAtMillis <= 0L || snapshot.generatedAtMillis > nowMillis + 5 * 60 * 1000L) {
            return PostureHistoryResult(List(snapshot.checks.size) { PostureComparison.UNVERIFIABLE }, PostureHistoryFailure.CLOCK_UNTRUSTWORTHY)
        }
        val payload = when (val read = storage.read(KEY)) {
            is SecureStorageResult.Success -> read.value
            is SecureStorageResult.Failure -> return PostureHistoryResult(List(snapshot.checks.size) { PostureComparison.UNVERIFIABLE }, PostureHistoryFailure.READ_UNAVAILABLE)
        }
        // A successfully decrypted malformed value is a corruption outcome, never a best-effort interpretation.
        val decoded = payload?.let { PostureHistoryCodec.decode(it, nowMillis) }
        if (payload != null && decoded == null) {
            return PostureHistoryResult(List(snapshot.checks.size) { PostureComparison.UNVERIFIABLE }, PostureHistoryFailure.CORRUPT)
        }
        val prior = decoded.orEmpty()
        val current = snapshot.checks.map { PostureObservation(it.id, it.state, it.evidenceMode, snapshot.generatedAtMillis) }
        val comparisons = current.map { item -> comparison(item, prior.filter { it.checkId == item.checkId }.maxByOrNull { it.observedAtMillis }) }
        val retained = (prior + current).sortedByDescending { it.observedAtMillis }.take(PostureHistoryCodec.MAX_RECORDS)
        val encoded = PostureHistoryCodec.encode(retained) ?: return PostureHistoryResult(comparisons, PostureHistoryFailure.CORRUPT)
        return when (storage.write(KEY, encoded)) {
            is SecureStorageResult.Success -> PostureHistoryResult(comparisons, PostureHistoryFailure.NONE)
            is SecureStorageResult.Failure -> PostureHistoryResult(List(current.size) { PostureComparison.UNVERIFIABLE }, PostureHistoryFailure.WRITE_UNAVAILABLE)
        }
    }

    /** Call from a background dispatcher; used by the root Privacy erase flow. */
    fun erase(): Boolean {
        val removed = storage.remove(KEY) is SecureStorageResult.Success
        val keyDeleted = runCatching { deleteEncryptionKey() }.getOrDefault(false)
        return removed && keyDeleted
    }

    private fun comparison(current: PostureObservation, previous: PostureObservation?): PostureComparison {
        if (previous == null || current.state == CheckState.UNKNOWN || previous.state == CheckState.UNKNOWN ||
            current.evidenceMode != PostureEvidenceMode.AUTOMATICALLY_OBSERVED ||
            previous.evidenceMode != PostureEvidenceMode.AUTOMATICALLY_OBSERVED) return PostureComparison.UNVERIFIABLE
        return if (current.state == previous.state && current.evidenceMode == previous.evidenceMode) PostureComparison.UNCHANGED else PostureComparison.CHANGED
    }

    companion object {
        private val KEY = SecureStorageKey("posture.history.v1")
        fun android(context: Context): DevicePostureHistoryController {
            val encryptedStorage = AndroidKeystoreEncryptedStorage(
                context.applicationContext.getSharedPreferences("posture_observation_history", Context.MODE_PRIVATE),
                keyAlias = "apk_sentinel.posture_history.v1",
                namespace = "apk_sentinel_posture_history",
            )
            return DevicePostureHistoryController(encryptedStorage, encryptedStorage::deleteEncryptionKey)
        }
    }
}
