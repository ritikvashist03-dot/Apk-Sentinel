package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.nio.charset.StandardCharsets

/**
 * A deliberately small, local record of completed user actions.
 *
 * This is not an audit log. It must never receive inputs, package names, IP addresses, URLs,
 * report text, or a description supplied by another feature. Categories and result codes are
 * closed enums so a caller cannot accidentally turn this into a sensitive history store.
 */
internal enum class SafeActivityCategory { APK_CHECK, LINK_CHECK, DEVICE_CHECK }
internal enum class SafeActivityOutcome { COMPLETED, ATTENTION, UNAVAILABLE, CANCELLED }
internal enum class SafeActivityCode { NONE, LOCAL_CHECK, LIMITED_EVIDENCE, USER_CANCELLED, CAPABILITY_UNAVAILABLE }

internal data class SafeActivityRecord(
    val category: SafeActivityCategory,
    val outcome: SafeActivityOutcome,
    val atMillis: Long,
    val code: SafeActivityCode = SafeActivityCode.NONE,
)

internal enum class SafeActivityReadState { READY, UNAVAILABLE, CORRUPT, CLOCK_UNTRUSTWORTHY }
internal data class SafeActivityReadResult(
    val state: SafeActivityReadState,
    val records: List<SafeActivityRecord> = emptyList(),
)

/** Strict, bounded versioned plaintext framing; the controller encrypts it before storage. */
internal object SafeActivityCodec {
    private const val VERSION = "v1"
    const val MAX_RECORDS = 120
    const val MAX_BYTES = 16 * 1024
    internal const val MAX_AGE_MILLIS = 90L * 24 * 60 * 60 * 1_000L
    internal const val MAX_FUTURE_SKEW_MILLIS = 5 * 60 * 1_000L

    fun encode(records: List<SafeActivityRecord>): ByteArray? {
        if (records.size > MAX_RECORDS || records.any { !valid(it, Long.MAX_VALUE) }) return null
        return buildString {
            append(VERSION).append('\n')
            records.forEach { record ->
                append(record.atMillis).append('|')
                    .append(record.category.name).append('|')
                    .append(record.outcome.name).append('|')
                    .append(record.code.name).append('\n')
            }
        }.toByteArray(StandardCharsets.US_ASCII).takeIf { it.size <= MAX_BYTES }
    }

    fun decode(bytes: ByteArray, nowMillis: Long): List<SafeActivityRecord>? {
        if (bytes.isEmpty() || bytes.size > MAX_BYTES || nowMillis !in 1L..(Long.MAX_VALUE - MAX_FUTURE_SKEW_MILLIS)) return null
        val text = runCatching { String(bytes, StandardCharsets.US_ASCII) }.getOrNull() ?: return null
        // The record separator is '\n' (0x0A), which is deliberately outside the printable
        // range this check enforces. Excluding it rejected every payload encode() ever
        // produced, so decode always returned null: the activity log could never load a
        // record, and append refused to add one because it requires a READY read first.
        if (text.any { it.code !in 0x20..0x7e && it != '\n' }) return null
        val lines = text.split('\n')
        if (lines.firstOrNull() != VERSION || lines.size !in 2..(MAX_RECORDS + 2) || lines.last().isNotEmpty()) return null
        val records = lines.drop(1).dropLast(1).map { line ->
            val fields = line.split('|')
            if (fields.size != 4) return null
            val record = SafeActivityRecord(
                category = runCatching { SafeActivityCategory.valueOf(fields[1]) }.getOrNull() ?: return null,
                outcome = runCatching { SafeActivityOutcome.valueOf(fields[2]) }.getOrNull() ?: return null,
                atMillis = fields[0].toLongOrNull() ?: return null,
                code = runCatching { SafeActivityCode.valueOf(fields[3]) }.getOrNull() ?: return null,
            )
            if (!valid(record, nowMillis + MAX_FUTURE_SKEW_MILLIS)) return null
            record
        }
        return records.filter { nowMillis - it.atMillis in 0..MAX_AGE_MILLIS }
    }

    private fun valid(record: SafeActivityRecord, maximumTimestamp: Long): Boolean =
        record.atMillis in 1..maximumTimestamp
}

internal class SafeActivityStoreController(
    private val storage: EncryptedStorage,
    private val deleteEncryptionKey: () -> Boolean = { true },
) {
    /** Call from a worker dispatcher. Corrupt or unavailable data is never replaced implicitly. */
    fun read(nowMillis: Long = System.currentTimeMillis()): SafeActivityReadResult {
        if (nowMillis <= 0L) return SafeActivityReadResult(SafeActivityReadState.CLOCK_UNTRUSTWORTHY)
        return when (val response = storage.read(KEY)) {
            is SecureStorageResult.Failure -> SafeActivityReadResult(SafeActivityReadState.UNAVAILABLE)
            is SecureStorageResult.Success -> {
                val bytes = response.value ?: return SafeActivityReadResult(SafeActivityReadState.READY)
                try {
                    SafeActivityCodec.decode(bytes, nowMillis)?.let { SafeActivityReadResult(SafeActivityReadState.READY, it) }
                        ?: SafeActivityReadResult(SafeActivityReadState.CORRUPT)
                } finally {
                    bytes.fill(0)
                }
            }
        }
    }

    /** Future feature integrations may add only a closed typed record after a completed action. */
    fun append(record: SafeActivityRecord, nowMillis: Long = System.currentTimeMillis()): Boolean {
        if (nowMillis !in 1L..(Long.MAX_VALUE - SafeActivityCodec.MAX_FUTURE_SKEW_MILLIS)) return false
        val earliestAllowed = (nowMillis - SafeActivityCodec.MAX_AGE_MILLIS).coerceAtLeast(1L)
        val latestAllowed = nowMillis + SafeActivityCodec.MAX_FUTURE_SKEW_MILLIS
        if (record.atMillis !in earliestAllowed..latestAllowed) return false
        val current = read(nowMillis)
        if (current.state != SafeActivityReadState.READY) return false
        val updated = (current.records + record).sortedByDescending { it.atMillis }.take(SafeActivityCodec.MAX_RECORDS)
        val encoded = SafeActivityCodec.encode(updated) ?: return false
        return try {
            // Give storage its own ownership boundary; then erase this controller buffer.
            storage.write(KEY, encoded.copyOf()) is SecureStorageResult.Success
        } finally {
            encoded.fill(0)
        }
    }

    /** Privacy erase removes ciphertext and the dedicated Android Keystore key. */
    fun erase(): Boolean = (storage.remove(KEY) is SecureStorageResult.Success) &&
        runCatching { deleteEncryptionKey() }.getOrDefault(false)

    companion object {
        private val KEY = SecureStorageKey("activity.safe.v1")
        fun android(context: Context): SafeActivityStoreController {
            val encrypted = AndroidKeystoreEncryptedStorage(
                preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE),
                keyAlias = "apk_sentinel.safe_activity.v1",
                namespace = "apk_sentinel_safe_activity",
            )
            return SafeActivityStoreController(encrypted, encrypted::deleteEncryptionKey)
        }

        internal const val PREFERENCES = "safe_activity"
    }
}
