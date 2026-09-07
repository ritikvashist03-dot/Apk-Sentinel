package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.nio.charset.StandardCharsets

/** Non-sensitive proof of the most recent user-confirmed local erase. */
internal data class PrivacyDeletionReceipt(
    val completedAtMillis: Long,
    val grantsReleased: Int,
    val networkEventsCleared: Int,
    val firewallRulesCleared: Int,
    val firewallPolicyConfirmed: Boolean,
    val threatDataConfirmed: Boolean,
    val installedHistoryConfirmed: Boolean,
    val networkHistoryConfirmed: Boolean,
    val postureHistoryConfirmed: Boolean,
    val privateFilesConfirmed: Boolean,
    val preferencesConfirmed: Boolean,
    val documentGrantsConfirmed: Boolean,
    val monitorStopped: Boolean,
)

internal enum class PrivacyReceiptReadState { ABSENT, AVAILABLE, UNAVAILABLE, CORRUPT }

internal data class PrivacyReceiptReadResult(
    val state: PrivacyReceiptReadState,
    val receipt: PrivacyDeletionReceipt? = null,
)

/** Strict typed codec. It never stores file names, package names, endpoints, or user content. */
internal object PrivacyDeletionReceiptCodec {
    private const val VERSION = "v2"
    const val MAX_BYTES = 512
    private const val FIELD_COUNT = 13
    private const val MAX_COUNT = 1_000_000
    private const val MAX_FUTURE_SKEW_MILLIS = 5 * 60 * 1000L

    fun encode(receipt: PrivacyDeletionReceipt): ByteArray? {
        if (!valid(receipt, Long.MAX_VALUE)) return null
        return listOf(
            VERSION,
            receipt.completedAtMillis.toString(),
            receipt.grantsReleased.toString(),
            receipt.networkEventsCleared.toString(),
            receipt.firewallRulesCleared.toString(),
            receipt.firewallPolicyConfirmed.asDigit(),
            receipt.threatDataConfirmed.asDigit(),
            receipt.installedHistoryConfirmed.asDigit(),
            receipt.networkHistoryConfirmed.asDigit(),
            receipt.postureHistoryConfirmed.asDigit(),
            receipt.privateFilesConfirmed.asDigit(),
            receipt.preferencesConfirmed.asDigit(),
            receipt.documentGrantsConfirmed.asDigit(),
            receipt.monitorStopped.asDigit(),
        ).joinToString("|").toByteArray(StandardCharsets.US_ASCII).takeIf { it.size <= MAX_BYTES }
    }

    fun decode(payload: ByteArray, nowMillis: Long): PrivacyDeletionReceipt? {
        if (payload.isEmpty() || payload.size > MAX_BYTES || nowMillis <= 0L) return null
        val text = runCatching { String(payload, StandardCharsets.US_ASCII) }.getOrNull() ?: return null
        if (text.any { it.code !in 0x20..0x7e }) return null
        val fields = text.split('|')
        if (fields.size != FIELD_COUNT + 1 || fields[0] != VERSION) return null
        val receipt = PrivacyDeletionReceipt(
            completedAtMillis = fields[1].toLongOrNull() ?: return null,
            grantsReleased = fields[2].boundedCount() ?: return null,
            networkEventsCleared = fields[3].boundedCount() ?: return null,
            firewallRulesCleared = fields[4].boundedCount() ?: return null,
            firewallPolicyConfirmed = fields[5].strictBoolean() ?: return null,
            threatDataConfirmed = fields[6].strictBoolean() ?: return null,
            installedHistoryConfirmed = fields[7].strictBoolean() ?: return null,
            networkHistoryConfirmed = fields[8].strictBoolean() ?: return null,
            postureHistoryConfirmed = fields[9].strictBoolean() ?: return null,
            privateFilesConfirmed = fields[10].strictBoolean() ?: return null,
            preferencesConfirmed = fields[11].strictBoolean() ?: return null,
            documentGrantsConfirmed = fields[12].strictBoolean() ?: return null,
            monitorStopped = fields[13].strictBoolean() ?: return null,
        )
        return receipt.takeIf { valid(it, nowMillis + MAX_FUTURE_SKEW_MILLIS) }
    }

    private fun valid(receipt: PrivacyDeletionReceipt, maximumTimestamp: Long): Boolean =
        receipt.completedAtMillis in 1..maximumTimestamp &&
            listOf(receipt.grantsReleased, receipt.networkEventsCleared, receipt.firewallRulesCleared)
                .all { it in 0..MAX_COUNT }

    private fun Boolean.asDigit(): String = if (this) "1" else "0"
    private fun String.strictBoolean(): Boolean? = when (this) { "1" -> true; "0" -> false; else -> null }
    private fun String.boundedCount(): Int? = toIntOrNull()?.takeIf { it in 0..MAX_COUNT }
}

internal class PrivacyDeletionReceiptController(
    private val storage: EncryptedStorage,
) {
    /** Call from a background dispatcher. */
    fun read(nowMillis: Long = System.currentTimeMillis()): PrivacyReceiptReadResult {
        return when (val result = storage.read(KEY)) {
            is SecureStorageResult.Failure -> PrivacyReceiptReadResult(PrivacyReceiptReadState.UNAVAILABLE)
            is SecureStorageResult.Success -> {
                val payload = result.value ?: return PrivacyReceiptReadResult(PrivacyReceiptReadState.ABSENT)
                try {
                    val decoded = PrivacyDeletionReceiptCodec.decode(payload, nowMillis)
                    if (decoded == null) PrivacyReceiptReadResult(PrivacyReceiptReadState.CORRUPT)
                    else PrivacyReceiptReadResult(PrivacyReceiptReadState.AVAILABLE, decoded)
                } finally {
                    payload.fill(0)
                }
            }
        }
    }

    /** Call from a background dispatcher. */
    fun save(receipt: PrivacyDeletionReceipt): Boolean {
        val encoded = PrivacyDeletionReceiptCodec.encode(receipt) ?: return false
        return try {
            storage.write(KEY, encoded) is SecureStorageResult.Success
        } finally {
            encoded.fill(0)
        }
    }

    companion object {
        private val KEY = SecureStorageKey("privacy.erase.receipt.v1")

        fun android(context: Context): PrivacyDeletionReceiptController = PrivacyDeletionReceiptController(
            AndroidKeystoreEncryptedStorage(
                preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE),
                keyAlias = "apk_sentinel.privacy_erase_receipt.v1",
                namespace = "apk_sentinel_privacy_erase_receipt",
            ),
        )

        internal const val PREFERENCES = "privacy_deletion_receipt"
    }
}
