package app.apksentinel.core.security

import app.apksentinel.core.model.ConsentPurpose
import app.apksentinel.core.model.ConsentReceipt
import app.apksentinel.core.model.ConsentReceiptId
import app.apksentinel.core.model.ConsentScope

/**
 * Append-only, purpose-specific consent history. A receipt for one purpose
 * never grants a different purpose, even when the scopes have similar names.
 */
interface ConsentLedger {
    fun record(receipt: ConsentReceipt): ConsentRecordResult

    fun latest(purpose: ConsentPurpose): ConsentReceipt?

    fun history(purpose: ConsentPurpose): List<ConsentReceipt>

    fun isGranted(
        purpose: ConsentPurpose,
        requiredScopes: Set<ConsentScope>,
        atEpochMillis: Long,
    ): Boolean
}

sealed interface ConsentRecordResult {
    data class Recorded(val receiptId: ConsentReceiptId) : ConsentRecordResult

    data class Rejected(val reason: ConsentRecordRejection) : ConsentRecordResult
}

enum class ConsentRecordRejection {
    DUPLICATE_RECEIPT_ID,
    NON_MONOTONIC_PURPOSE_TIMESTAMP,
}

/**
 * Thread-safe in-memory implementation for composition and tests. Persisted
 * implementations should preserve the same append-only and timestamp rules.
 */
class InMemoryConsentLedger(
    initialReceipts: Iterable<ConsentReceipt> = emptyList(),
) : ConsentLedger {
    private val lock = Any()
    private val receiptsById = LinkedHashMap<ConsentReceiptId, ConsentReceipt>()

    init {
        initialReceipts.forEach { receipt ->
            check(record(receipt) is ConsentRecordResult.Recorded) {
                "Initial receipts must be unique and monotonic for each purpose."
            }
        }
    }

    override fun record(receipt: ConsentReceipt): ConsentRecordResult = synchronized(lock) {
        if (receiptsById.containsKey(receipt.id)) {
            return@synchronized ConsentRecordResult.Rejected(
                ConsentRecordRejection.DUPLICATE_RECEIPT_ID,
            )
        }

        val previous = latestLocked(receipt.purpose)
        if (previous != null && receipt.decidedAtEpochMillis <= previous.decidedAtEpochMillis) {
            return@synchronized ConsentRecordResult.Rejected(
                ConsentRecordRejection.NON_MONOTONIC_PURPOSE_TIMESTAMP,
            )
        }

        receiptsById[receipt.id] = receipt
        ConsentRecordResult.Recorded(receipt.id)
    }

    override fun latest(purpose: ConsentPurpose): ConsentReceipt? = synchronized(lock) {
        latestLocked(purpose)
    }

    override fun history(purpose: ConsentPurpose): List<ConsentReceipt> = synchronized(lock) {
        receiptsById.values
            .asSequence()
            .filter { it.purpose == purpose }
            .sortedBy { it.decidedAtEpochMillis }
            .toList()
    }

    override fun isGranted(
        purpose: ConsentPurpose,
        requiredScopes: Set<ConsentScope>,
        atEpochMillis: Long,
    ): Boolean = synchronized(lock) {
        require(atEpochMillis >= 0) { "atEpochMillis cannot be negative." }
        require(requiredScopes.isNotEmpty()) { "At least one required scope is required." }

        val receipt = latestLocked(purpose) ?: return@synchronized false
        receipt.isGrantedAt(atEpochMillis) && receipt.scopes.containsAll(requiredScopes)
    }

    private fun latestLocked(purpose: ConsentPurpose): ConsentReceipt? =
        receiptsById.values
            .asSequence()
            .filter { it.purpose == purpose }
            .maxByOrNull { it.decidedAtEpochMillis }
}
