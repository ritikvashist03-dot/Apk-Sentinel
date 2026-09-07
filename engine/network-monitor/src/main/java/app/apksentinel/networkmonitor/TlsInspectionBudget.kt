package app.apksentinel.networkmonitor

/**
 * Atomic memory-only byte/time budget shared by all TLS flows in one route
 * session. Bytes are counted when ciphertext is presented in either direction.
 * Duration uses monotonic time; wall-clock time is intentionally not used for
 * an active session because user/device clock changes must not extend it.
 */
class TlsInspectionBudget(
    private val maximumSessionBytes: Int,
    private val maximumBytesPerFlow: Int,
    private val maximumDurationMillis: Long,
    private val nowNanos: () -> Long = { System.nanoTime() },
) {
    private val lock = Any()
    private val flowBytes = HashMap<Long, Int>()
    private var nextFlowId = 1L
    private var sessionBytes = 0
    private var terminalFailure: TlsInspectionRouteFailure? = null
    private val maximumDurationNanos = millisToNanosSaturated(maximumDurationMillis)
    private val startedAtNanos: Long = nowNanos()

    init {
        require(maximumSessionBytes > 0)
        require(maximumBytesPerFlow > 0 && maximumBytesPerFlow <= maximumSessionBytes)
        require(maximumDurationMillis > 0L)
    }

    fun openFlow(): TlsInspectionBudgetOpenResult = synchronized(lock) {
        val failure = terminalFailure ?: expiryFailureLocked(nowNanos())
        if (failure != null) {
            if (failure == TlsInspectionRouteFailure.HANDSHAKE_TIMEOUT) terminalFailure = failure
            return@synchronized TlsInspectionBudgetOpenResult.Rejected(failure)
        }
        val id = nextAvailableFlowIdLocked()
        flowBytes[id] = 0
        TlsInspectionBudgetOpenResult.Accepted(id)
    }

    /** Returns null when admitted; otherwise the terminal reason for this operation. */
    fun admit(flowId: Long, bytes: Int): TlsInspectionRouteFailure? = synchronized(lock) {
        require(bytes >= 0)
        val existing = flowBytes[flowId] ?: return@synchronized TlsInspectionRouteFailure.CLOSED
        terminalFailure ?: expiryFailureLocked(nowNanos())?.also { terminalFailure = it } ?: run {
            // Subtraction avoids Int/Long addition overflow and admits zero-byte
            // handshake/close drains while still enforcing expiry and stop.
            val flowRemaining = maximumBytesPerFlow - existing
            val sessionRemaining = maximumSessionBytes - sessionBytes
            when {
                bytes > flowRemaining || bytes > sessionRemaining -> {
                    if (bytes > sessionRemaining) terminalFailure = TlsInspectionRouteFailure.BUFFER_LIMIT
                    TlsInspectionRouteFailure.BUFFER_LIMIT
                }
                else -> {
                    flowBytes[flowId] = existing + bytes
                    sessionBytes += bytes
                    null
                }
            }
        }
    }

    fun closeFlow(flowId: Long) = synchronized(lock) { flowBytes.remove(flowId) }

    fun stop() = synchronized(lock) { terminalFailure = TlsInspectionRouteFailure.CLOSED }

    fun snapshot(): TlsInspectionBudgetSnapshot = synchronized(lock) {
        TlsInspectionBudgetSnapshot(sessionBytes, flowBytes.toMap(), terminalFailure)
    }

    private fun expiryFailureLocked(now: Long): TlsInspectionRouteFailure? =
        if (now >= startedAtNanos && now - startedAtNanos >= maximumDurationNanos) {
            TlsInspectionRouteFailure.HANDSHAKE_TIMEOUT
        } else {
            null
        }

    private fun nextAvailableFlowIdLocked(): Long {
        repeat(flowBytes.size + 1) {
            val candidate = nextFlowId
            nextFlowId = if (nextFlowId == Long.MAX_VALUE) 1L else nextFlowId + 1L
            if (!flowBytes.containsKey(candidate)) return candidate
        }
        error("The bounded TLS flow registry is exhausted.")
    }

}

private fun millisToNanosSaturated(millis: Long): Long = when {
    millis <= 0L -> 0L
    millis > Long.MAX_VALUE / 1_000_000L -> Long.MAX_VALUE
    else -> millis * 1_000_000L
}

sealed interface TlsInspectionBudgetOpenResult {
    data class Accepted(val flowId: Long) : TlsInspectionBudgetOpenResult
    data class Rejected(val reason: TlsInspectionRouteFailure) : TlsInspectionBudgetOpenResult
}

data class TlsInspectionBudgetSnapshot(
    val sessionBytes: Int,
    val flowBytes: Map<Long, Int>,
    val terminalFailure: TlsInspectionRouteFailure?,
)
