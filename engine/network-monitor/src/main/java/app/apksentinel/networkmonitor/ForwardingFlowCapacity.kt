package app.apksentinel.networkmonitor

/**
 * Process-local admission gate shared by TCP and UDP flow maps. It keeps a
 * compromised or noisy app from causing unbounded socket, buffer, or thread
 * growth. Each successful acquisition must be paired with [release] exactly
 * once when the associated flow closes.
 */
internal class ForwardingFlowCapacity(
    private val maximumFlows: Int,
) {
    private var activeFlows = 0

    init {
        require(maximumFlows in 1..4_096) { "Maximum forwarding flows must be between 1 and 4096." }
    }

    @Synchronized
    fun tryAcquire(): Boolean {
        if (activeFlows >= maximumFlows) return false
        activeFlows += 1
        return true
    }

    @Synchronized
    fun release() {
        if (activeFlows > 0) activeFlows -= 1
    }

    @Synchronized
    fun activeCount(): Int = activeFlows
}
