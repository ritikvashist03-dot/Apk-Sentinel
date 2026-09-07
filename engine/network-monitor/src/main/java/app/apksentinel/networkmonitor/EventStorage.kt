package app.apksentinel.networkmonitor

import java.util.ArrayDeque
import java.util.LinkedHashMap

/**
 * Storage is intentionally an interface so a host app can add reviewed,
 * encrypted persistence later. The default implementation is process-local and
 * bounded; it never writes packets or payloads to disk. Eviction is strictly
 * count-based: there is no time- or age-based retention window, and process
 * death clears the default store. Implementations passed to
 * [NetworkMonitorRuntime] must make append, snapshot, and clear safe for
 * concurrent UI and forwarding calls.
 */
interface NetworkEventStore {
    val capacity: Int
    val droppedEventCount: Long

    fun append(event: NetworkEvent): EventStoreAppendResult

    /** Oldest-to-newest, bounded to [limit] most recent entries; this is not a time-based history. */
    fun snapshot(limit: Int = capacity): List<NetworkEvent>

    fun clear(): Int
}

data class EventStoreAppendResult(
    val retainedCount: Int,
    val evictedCount: Int,
    val droppedEventCount: Long,
)

class BoundedInMemoryNetworkEventStore(
    override val capacity: Int = DEFAULT_EVENT_CAPACITY,
) : NetworkEventStore {
    private val lock = Any()
    private val events = ArrayDeque<NetworkEvent>(capacity)
    private var dropped: Long = 0L

    init {
        require(capacity > 0) { "Event capacity must be positive." }
    }

    override val droppedEventCount: Long
        get() = synchronized(lock) { dropped }

    override fun append(event: NetworkEvent): EventStoreAppendResult = synchronized(lock) {
        var evicted = 0
        if (events.size == capacity) {
            events.removeFirst()
            evicted = 1
            dropped += 1L
        }
        events.addLast(event)
        EventStoreAppendResult(
            retainedCount = events.size,
            evictedCount = evicted,
            droppedEventCount = dropped,
        )
    }

    override fun snapshot(limit: Int): List<NetworkEvent> = synchronized(lock) {
        require(limit >= 0) { "Snapshot limit must not be negative." }
        if (limit == 0) return@synchronized emptyList()
        val result = events.toList()
        if (result.size <= limit) result else result.takeLast(limit)
    }

    override fun clear(): Int = synchronized(lock) {
        val count = events.size
        events.clear()
        count
    }

    private companion object {
        const val DEFAULT_EVENT_CAPACITY = 512
    }
}

/**
 * Aggregates a bounded number of metadata-only flows. A flow eviction is
 * explicit so callers can present a truthful "older flows not retained" state.
 */
class BoundedFlowRegistry(
    private val capacity: Int = DEFAULT_FLOW_CAPACITY,
) {
    private val lock = Any()
    private val flows = LinkedHashMap<NetworkFlowKey, NetworkFlow>()
    private val recency = ArrayDeque<NetworkFlowKey>(capacity)
    private var dropped: Long = 0L

    init {
        require(capacity > 0) { "Flow capacity must be positive." }
    }

    fun observe(
        metadata: PacketMetadata,
        attribution: AppAttribution,
        direction: PacketDirection,
        atMillis: Long,
    ): FlowObservation = synchronized(lock) {
        val key = metadata.toFlowKey(direction)
        val existing = flows[key]
        if (existing != null) {
            val updated = existing.observe(metadata, attribution, atMillis)
            flows[key] = updated
            recency.remove(key)
            recency.addLast(key)
            return@synchronized FlowObservation(flow = updated)
        }

        var evicted: NetworkFlow? = null
        if (flows.size == capacity) {
            val oldest = recency.removeFirst()
            evicted = flows.remove(oldest)
            dropped += 1L
        }
        val flow = NetworkFlow.fromPacket(metadata, attribution, direction, atMillis)
        flows[key] = flow
        recency.addLast(key)
        FlowObservation(flow = flow, evictedFlow = evicted, droppedFlowCount = dropped)
    }

    fun snapshot(): List<NetworkFlow> = synchronized(lock) {
        recency.mapNotNull(flows::get)
    }

    /** Bounded, immutable state for a local UI or export coordinator. */
    fun snapshotState(): FlowRegistrySnapshot = synchronized(lock) {
        FlowRegistrySnapshot(
            flows = recency.mapNotNull(flows::get),
            droppedFlowCount = dropped,
            capacity = capacity,
        )
    }

    fun clear(): Int = synchronized(lock) {
        val size = flows.size
        flows.clear()
        recency.clear()
        size
    }

    val droppedFlowCount: Long
        get() = synchronized(lock) { dropped }

    private companion object {
        const val DEFAULT_FLOW_CAPACITY = 1_024
    }
}

/** A truthful snapshot: [droppedFlowCount] reports capacity eviction, not a time window. */
data class FlowRegistrySnapshot(
    val flows: List<NetworkFlow> = emptyList(),
    val droppedFlowCount: Long = 0L,
    val capacity: Int = 0,
) {
    init {
        require(droppedFlowCount >= 0L) { "Dropped flow count must not be negative." }
        require(capacity >= 0) { "Flow capacity must not be negative." }
        require(flows.size <= capacity || capacity == 0) { "Flow snapshot exceeds its declared capacity." }
    }
}

data class FlowObservation(
    val flow: NetworkFlow,
    val evictedFlow: NetworkFlow? = null,
    val droppedFlowCount: Long = 0L,
)
