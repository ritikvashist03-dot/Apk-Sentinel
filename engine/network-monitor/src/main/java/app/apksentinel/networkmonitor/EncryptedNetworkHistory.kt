package app.apksentinel.networkmonitor

import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageFailure
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Explicit retention policy. Persistence is still inactive until a host composes a controller. */
enum class DurableHistoryRetentionPolicy(val retentionMillis: Long?) {
    SESSION_ONLY(null),
    ONE_DAY(24L * 60L * 60L * 1_000L),
    SEVEN_DAYS(7L * 24L * 60L * 60L * 1_000L),
    THIRTY_DAYS(30L * 24L * 60L * 60L * 1_000L),
}

data class DurableHistoryLimits(
    val maximumRecords: Int = 4_096,
    val maximumPlaintextBytes: Int = 512 * 1_024,
    val maximumRecordBytes: Int = 256,
    val maximumIngressRecords: Int = 512,
) {
    init {
        require(maximumRecords in 1..16_384) { "History record limit is outside the supported range." }
        require(maximumPlaintextBytes in 1_024..1_048_576) { "History byte limit is outside the supported range." }
        require(maximumRecordBytes in 32..4_096) { "History record byte limit is outside the supported range." }
        require(maximumIngressRecords in 1..4_096) { "History ingress limit is outside the supported range." }
    }
}

enum class DurableHistoryFailure {
    STORAGE_READ_FAILED,
    DECRYPTION_FAILED,
    CORRUPT_OR_UNSUPPORTED,
    STORAGE_WRITE_FAILED,
    CLOCK_INVALID,
    ERASE_CIPHERTEXT_FAILED,
    ERASE_KEY_FAILED,
    ERASE_UNAVAILABLE,
}

enum class DurableHistoryReadState {
    NOT_LOADED,
    SESSION_ONLY,
    READY,
    FAILED,
    ERASING,
    ERASED,
}

/** Safe UI state: no exception text, ciphertext, raw packet, endpoint, or DNS-name fields. */
data class DurableHistorySnapshot(
    val state: DurableHistoryReadState,
    val policy: DurableHistoryRetentionPolicy,
    val records: List<DurableHistoryRecord> = emptyList(),
    val retainedPlaintextBytes: Int = 0,
    val droppedIngressRecords: Long = 0L,
    val droppedByLimitRecords: Long = 0L,
    val failure: DurableHistoryFailure? = null,
) {
    init {
        require(retainedPlaintextBytes >= 0) { "Retained history bytes must not be negative." }
        require(droppedIngressRecords >= 0L && droppedByLimitRecords >= 0L) { "Dropped counts must not be negative." }
    }
}

/** Dedicated key destruction hook. The Android composition supplies Android Keystore deletion. */
fun interface DurableHistoryKeyEraser {
    fun eraseKey(): Boolean
}

/**
 * Metadata-only records. Deliberately omitted: session/flow/rule IDs,
 * addresses, ports, package names/uids, DNS names, exception/detail prose,
 * protocol-evidence observations, and all packet/payload/document bytes.
 */
sealed interface DurableHistoryRecord {
    val atMillis: Long

    data class MonitorState(override val atMillis: Long, val state: MonitorLifecycleState) : DurableHistoryRecord

    data class Packet(
        override val atMillis: Long,
        val direction: PacketDirection,
        val ipVersion: IpVersion,
        val transport: TransportProtocol,
        val ipProtocolNumber: Int,
        val capturedBytes: Int,
        val declaredIpBytes: Int?,
        val dnsStatus: DnsParseStatus?,
        val attribution: DurableAttribution,
        val parserNotes: Set<PacketParserNote>,
        val observedCount: Int = 1,
    ) : DurableHistoryRecord {
        init {
            require(ipProtocolNumber in 0..255 && capturedBytes >= 0) { "Invalid packet history metadata." }
            require(declaredIpBytes == null || declaredIpBytes >= 0) { "Invalid declared packet length." }
            require(observedCount in 1..Int.MAX_VALUE) { "Observed count must be positive." }
        }
    }

    data class FirewallDecision(
        override val atMillis: Long,
        val requestedAction: FirewallAction,
        val reason: FirewallDecisionReason,
        val enforcement: FirewallEnforcementState,
        val hadMatchingRule: Boolean,
    ) : DurableHistoryRecord

    data class PacketParseFailure(
        override val atMillis: Long,
        val code: PacketParseFailureCode,
    ) : DurableHistoryRecord

    data class Limitation(override val atMillis: Long, val code: EngineLimitationCode) : DurableHistoryRecord

    data class Enforcement(override val atMillis: Long, val outcome: FirewallEnforcementOutcome) : DurableHistoryRecord
}

sealed interface DurableAttribution {
    data object Known : DurableAttribution
    data class Unknown(val reason: AttributionUnavailableReason) : DurableAttribution
}

/** A bounded enqueue-only surface safe to call alongside the existing event store. */
interface DurableNetworkHistorySink {
    fun offer(event: NetworkEvent)

    /** Requests a background drain and waits only up to the caller-provided bound. */
    fun flush(timeoutMillis: Long): Boolean

    fun snapshot(): DurableHistorySnapshot

    /** Removes ciphertext then the dedicated key; never runs cryptography or storage on a forwarding thread. */
    fun erase(timeoutMillis: Long): DurableHistorySnapshot
}

/**
 * Optional durable history writer. It is never installed by default. [offer]
 * maps an event to safe primitive metadata and performs a bounded in-memory
 * queue offer only; Android Keystore and SharedPreferences calls run on one
 * writer thread. The persisted value is one authenticated, versioned blob, so
 * a successful backing-store commit cannot expose a partially written record.
 */
class EncryptedNetworkHistoryController(
    private val storage: EncryptedStorage,
    private val key: SecureStorageKey = SecureStorageKey("network-history-v1"),
    private val keyEraser: DurableHistoryKeyEraser? = null,
    private val policy: DurableHistoryRetentionPolicy = DurableHistoryRetentionPolicy.SEVEN_DAYS,
    private val limits: DurableHistoryLimits = DurableHistoryLimits(),
    private val clock: EpochClock = SystemEpochClock,
    private val writer: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "apk-sentinel-network-history").apply { isDaemon = true }
    },
) : DurableNetworkHistorySink, AutoCloseable {
    private val ingressLock = Any()
    private val ingress = ArrayDeque<DurableHistoryRecord>(limits.maximumIngressRecords)
    private val scheduled = AtomicBoolean(false)
    private val accepting = AtomicBoolean(true)
    private val closed = AtomicBoolean(false)
    private val ingressDrops = AtomicLong(0L)
    private val limitDrops = AtomicLong(0L)

    @Volatile
    private var current = DurableHistorySnapshot(
        state = if (policy == DurableHistoryRetentionPolicy.SESSION_ONLY) {
            DurableHistoryReadState.SESSION_ONLY
        } else {
            DurableHistoryReadState.NOT_LOADED
        },
        policy = policy,
    )

    private var loaded = false
    private var blockedByReadFailure = false

    override fun offer(event: NetworkEvent) {
        if (closed.get() || !accepting.get() || policy == DurableHistoryRetentionPolicy.SESSION_ONLY) return
        val record = event.toDurableHistoryRecord() ?: return
        if (record.atMillis < 0L) {
            ingressDrops.incrementSaturating()
            return
        }
        synchronized(ingressLock) {
            if (closed.get() || !accepting.get()) return
            if (ingress.size == limits.maximumIngressRecords) {
                ingressDrops.incrementSaturating()
            } else {
                ingress.addLast(record)
            }
        }
        scheduleDrain()
    }

    /** Explicit async load for a future UI. Constructing this controller performs no I/O. */
    fun requestLoad() {
        if (closed.get() || policy == DurableHistoryRetentionPolicy.SESSION_ONLY) return
        submit { ensureLoaded() }
    }

    override fun flush(timeoutMillis: Long): Boolean {
        if (timeoutMillis < 0L || closed.get() || policy == DurableHistoryRetentionPolicy.SESSION_ONLY) return false
        val done = CountDownLatch(1)
        if (!submit {
            try {
                drainAndPersist()
            } finally {
                done.countDown()
            }
        }) return false
        return done.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }

    override fun snapshot(): DurableHistorySnapshot = current.copy(
        droppedIngressRecords = ingressDrops.get(),
        droppedByLimitRecords = limitDrops.get(),
    )

    override fun erase(timeoutMillis: Long): DurableHistorySnapshot {
        if (timeoutMillis < 0L || closed.get()) return snapshot()
        val done = CountDownLatch(1)
        current = current.copy(state = DurableHistoryReadState.ERASING, failure = null)
        synchronized(ingressLock) { ingress.clear() }
        if (!submit {
            try {
                val removed = runCatching { storage.remove(key) }.getOrNull()
                if (removed !is SecureStorageResult.Success) {
                    current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.ERASE_CIPHERTEXT_FAILED)
                    return@submit
                }
                val erased = keyEraser?.eraseKey()
                current = when (erased) {
                    true -> DurableHistorySnapshot(DurableHistoryReadState.ERASED, policy)
                    false -> current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.ERASE_KEY_FAILED)
                    null -> current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.ERASE_UNAVAILABLE)
                }
                loaded = erased == true
                blockedByReadFailure = erased != true
            } finally {
                done.countDown()
            }
        }) return snapshot()
        done.await(timeoutMillis, TimeUnit.MILLISECONDS)
        return snapshot()
    }

    override fun close() {
        if (closed.get()) return
        freeze()
        flush(CLOSE_FLUSH_MILLIS)
        if (!closed.compareAndSet(false, true)) return
        writer.shutdown()
    }

    /** Prevents late forwarding offers before an erase or lifecycle teardown. */
    fun freeze() {
        accepting.set(false)
    }

    private fun scheduleDrain() {
        if (!scheduled.compareAndSet(false, true)) return
        if (!submit {
            try {
                drainAndPersist()
            } finally {
                scheduled.set(false)
                synchronized(ingressLock) {
                    if (ingress.isNotEmpty() && !closed.get()) scheduleDrain()
                }
            }
        }) scheduled.set(false)
    }

    private fun drainAndPersist() {
        if (closed.get() || policy == DurableHistoryRetentionPolicy.SESSION_ONLY) return
        if (!ensureLoaded()) {
            synchronized(ingressLock) {
                ingressDrops.addSaturating(ingress.size.toLong())
                ingress.clear()
            }
            return
        }
        val batch = synchronized(ingressLock) {
            buildList(ingress.size) {
                while (ingress.isNotEmpty()) add(ingress.removeFirst())
            }
        }
        if (batch.isEmpty()) return
        val now = runCatching { clock.nowMillis() }.getOrNull()
        if (now == null || now < 0L) {
            current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.CLOCK_INVALID)
            ingressDrops.addSaturating(batch.size.toLong())
            return
        }
        val merged = coalesce(current.records + batch)
        val pruned = prune(merged, now)
        val bounded = applyLimits(pruned)
        val encoded = DurableHistoryCodec.encode(bounded, limits)
        if (encoded is HistoryCodecResult.Failure) {
            current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.CORRUPT_OR_UNSUPPORTED)
            ingressDrops.addSaturating(batch.size.toLong())
            return
        }
        val bytes = (encoded as HistoryCodecResult.Success).bytes
        when (runCatching { storage.write(key, bytes) }.getOrNull()) {
            is SecureStorageResult.Success -> current = DurableHistorySnapshot(
                state = DurableHistoryReadState.READY,
                policy = policy,
                records = bounded,
                retainedPlaintextBytes = bytes.size,
            )

            else -> {
                ingressDrops.addSaturating(batch.size.toLong())
                current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.STORAGE_WRITE_FAILED)
            }
        }
    }

    private fun ensureLoaded(): Boolean {
        if (loaded) return !blockedByReadFailure
        if (policy == DurableHistoryRetentionPolicy.SESSION_ONLY) return false
        val result = runCatching { storage.read(key) }.getOrNull()
        when (result) {
            is SecureStorageResult.Success -> {
                val bytes = result.value
                if (bytes == null) {
                    current = DurableHistorySnapshot(DurableHistoryReadState.READY, policy)
                    loaded = true
                    return true
                }
                when (val decoded = DurableHistoryCodec.decode(bytes, limits)) {
                    is HistoryCodecResult.Success -> {
                        val now = runCatching { clock.nowMillis() }.getOrNull()
                        if (now == null || now < 0L) {
                            current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.CLOCK_INVALID)
                            blockedByReadFailure = true
                        } else {
                            val records = applyLimits(prune(decoded.records, now))
                            val encoded = DurableHistoryCodec.encode(records, limits)
                            val encodedBytes = (encoded as? HistoryCodecResult.Success)?.bytes
                            if (encodedBytes == null) {
                                current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.CORRUPT_OR_UNSUPPORTED)
                                blockedByReadFailure = true
                            } else if (records != decoded.records &&
                                runCatching { storage.write(key, encodedBytes) }.getOrNull() !is SecureStorageResult.Success
                            ) {
                                // Do not report a successful retention prune when the old
                                // ciphertext could not be atomically replaced.
                                current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.STORAGE_WRITE_FAILED)
                                blockedByReadFailure = true
                            } else current = DurableHistorySnapshot(
                                state = DurableHistoryReadState.READY,
                                policy = policy,
                                records = records,
                                retainedPlaintextBytes = encodedBytes.size,
                            )
                        }
                    }

                    is HistoryCodecResult.Failure -> {
                        current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.CORRUPT_OR_UNSUPPORTED)
                        blockedByReadFailure = true
                    }
                }
            }

            is SecureStorageResult.Failure -> {
                val failure = if (result.reason == SecureStorageFailure.DECRYPTION_FAILED) {
                    DurableHistoryFailure.DECRYPTION_FAILED
                } else {
                    DurableHistoryFailure.STORAGE_READ_FAILED
                }
                current = current.copy(state = DurableHistoryReadState.FAILED, failure = failure)
                blockedByReadFailure = true
            }

            null -> {
                current = current.copy(state = DurableHistoryReadState.FAILED, failure = DurableHistoryFailure.STORAGE_READ_FAILED)
                blockedByReadFailure = true
            }
        }
        loaded = true
        return !blockedByReadFailure
    }

    private fun prune(records: List<DurableHistoryRecord>, now: Long): List<DurableHistoryRecord> {
        val retention = requireNotNull(policy.retentionMillis)
        val cutoff = if (now < retention) 0L else now - retention
        // Do not discard a record merely because the wall clock moved backward.
        // Record-count/byte caps still bound any hostile future timestamps.
        return records.filter { it.atMillis >= cutoff }
    }

    private fun applyLimits(records: List<DurableHistoryRecord>): List<DurableHistoryRecord> {
        val bounded = if (records.size > limits.maximumRecords) {
            limitDrops.addSaturating((records.size - limits.maximumRecords).toLong())
            records.takeLast(limits.maximumRecords)
        } else {
            records
        }
        if (DurableHistoryCodec.encode(bounded, limits) is HistoryCodecResult.Success) return bounded
        // A record has a fixed bounded encoding. Find the oldest prefix to
        // discard with O(log n) full encodes instead of one encode per record.
        var low = 1
        var high = bounded.size
        var best = bounded.size
        while (low <= high) {
            val middle = low + (high - low) / 2
            if (DurableHistoryCodec.encode(bounded.drop(middle), limits) is HistoryCodecResult.Success) {
                best = middle
                high = middle - 1
            } else {
                low = middle + 1
            }
        }
        limitDrops.addSaturating(best.toLong())
        return bounded.drop(best)
    }

    private fun coalesce(records: List<DurableHistoryRecord>): List<DurableHistoryRecord> {
        val result = ArrayList<DurableHistoryRecord>(records.size)
        records.forEach { record ->
            val previous = result.lastOrNull()
            if (previous is DurableHistoryRecord.Packet && record is DurableHistoryRecord.Packet &&
                previous.atMillis / 1_000L == record.atMillis / 1_000L &&
                previous.copy(atMillis = record.atMillis, observedCount = 1) == record.copy(observedCount = 1) &&
                previous.observedCount < Int.MAX_VALUE
            ) {
                result[result.lastIndex] = previous.copy(
                    atMillis = record.atMillis,
                    observedCount = previous.observedCount + record.observedCount.coerceAtMost(Int.MAX_VALUE - previous.observedCount),
                )
            } else {
                result += record
            }
        }
        return result
    }

    private fun submit(task: () -> Unit): Boolean = try {
        writer.execute(task)
        true
    } catch (_: RejectedExecutionException) {
        false
    }

    private companion object {
        const val CLOSE_FLUSH_MILLIS = 1_500L
    }
}

private sealed interface HistoryCodecResult {
    data class Success(val bytes: ByteArray = ByteArray(0), val records: List<DurableHistoryRecord> = emptyList()) : HistoryCodecResult
    data object Failure : HistoryCodecResult
}

/** Versioned framing with a bounded length prefix around every record. */
private object DurableHistoryCodec {
    private const val MAGIC = 0x41534831 // ASH1
    private const val VERSION = 1

    fun encode(records: List<DurableHistoryRecord>, limits: DurableHistoryLimits): HistoryCodecResult = try {
        if (records.size > limits.maximumRecords) return HistoryCodecResult.Failure
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data ->
            data.writeInt(MAGIC)
            data.writeShort(VERSION)
            data.writeInt(records.size)
            records.forEach { record ->
                val frame = encodeRecord(record) ?: return HistoryCodecResult.Failure
                if (frame.size !in 1..limits.maximumRecordBytes) return HistoryCodecResult.Failure
                if (output.size().toLong() + 4L + frame.size.toLong() > limits.maximumPlaintextBytes.toLong()) {
                    return HistoryCodecResult.Failure
                }
                data.writeInt(frame.size)
                data.write(frame)
            }
        }
        HistoryCodecResult.Success(bytes = output.toByteArray())
    } catch (_: RuntimeException) {
        HistoryCodecResult.Failure
    }

    fun decode(bytes: ByteArray, limits: DurableHistoryLimits): HistoryCodecResult {
        if (bytes.size !in HEADER_BYTES..limits.maximumPlaintextBytes) return HistoryCodecResult.Failure
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { data ->
                if (data.readInt() != MAGIC || data.readUnsignedShort() != VERSION) return HistoryCodecResult.Failure
                val count = data.readInt()
                if (count !in 0..limits.maximumRecords) return HistoryCodecResult.Failure
                val records = ArrayList<DurableHistoryRecord>(count)
                repeat(count) {
                    val length = data.readInt()
                    if (length !in 1..limits.maximumRecordBytes || length > data.available()) return HistoryCodecResult.Failure
                    val frame = ByteArray(length)
                    data.readFully(frame)
                    records += decodeRecord(frame) ?: return HistoryCodecResult.Failure
                }
                if (data.available() != 0) return HistoryCodecResult.Failure
                HistoryCodecResult.Success(records = records)
            }
        } catch (_: EOFException) {
            HistoryCodecResult.Failure
        } catch (_: RuntimeException) {
            HistoryCodecResult.Failure
        }
    }

    private fun encodeRecord(record: DurableHistoryRecord): ByteArray? = try {
        ByteArrayOutputStream().also { output ->
            DataOutputStream(output).use { data ->
                when (record) {
                    is DurableHistoryRecord.MonitorState -> {
                        data.writeByte(1); data.writeLong(record.atMillis); data.writeByte(code(record.state))
                    }
                    is DurableHistoryRecord.Packet -> {
                        data.writeByte(2); data.writeLong(record.atMillis); data.writeByte(code(record.direction))
                        data.writeByte(code(record.ipVersion)); data.writeByte(code(record.transport)); data.writeByte(record.ipProtocolNumber)
                        data.writeInt(record.capturedBytes); data.writeInt(record.declaredIpBytes ?: -1)
                        data.writeByte(record.dnsStatus?.let(::code) ?: 0); data.writeByte(attributionCode(record.attribution))
                        data.writeByte((record.attribution as? DurableAttribution.Unknown)?.let { code(it.reason) } ?: 0)
                        data.writeLong(mask(record.parserNotes)); data.writeInt(record.observedCount)
                    }
                    is DurableHistoryRecord.FirewallDecision -> {
                        data.writeByte(3); data.writeLong(record.atMillis); data.writeByte(code(record.requestedAction))
                        data.writeByte(code(record.reason)); data.writeByte(code(record.enforcement)); data.writeBoolean(record.hadMatchingRule)
                    }
                    is DurableHistoryRecord.PacketParseFailure -> {
                        data.writeByte(4); data.writeLong(record.atMillis); data.writeByte(code(record.code))
                    }
                    is DurableHistoryRecord.Limitation -> {
                        data.writeByte(5); data.writeLong(record.atMillis); data.writeShort(code(record.code))
                    }
                    is DurableHistoryRecord.Enforcement -> {
                        data.writeByte(6); data.writeLong(record.atMillis); data.writeByte(code(record.outcome))
                    }
                }
            }
        }.toByteArray()
    } catch (_: RuntimeException) { null }

    private fun decodeRecord(frame: ByteArray): DurableHistoryRecord? = try {
        DataInputStream(ByteArrayInputStream(frame)).use { data ->
            val type = data.readUnsignedByte()
            val at = data.readLong()
            if (at < 0L) return null
            val result: DurableHistoryRecord? = when (type) {
                1 -> enumByCode<MonitorLifecycleState>(data.readUnsignedByte())?.let { DurableHistoryRecord.MonitorState(at, it) }
                2 -> {
                    val direction = enumByCode<PacketDirection>(data.readUnsignedByte())
                    val version = enumByCode<IpVersion>(data.readUnsignedByte())
                    val transport = enumByCode<TransportProtocol>(data.readUnsignedByte())
                    val protocol = data.readUnsignedByte(); val captured = data.readInt(); val declared = data.readInt()
                    val dns = nullableEnum<DnsParseStatus>(data.readUnsignedByte())
                    val attributionCode = data.readUnsignedByte()
                    val unknownReasonCode = data.readUnsignedByte()
                    val attribution = when (attributionCode) {
                        1 -> DurableAttribution.Known
                        2 -> enumByCode<AttributionUnavailableReason>(unknownReasonCode)?.let(DurableAttribution::Unknown)
                        else -> null
                    }
                    val notes = unmask<PacketParserNote>(data.readLong())
                    val count = data.readInt()
                    if (direction == null || version == null || transport == null || captured < 0 || declared < -1 || attribution == null || count <= 0) null
                    else DurableHistoryRecord.Packet(at, direction, version, transport, protocol, captured, declared.takeIf { it >= 0 }, dns, attribution, notes, count)
                }
                3 -> {
                    val action = enumByCode<FirewallAction>(data.readUnsignedByte())
                    val reason = enumByCode<FirewallDecisionReason>(data.readUnsignedByte())
                    val enforcement = enumByCode<FirewallEnforcementState>(data.readUnsignedByte())
                    val match = data.readBoolean()
                    if (action == null || reason == null || enforcement == null) null else DurableHistoryRecord.FirewallDecision(at, action, reason, enforcement, match)
                }
                4 -> enumByCode<PacketParseFailureCode>(data.readUnsignedByte())?.let { DurableHistoryRecord.PacketParseFailure(at, it) }
                5 -> enumByCode<EngineLimitationCode>(data.readUnsignedShort())?.let { DurableHistoryRecord.Limitation(at, it) }
                6 -> enumByCode<FirewallEnforcementOutcome>(data.readUnsignedByte())?.let { DurableHistoryRecord.Enforcement(at, it) }
                else -> null
            }
            if (data.available() != 0) null else result
        }
    } catch (_: EOFException) { null } catch (_: RuntimeException) { null }

    private inline fun <reified T : Enum<T>> code(value: T): Int = value.ordinal + 1
    private inline fun <reified T : Enum<T>> enumByCode(code: Int): T? = enumValues<T>().getOrNull(code - 1)
    private inline fun <reified T : Enum<T>> nullableEnum(code: Int): T? = if (code == 0) null else enumByCode(code)
    private fun attributionCode(value: DurableAttribution): Int = if (value is DurableAttribution.Known) 1 else 2
    private inline fun <reified T : Enum<T>> mask(values: Set<T>): Long = values.fold(0L) { mask, value ->
        if (value.ordinal >= Long.SIZE_BITS - 1) throw IllegalArgumentException("Too many enum values")
        mask or (1L shl value.ordinal)
    }
    private inline fun <reified T : Enum<T>> unmask(mask: Long): Set<T> {
        if (mask < 0L) throw IllegalArgumentException("Invalid enum mask")
        return enumValues<T>().filterTo(linkedSetOf()) { value -> mask and (1L shl value.ordinal) != 0L }
    }

    private const val HEADER_BYTES = 10
}

private fun NetworkEvent.toDurableHistoryRecord(): DurableHistoryRecord? = when (this) {
    is MonitorStateEvent -> DurableHistoryRecord.MonitorState(atMillis, state)
    is PacketObservedEvent -> DurableHistoryRecord.Packet(
        atMillis = atMillis,
        direction = direction,
        ipVersion = metadata.ipVersion,
        transport = metadata.transportProtocol,
        ipProtocolNumber = metadata.ipProtocolNumber,
        capturedBytes = metadata.capturedPacketBytes,
        declaredIpBytes = metadata.declaredIpPacketBytes,
        dnsStatus = metadata.dns?.status,
        attribution = when (attribution) {
            is AppAttribution.Known -> DurableAttribution.Known
            is AppAttribution.Unknown -> DurableAttribution.Unknown(attribution.reason)
        },
        parserNotes = metadata.notes,
    )
    is FirewallDecisionEvent -> DurableHistoryRecord.FirewallDecision(
        atMillis, decision.requestedAction, decision.reason, decision.enforcement, decision.matchedRuleId != null,
    )
    is PacketParseFailureEvent -> DurableHistoryRecord.PacketParseFailure(atMillis, code)
    is EngineLimitationEvent -> DurableHistoryRecord.Limitation(atMillis, limitation.code)
    is ForwarderEnforcementEvent -> DurableHistoryRecord.Enforcement(atMillis, result.outcome)
}

private fun AtomicLong.incrementSaturating() = updateAndGet { if (it == Long.MAX_VALUE) it else it + 1L }
private fun AtomicLong.addSaturating(delta: Long) = updateAndGet { current ->
    if (delta <= 0L || current >= Long.MAX_VALUE - delta) Long.MAX_VALUE else current + delta
}
