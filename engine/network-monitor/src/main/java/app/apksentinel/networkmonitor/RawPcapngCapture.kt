package app.apksentinel.networkmonitor

import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Explicit limits for a user-started raw-IP evidence export. These limits are
 * deliberately independent of the VPN's forwarding limits: capture is an
 * optional observer and must never become a reason to delay packet forwarding.
 */
data class RawPcapngCaptureLimits(
    val maximumDurationMillis: Long = 60_000L,
    val maximumPackets: Long = 5_000L,
    val maximumCapturedBytes: Long = 20L * 1_024L * 1_024L,
    val perPacketSnaplen: Int = 65_535,
    val queueCapacity: Int = 128,
) {
    init {
        require(maximumDurationMillis in 1_000L..15 * 60 * 1_000L) {
            "Capture duration must be between one second and fifteen minutes."
        }
        require(maximumPackets in 1L..100_000L) { "Packet limit must be between 1 and 100000." }
        require(maximumCapturedBytes in 1_024L..128L * 1_024L * 1_024L) {
            "Captured-byte limit must be between 1024 and 134217728."
        }
        require(perPacketSnaplen in 20..65_535) { "Snap length must be between 20 and 65535." }
        require(queueCapacity in 1..2_048) { "Queue capacity must be between 1 and 2048." }
        // Bounds temporary copies even when a caller selects a large snap length.
        require(queueCapacity.toLong() * perPacketSnaplen <= 16L * 1_024L * 1_024L) {
            "Queue capacity multiplied by snap length must not exceed 16 MiB."
        }
    }
}

enum class RawPcapngCaptureState {
    STOPPED,
    RUNNING,
    STOPPING,
    FAILED,
}

/** Stable, non-sensitive reason codes for a rejected capture start. */
enum class RawPcapngCaptureStartRejection {
    ALREADY_ACTIVE,
    CLOCK_UNAVAILABLE,
    INVALID_START_TIME,
    WRITER_START_FAILED,
}

/** Stable, non-sensitive reason codes for a terminal capture failure. */
enum class RawPcapngCaptureFailureReason {
    CLOCK_UNAVAILABLE,
    INVALID_CLOCK_TIME,
    OUTPUT_WRITE_FAILED,
    WRITER_INTERRUPTED,
    WRITER_RUNTIME_FAILURE,
    WRITER_START_FAILED,
}

/** Counters are intentionally payload-free and safe to expose in a UI. */
data class RawPcapngCaptureStatus(
    val state: RawPcapngCaptureState = RawPcapngCaptureState.STOPPED,
    val startedAtMillis: Long? = null,
    val endedAtMillis: Long? = null,
    val acceptedPackets: Long = 0L,
    val writtenPackets: Long = 0L,
    val capturedBytes: Long = 0L,
    val writtenFileBytes: Long = 0L,
    val truncatedPackets: Long = 0L,
    val droppedQueueFull: Long = 0L,
    val droppedByLimit: Long = 0L,
    val droppedUnsupportedPacket: Long = 0L,
    val droppedInvalidTimestamp: Long = 0L,
    /** Decryption Secrets Blocks written, so the capture can say whether it self-decrypts. */
    val writtenSecretBlocks: Long = 0L,
    val droppedSecretBlocks: Long = 0L,
    /** Never contains an exception or document-provider message. */
    val failureReason: RawPcapngCaptureFailureReason? = null,
)

sealed interface RawPcapngCaptureStartResult {
    data class Started(val startedAtMillis: Long) : RawPcapngCaptureStartResult
    data class Rejected(val reason: RawPcapngCaptureStartRejection) : RawPcapngCaptureStartResult
}

/**
 * Original PCAPNG writer for link type DLT_RAW (101): each enhanced packet
 * block contains one raw IPv4 or IPv6 datagram. It intentionally has no packet
 * parser, UI payload accessor, decryption, network destination, or stream
 * ownership. The caller must obtain a local document [OutputStream] after an
 * explicit user action and remains responsible for closing that stream.
 */
class RawPcapngCaptureManager(
    private val clock: EpochClock = SystemEpochClock,
    private val workerStarter: (name: String, task: () -> Unit) -> Thread = { name, task ->
        thread(start = true, isDaemon = true, name = name) { task() }
    },
) {
    private val lock = Any()
    private var active: CaptureSession? = null
    private var lastStatus = RawPcapngCaptureStatus()

    fun start(
        output: OutputStream,
        limits: RawPcapngCaptureLimits = RawPcapngCaptureLimits(),
    ): RawPcapngCaptureStartResult = synchronized(lock) {
        if (active != null) return RawPcapngCaptureStartResult.Rejected(RawPcapngCaptureStartRejection.ALREADY_ACTIVE)
        val now = runCatching { clock.nowMillis() }.getOrElse {
            return RawPcapngCaptureStartResult.Rejected(RawPcapngCaptureStartRejection.CLOCK_UNAVAILABLE)
        }
        if (now < 0L) return RawPcapngCaptureStartResult.Rejected(RawPcapngCaptureStartRejection.INVALID_START_TIME)
        val session = CaptureSession(output, limits, now)
        active = session
        lastStatus = session.status()
        try {
            session.startWriter()
        } catch (_: Throwable) {
            session.failToStart()
            lastStatus = session.status()
            if (active === session) active = null
            return RawPcapngCaptureStartResult.Rejected(RawPcapngCaptureStartRejection.WRITER_START_FAILED)
        }
        RawPcapngCaptureStartResult.Started(now)
    }

    /**
     * Non-blocking hook for the forwarding path. It copies at most snaplen
     * bytes and uses [ArrayBlockingQueue.offer], so slow document storage only
     * causes explicit drops rather than blocking a TUN reader or socket worker.
     */
    fun offerRawIpPacket(packet: ByteArray) {
        val session = synchronized(lock) { active } ?: return
        val observedAtMillis = runCatching { clock.nowMillis() }.getOrElse {
            session.failForClock()
            return
        }
        session.offer(packet, observedAtMillis)
    }

    fun offerRawIpPacket(packet: ByteArray, observedAtMillis: Long) {
        val session = synchronized(lock) { active } ?: return
        session.offer(packet, observedAtMillis)
    }

    /**
     * Embeds TLS secrets in the running capture so it decrypts when opened.
     *
     * [block] must be NSS key-log text. The manager takes ownership and zeroizes it, whether
     * or not a capture is running.
     */
    fun offerTlsSecrets(block: ByteArray) {
        val session = synchronized(lock) { active }
        if (session == null) {
            block.fill(0)
            return
        }
        session.offerSecrets(block)
    }

    fun status(): RawPcapngCaptureStatus = synchronized(lock) { active?.status() ?: lastStatus }

    /** Requests a graceful, flushing stop. The caller-owned stream is never closed. */
    fun stop() {
        synchronized(lock) { active }?.requestStop()
    }

    /** Useful for lifecycle teardown/tests; never waits indefinitely on a slow OutputStream. */
    fun awaitStopped(timeoutMillis: Long): Boolean {
        require(timeoutMillis >= 0L) { "Timeout must not be negative." }
        val session = synchronized(lock) { active } ?: return true
        return session.awaitStopped(timeoutMillis)
    }

    private fun completed(session: CaptureSession, finalStatus: RawPcapngCaptureStatus) {
        synchronized(lock) {
            lastStatus = finalStatus
            if (active === session) active = null
        }
    }

    private data class PendingPacket(
        val bytes: ByteArray,
        val originalLength: Int,
        val observedAtMillis: Long,
    )

    private inner class CaptureSession(
        private val output: OutputStream,
        private val limits: RawPcapngCaptureLimits,
        private val startedAtMillis: Long,
    ) {
        private val queue = ArrayBlockingQueue<PendingPacket>(limits.queueCapacity)
        private val secretsQueue = ArrayBlockingQueue<ByteArray>(SECRETS_QUEUE_CAPACITY)
        private val stateLock = Any()
        private val acceptedPackets = AtomicLong()
        private val writtenPackets = AtomicLong()
        private val capturedBytes = AtomicLong()
        private val writtenFileBytes = AtomicLong()
        private val reservedFileBytes = AtomicLong(HEADER_FILE_BYTES.toLong())
        private val truncatedPackets = AtomicLong()
        private val droppedQueueFull = AtomicLong()
        private val droppedByLimit = AtomicLong()
        private val droppedUnsupportedPacket = AtomicLong()
        private val droppedInvalidTimestamp = AtomicLong()
        private val droppedSecretBlocks = AtomicLong()
        private val writtenSecretBlocks = AtomicLong()
        private val deadlineMillis = saturatingAdd(startedAtMillis, limits.maximumDurationMillis)
        @Volatile private var state = RawPcapngCaptureState.RUNNING
        @Volatile private var endedAtMillis: Long? = null
        @Volatile private var failureReason: RawPcapngCaptureFailureReason? = null
        @Volatile private var writer: Thread? = null
        private var stopRequestedByLimit = false

        fun startWriter() {
            writer = workerStarter("apk-sentinel-pcapng-writer", ::writeLoop)
        }

        fun failToStart() {
            synchronized(stateLock) {
                state = RawPcapngCaptureState.FAILED
                failureReason = RawPcapngCaptureFailureReason.WRITER_START_FAILED
                endedAtMillis = startedAtMillis
            }
        }

        fun failForClock() = fail(RawPcapngCaptureFailureReason.CLOCK_UNAVAILABLE)

        fun offer(packet: ByteArray, observedAtMillis: Long) {
            synchronized(stateLock) {
                if (state != RawPcapngCaptureState.RUNNING) {
                    if (stopRequestedByLimit) droppedByLimit.incrementAndGet()
                    return
                }
                if (observedAtMillis < 0L) {
                    droppedInvalidTimestamp.incrementAndGet()
                    return
                }
                if (observedAtMillis >= deadlineMillis) {
                    droppedByLimit.incrementAndGet()
                    requestStopForLimit()
                    return
                }
                if (!isStructurallyRawIp(packet)) {
                    droppedUnsupportedPacket.incrementAndGet()
                    return
                }
                val retainedLength = minOf(packet.size, limits.perPacketSnaplen)
                if (!reserve(retainedLength)) return
                val copy = packet.copyOf(retainedLength)
                if (retainedLength < packet.size) truncatedPackets.incrementAndGet()
                val pending = PendingPacket(copy, packet.size, observedAtMillis)
                if (!queue.offer(pending)) {
                    copy.fill(0)
                    acceptedPackets.decrementAndGet()
                    capturedBytes.addAndGet(-retainedLength.toLong())
                    reservedFileBytes.addAndGet(-serializedEnhancedPacketBytes(retainedLength).toLong())
                    if (retainedLength < packet.size) truncatedPackets.decrementAndGet()
                    droppedQueueFull.incrementAndGet()
                } else if (
                    acceptedPackets.get() >= limits.maximumPackets ||
                    reservedFileBytes.get() >= limits.maximumCapturedBytes
                ) {
                    requestStopForLimit()
                }
            }
        }

        /**
         * Queues TLS secrets for a Decryption Secrets Block.
         *
         * Wireshark reads these out of the file itself, so a capture taken with key logging
         * on decrypts when it is opened, with nothing for the user to configure. The bytes
         * are zeroized once written.
         */
        fun offerSecrets(block: ByteArray) {
            synchronized(stateLock) {
                if (state != RawPcapngCaptureState.RUNNING || block.isEmpty()) {
                    block.fill(0)
                    return
                }
                if (block.size > MAX_SECRETS_BLOCK_BYTES) {
                    block.fill(0)
                    droppedSecretBlocks.incrementAndGet()
                    return
                }
                val serialized = serializedSecretsBytes(block.size).toLong()
                if (reservedFileBytes.get() > limits.maximumCapturedBytes - serialized) {
                    block.fill(0)
                    droppedSecretBlocks.incrementAndGet()
                    return
                }
                reservedFileBytes.addAndGet(serialized)
                if (!secretsQueue.offer(block)) {
                    block.fill(0)
                    reservedFileBytes.addAndGet(-serialized)
                    droppedSecretBlocks.incrementAndGet()
                }
            }
        }

        private fun reserve(retainedLength: Int): Boolean {
            val serializedBytes = serializedEnhancedPacketBytes(retainedLength).toLong()
            val oldCount = acceptedPackets.get()
            if (oldCount >= limits.maximumPackets) {
                droppedByLimit.incrementAndGet()
                requestStopForLimit()
                return false
            }
            val oldCapturedBytes = capturedBytes.get()
            if (oldCapturedBytes > limits.maximumCapturedBytes - retainedLength.toLong()) {
                droppedByLimit.incrementAndGet()
                requestStopForLimit()
                return false
            }
            val oldReservedBytes = reservedFileBytes.get()
            if (oldReservedBytes > limits.maximumCapturedBytes - serializedBytes) {
                droppedByLimit.incrementAndGet()
                requestStopForLimit()
                return false
            }
            acceptedPackets.incrementAndGet()
            capturedBytes.addAndGet(retainedLength.toLong())
            reservedFileBytes.addAndGet(serializedBytes)
            return true
        }

        /** Header sanity only; capture never parses transport or payload bytes. */
        private fun isStructurallyRawIp(packet: ByteArray): Boolean = when (packet.firstOrNull()?.toInt()?.ushr(4)) {
            4 -> packet.size >= 20 && ((packet[0].toInt() and 0x0F) * 4) in 20..packet.size
            6 -> packet.size >= 40
            else -> false
        }

        fun requestStop() {
            synchronized(stateLock) {
                if (state == RawPcapngCaptureState.RUNNING) state = RawPcapngCaptureState.STOPPING
            }
        }

        private fun requestStopForLimit() {
            synchronized(stateLock) {
                stopRequestedByLimit = true
                if (state == RawPcapngCaptureState.RUNNING) state = RawPcapngCaptureState.STOPPING
            }
        }

        fun awaitStopped(timeoutMillis: Long): Boolean {
            writer?.join(timeoutMillis)
            return state == RawPcapngCaptureState.STOPPED || state == RawPcapngCaptureState.FAILED
        }

        fun status(): RawPcapngCaptureStatus = RawPcapngCaptureStatus(
            state = state,
            startedAtMillis = startedAtMillis,
            endedAtMillis = endedAtMillis,
            acceptedPackets = acceptedPackets.get(),
            writtenPackets = writtenPackets.get(),
            capturedBytes = capturedBytes.get(),
            writtenFileBytes = writtenFileBytes.get(),
            truncatedPackets = truncatedPackets.get(),
            droppedQueueFull = droppedQueueFull.get(),
            droppedByLimit = droppedByLimit.get(),
            droppedUnsupportedPacket = droppedUnsupportedPacket.get(),
            droppedInvalidTimestamp = droppedInvalidTimestamp.get(),
            writtenSecretBlocks = writtenSecretBlocks.get(),
            droppedSecretBlocks = droppedSecretBlocks.get(),
            failureReason = failureReason,
        )

        private fun writeLoop() {
            try {
                writeSectionHeader()
                writeInterfaceDescription()
                while (state == RawPcapngCaptureState.RUNNING || queue.isNotEmpty() || secretsQueue.isNotEmpty()) {
                    val now = try {
                        clock.nowMillis()
                    } catch (_: RuntimeException) {
                        fail(RawPcapngCaptureFailureReason.CLOCK_UNAVAILABLE)
                        break
                    }
                    if (now < 0L) {
                        fail(RawPcapngCaptureFailureReason.INVALID_CLOCK_TIME)
                        break
                    }
                    if (state == RawPcapngCaptureState.RUNNING && now >= deadlineMillis) {
                        requestStopForLimit()
                        continue
                    }
                    // Secrets first: Wireshark applies a DSB to the packets that follow it,
                    // so a key must never trail the traffic it unlocks.
                    while (true) writeDecryptionSecrets(secretsQueue.poll() ?: break)
                    val pending = queue.poll(100L, TimeUnit.MILLISECONDS) ?: continue
                    writeEnhancedPacket(pending)
                }
                while (true) writeDecryptionSecrets(secretsQueue.poll() ?: break)
                if (state != RawPcapngCaptureState.FAILED) {
                    output.flush()
                    synchronized(stateLock) {
                        if (state != RawPcapngCaptureState.FAILED) {
                            state = RawPcapngCaptureState.STOPPED
                        }
                    }
                }
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                fail(RawPcapngCaptureFailureReason.WRITER_INTERRUPTED)
            } catch (_: IOException) {
                fail(RawPcapngCaptureFailureReason.OUTPUT_WRITE_FAILED)
            } catch (_: Throwable) {
                fail(RawPcapngCaptureFailureReason.WRITER_RUNTIME_FAILURE)
            } finally {
                clearQueueAndZeroize()
                val terminalTime = try {
                    clock.nowMillis()
                } catch (_: RuntimeException) {
                    if (state != RawPcapngCaptureState.FAILED) {
                        fail(RawPcapngCaptureFailureReason.CLOCK_UNAVAILABLE)
                    }
                    null
                }
                if (terminalTime == null || terminalTime < 0L) {
                    if (terminalTime != null && state != RawPcapngCaptureState.FAILED) {
                        fail(RawPcapngCaptureFailureReason.INVALID_CLOCK_TIME)
                    }
                    endedAtMillis = null
                } else {
                    endedAtMillis = terminalTime
                }
                completed(this, status())
            }
        }

        private fun fail(reason: RawPcapngCaptureFailureReason) {
            synchronized(stateLock) {
                failureReason = reason
                state = RawPcapngCaptureState.FAILED
                clearQueueAndZeroize()
            }
        }

        private fun writeSectionHeader() = writeBlock(SECTION_HEADER_BLOCK) { out ->
            out.int(PCAPNG_BYTE_ORDER_MAGIC)
            out.short(1)
            out.short(0)
            out.long(-1L)
        }

        private fun writeInterfaceDescription() = writeBlock(INTERFACE_DESCRIPTION_BLOCK) { out ->
            out.short(DLT_RAW)
            out.short(0)
            out.int(limits.perPacketSnaplen)
        }

        private fun writeEnhancedPacket(packet: PendingPacket) {
            try {
                writeBlock(ENHANCED_PACKET_BLOCK, packet.bytes.size) { out ->
                    val timestampMicros = saturatingMillisToMicros(packet.observedAtMillis)
                    out.int(0) // interface id
                    out.int((timestampMicros ushr 32).toInt())
                    out.int(timestampMicros.toInt())
                    out.int(packet.bytes.size)
                    out.int(packet.originalLength)
                    out.bytes(packet.bytes)
                }
                // Count only a complete EPB. A provider failure during its header,
                // body, or trailing length must never be reported as a written packet.
                writtenPackets.incrementAndGet()
            } finally {
                packet.bytes.fill(0)
            }
        }

        private fun writeDecryptionSecrets(block: ByteArray) {
            try {
                writeBlock(DECRYPTION_SECRETS_BLOCK, block.size) { out ->
                    out.int(SECRETS_TYPE_TLS_KEY_LOG)
                    out.int(block.size)
                    out.bytes(block)
                }
                writtenSecretBlocks.incrementAndGet()
            } finally {
                block.fill(0)
            }
        }

        private fun writeBlock(type: Int, payloadBytes: Int = 0, body: (LittleEndianOutput) -> Unit) {
            val paddedPayloadBytes = (payloadBytes + 3) and 3.inv()
            val totalLength = 12 + when (type) {
                SECTION_HEADER_BLOCK -> 16
                INTERFACE_DESCRIPTION_BLOCK -> 8
                ENHANCED_PACKET_BLOCK -> 20 + paddedPayloadBytes
                DECRYPTION_SECRETS_BLOCK -> 8 + paddedPayloadBytes
                else -> error("Unknown PCAPNG block type.")
            }
            check(totalLength.toLong() <= limits.maximumCapturedBytes - writtenFileBytes.get()) {
                "Serialized PCAPNG output reached its configured byte limit."
            }
            val header = ByteArray(8)
            LittleEndianOutput(header).apply {
                int(type)
                int(totalLength)
            }
            output.write(header)
            writtenFileBytes.addAndGet(header.size.toLong())
            val bodyBuffer = ByteArray(totalLength - 12)
            val bodyOut = LittleEndianOutput(bodyBuffer)
            try {
                body(bodyOut)
                output.write(bodyBuffer)
                writtenFileBytes.addAndGet(bodyBuffer.size.toLong())
            } finally {
                bodyBuffer.fill(0)
            }
            val trailer = ByteArray(4)
            LittleEndianOutput(trailer).int(totalLength)
            output.write(trailer)
            writtenFileBytes.addAndGet(trailer.size.toLong())
        }

        private fun clearQueueAndZeroize() {
            while (true) {
                val pending = queue.poll() ?: return
                pending.bytes.fill(0)
            }
        }

    }

    private class LittleEndianOutput(private val destination: ByteArray) {
        private var offset = 0
        fun short(value: Int) {
            destination[offset++] = value.toByte()
            destination[offset++] = (value ushr 8).toByte()
        }
        fun int(value: Int) {
            repeat(4) { index -> destination[offset++] = (value ushr (index * 8)).toByte() }
        }
        fun long(value: Long) {
            repeat(8) { index -> destination[offset++] = (value ushr (index * 8)).toByte() }
        }
        fun bytes(value: ByteArray) {
            value.copyInto(destination, offset)
            offset += value.size
        }
    }

    private companion object {
        const val SECTION_HEADER_BLOCK = 0x0A0D0D0A
        const val INTERFACE_DESCRIPTION_BLOCK = 0x00000001
        const val ENHANCED_PACKET_BLOCK = 0x00000006
        const val DECRYPTION_SECRETS_BLOCK = 0x0000000A

        /** "TLSK" - the NSS key log secrets type Wireshark understands. */
        const val SECRETS_TYPE_TLS_KEY_LOG = 0x544C534B
        const val SECRETS_QUEUE_CAPACITY = 64
        const val MAX_SECRETS_BLOCK_BYTES = 64 * 1_024
        const val PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
        const val DLT_RAW = 101
        const val HEADER_FILE_BYTES = 28 + 20

        private fun serializedSecretsBytes(secretBytes: Int): Int =
            16 + ((secretBytes + 3) and 3.inv())

        private fun serializedEnhancedPacketBytes(capturedBytes: Int): Int =
            32 + ((capturedBytes + 3) and 3.inv())

        private fun saturatingAdd(left: Long, right: Long): Long =
            if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right

        private fun saturatingMillisToMicros(millis: Long): Long =
            if (millis > Long.MAX_VALUE / MICROS_PER_MILLI) Long.MAX_VALUE else millis * MICROS_PER_MILLI

        const val MICROS_PER_MILLI = 1_000L
    }
}

/**
 * Process-wide public integration API. A host calls [start] only after the
 * user chooses a local destination and accepts a raw-packet disclosure. The
 * built-in forwarding data plane calls [offerRawIpPacket] for its IPv4/IPv6
 * TUN path. No packet bytes are retained after the bounded session ends.
 */
object RawPcapngCaptureRuntime {
    private val manager = RawPcapngCaptureManager()

    fun start(output: OutputStream, limits: RawPcapngCaptureLimits = RawPcapngCaptureLimits()): RawPcapngCaptureStartResult =
        manager.start(output, limits)

    fun offerRawIpPacket(packet: ByteArray) {
        manager.offerRawIpPacket(packet)
    }

    fun offerRawIpPacket(packet: ByteArray, observedAtMillis: Long) {
        manager.offerRawIpPacket(packet, observedAtMillis)
    }

    fun offerTlsSecrets(block: ByteArray) = manager.offerTlsSecrets(block)

    fun status(): RawPcapngCaptureStatus = manager.status()

    fun stop() = manager.stop()

    fun awaitStopped(timeoutMillis: Long): Boolean = manager.awaitStopped(timeoutMillis)
}
