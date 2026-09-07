package app.apksentinel.engine.rootcapture

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** The host owns this boundary; no capability check is allowed without an explicit consent object. */
interface RootCapturePrivilegeRunner {
    fun rootAvailability(): RootCaptureRootAvailability
    fun commandAvailability(command: RootCaptureCommand): RootCaptureCommandAvailability
    fun start(command: RootCaptureCommand): RootCaptureProcessLaunch
}

enum class RootCaptureRootAvailability { AVAILABLE, SU_UNAVAILABLE, ACCESS_DENIED, PROBE_FAILED }
enum class RootCaptureCommandAvailability { AVAILABLE, UNAVAILABLE, PROBE_FAILED }

sealed interface RootCaptureProcessLaunch {
    data class Started(val process: RootCaptureRunningProcess) : RootCaptureProcessLaunch
    data object Rejected : RootCaptureProcessLaunch
}

interface RootCaptureRunningProcess {
    fun stdout(): InputStream?
    fun stop()
    fun setTerminationListener(listener: (RootCaptureProcessTermination) -> Unit)
}

enum class RootCaptureProcessTermination { EXITED, DIED }

interface RootCaptureOutputStore {
    fun create(sessionId: String): RootCaptureOutputCreate
    fun erase(sessionId: String): Boolean
    fun eraseAll(): Boolean
    fun copyTo(sessionId: String, destination: OutputStream, maximumBytes: Long): Boolean
}

sealed interface RootCaptureOutputCreate {
    data class Ready(val stream: OutputStream) : RootCaptureOutputCreate
    data object Unavailable : RootCaptureOutputCreate
}

interface RootCaptureScheduledTask { fun cancel() }

interface RootCaptureScheduler {
    fun once(delayMillis: Long, action: () -> Unit): RootCaptureScheduledTask
    fun repeating(intervalMillis: Long, action: () -> Unit): RootCaptureScheduledTask
}

interface RootCapturePumpExecutor { fun execute(action: () -> Unit) }

/** Default process-local runtime. An integrating service must call [shutdown] when it is permanently destroyed. */
class ExecutorRootCaptureRuntime : RootCaptureScheduler, RootCapturePumpExecutor {
    private val scheduler = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "apk-sentinel-root-capture").apply { isDaemon = true }
    }
    private val pump = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "apk-sentinel-root-capture-pump").apply { isDaemon = true }
    }

    override fun once(delayMillis: Long, action: () -> Unit): RootCaptureScheduledTask =
        ScheduledTask(scheduler.schedule(action, delayMillis, TimeUnit.MILLISECONDS))

    override fun repeating(intervalMillis: Long, action: () -> Unit): RootCaptureScheduledTask =
        ScheduledTask(scheduler.scheduleAtFixedRate(action, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS))

    override fun execute(action: () -> Unit) { pump.execute(action) }

    fun shutdown() {
        scheduler.shutdownNow()
        pump.shutdownNow()
    }

    private class ScheduledTask(private val future: ScheduledFuture<*>) : RootCaptureScheduledTask {
        override fun cancel() { future.cancel(false) }
    }
}

internal sealed interface RootCapturePumpResult {
    data class Complete(val bytes: Long, val packets: Int = 0) : RootCapturePumpResult
    /** A valid PCAP prefix ending at a complete-record boundary. */
    data class ByteCap(val bytes: Long, val packets: Int = 0, val truncated: Boolean = true) : RootCapturePumpResult
    data class PacketCap(val bytes: Long, val packets: Int) : RootCapturePumpResult
    data object Failed : RootCapturePumpResult
}

/** Copies complete records directly from the privileged pipe with a bounded, zeroized record buffer. */
internal object RootCaptureBoundedOutputPump {
    /**
     * Copies only complete libpcap records. Neither stream is closed here: the
     * caller owns both streams and decides their lifetime. [onProgress] is
     * called after each accepted write so a controller can expose truthful
     * counters while a capture is still active.
     */
    fun copy(
        input: InputStream,
        output: OutputStream,
        maximumBytes: Long,
        maximumPackets: Int = Int.MAX_VALUE,
        snapLengthBytes: Int = 96,
        onProgress: (bytes: Long, packets: Int) -> Unit = { _, _ -> },
    ): RootCapturePumpResult {
        if (snapLengthBytes !in 96..RootCaptureLimits.MAX_SNAP_LENGTH_BYTES) {
            return RootCapturePumpResult.Failed
        }
        val globalHeader = ByteArray(24)
        val packetHeader = ByteArray(16)
        val packet = ByteArray(snapLengthBytes)
        return try {
            copyRecords(
                source = input,
                sink = output,
                maximumBytes = maximumBytes,
                maximumPackets = maximumPackets,
                snapLengthBytes = packet.size,
                globalHeader = globalHeader,
                packetHeader = packetHeader,
                packet = packet,
                onProgress = onProgress,
            )
        } catch (_: Exception) {
            RootCapturePumpResult.Failed
        } finally {
            globalHeader.fill(0)
            packetHeader.fill(0)
            packet.fill(0)
        }
    }

    private fun copyRecords(
        source: InputStream,
        sink: OutputStream,
        maximumBytes: Long,
        maximumPackets: Int,
        snapLengthBytes: Int,
        globalHeader: ByteArray,
        packetHeader: ByteArray,
        packet: ByteArray,
        onProgress: (bytes: Long, packets: Int) -> Unit,
    ): RootCapturePumpResult {
        if (!source.readFully(globalHeader)) return RootCapturePumpResult.Failed
        val byteOrder = PcapByteOrder.fromGlobalHeader(globalHeader) ?: return RootCapturePumpResult.Failed
        // A PCAP without its global header is never exportable. Public limits
        // are much larger, but fail closed for direct pure callers too.
        if (globalHeader.size.toLong() > maximumBytes) return RootCapturePumpResult.Failed
        sink.write(globalHeader)
        onProgress(globalHeader.size.toLong(), 0)
        var copied = globalHeader.size.toLong()
        var packets = 0
        if (maximumPackets <= 0) return RootCapturePumpResult.PacketCap(copied, packets)
        while (true) {
            when (source.readFullyOrEnd(packetHeader)) {
                ReadHeader.END -> return RootCapturePumpResult.Complete(copied, packets)
                ReadHeader.PARTIAL -> return RootCapturePumpResult.Failed
                ReadHeader.FULL -> Unit
            }
            val capturedLength = byteOrder.unsignedIntAt(packetHeader, 8)
            if (capturedLength !in 0L..packet.size.toLong()) return RootCapturePumpResult.Failed
            val originalLength = byteOrder.unsignedIntAt(packetHeader, 12)
            if (originalLength < capturedLength) return RootCapturePumpResult.Failed
            val recordBytes = packetHeader.size.toLong() + capturedLength
            if (recordBytes > maximumBytes - copied) return RootCapturePumpResult.ByteCap(copied, packets)
            val captured = capturedLength.toInt()
            if (!source.readFully(packet, captured)) return RootCapturePumpResult.Failed
            val nextSize = copied + recordBytes
            sink.write(packetHeader)
            sink.write(packet, 0, captured)
            copied = nextSize
            packets += 1
            onProgress(copied, packets)
            if (packets >= maximumPackets) return RootCapturePumpResult.PacketCap(copied, packets)
        }
    }

    private enum class ReadHeader { FULL, END, PARTIAL }

    private fun InputStream.readFully(target: ByteArray, length: Int = target.size): Boolean {
        var offset = 0
        var emptyReads = 0
        while (offset < length) {
            val read = read(target, offset, length - offset)
            if (read < 0) return false
            if (read == 0) {
                if (++emptyReads > MAX_EMPTY_READS) return false
                val single = read()
                if (single < 0) return false
                target[offset++] = single.toByte()
                emptyReads = 0
            } else {
                emptyReads = 0
                offset += read
            }
        }
        return true
    }

    private fun InputStream.readFullyOrEnd(target: ByteArray): ReadHeader {
        var offset = 0
        var emptyReads = 0
        while (offset < target.size) {
            val read = read(target, offset, target.size - offset)
            if (read < 0) return if (offset == 0) ReadHeader.END else ReadHeader.PARTIAL
            if (read == 0) {
                if (++emptyReads > MAX_EMPTY_READS) return ReadHeader.PARTIAL
                val single = read()
                if (single < 0) return if (offset == 0) ReadHeader.END else ReadHeader.PARTIAL
                target[offset++] = single.toByte()
                emptyReads = 0
            } else {
                emptyReads = 0
                offset += read
            }
        }
        return ReadHeader.FULL
    }

    private enum class PcapByteOrder {
        LITTLE,
        BIG;

        fun unsignedIntAt(bytes: ByteArray, offset: Int): Long = when (this) {
            LITTLE -> (bytes[offset].toLong() and 0xffL) or
                ((bytes[offset + 1].toLong() and 0xffL) shl 8) or
                ((bytes[offset + 2].toLong() and 0xffL) shl 16) or
                ((bytes[offset + 3].toLong() and 0xffL) shl 24)
            BIG -> ((bytes[offset].toLong() and 0xffL) shl 24) or
                ((bytes[offset + 1].toLong() and 0xffL) shl 16) or
                ((bytes[offset + 2].toLong() and 0xffL) shl 8) or
                (bytes[offset + 3].toLong() and 0xffL)
        }

        companion object {
            fun fromGlobalHeader(header: ByteArray): PcapByteOrder? = when (
                header.take(4).map { it.toInt() and 0xff }
            ) {
                listOf(0xd4, 0xc3, 0xb2, 0xa1), listOf(0x4d, 0x3c, 0xb2, 0xa1) -> LITTLE
                listOf(0xa1, 0xb2, 0xc3, 0xd4), listOf(0xa1, 0xb2, 0x3c, 0x4d) -> BIG
                else -> null
            }
        }
    }

    private const val MAX_EMPTY_READS = 4
}
