package app.apksentinel.engine.tlsinspection

import java.io.OutputStream
import java.nio.charset.StandardCharsets

/** A fresh acknowledgement, required before any decrypted content is retained at all. */
data class DecryptedSessionConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank()) { "A decrypted-session disclosure version is required." }
        require(acknowledgedAtMillis > 0L) { "A decrypted-session acknowledgement time must be positive." }
    }
}

/**
 * Opt-in settings for retaining decrypted TLS content.
 *
 * Off by default. This is the most sensitive switch in the product: with it on, the app
 * holds readable content from HTTPS sessions it decrypted. It is bounded, memory-only, and
 * cleared on stop. Every bound below exists so a long session cannot quietly become an
 * unbounded transcript of someone's browsing.
 */
data class DecryptedSessionConfiguration(
    val enabled: Boolean = false,
    val consent: DecryptedSessionConsent? = null,
    val maximumSegments: Int = 256,
    val maximumTotalBytes: Int = 512 * 1_024,
    val maximumSegmentBytes: Int = 16 * 1_024,
) {
    init {
        require(!enabled || consent != null) { "Retaining decrypted content requires separate session consent." }
        require(maximumSegments in 1..4_096) { "Segment count bound is out of range." }
        require(maximumTotalBytes in 1_024..8 * 1_024 * 1_024) { "Total byte bound is out of range." }
        require(maximumSegmentBytes in 256..1_024 * 1_024) { "Per-segment bound is out of range." }
    }

    val isActive: Boolean get() = enabled && consent != null
}

/** One retained slice of decrypted content. */
class DecryptedSessionSegment(
    val direction: TlsInspectionPlaintextDirection,
    val observedAtMillis: Long,
    val bytes: ByteArray,
    val truncated: Boolean,
)

data class DecryptedSessionSnapshot(
    val enabledForSession: Boolean = false,
    val segmentCount: Int = 0,
    val retainedBytes: Int = 0,
    val droppedSegments: Long = 0L,
)

/**
 * Retains a bounded amount of decrypted TLS content so the user can export the session
 * they deliberately decrypted.
 *
 * The bridge hands plaintext to its consumer and zeroizes the segment as soon as the
 * callback returns, which is exactly why decrypted-session export did not exist: nothing
 * was kept long enough to write anywhere. This copies inside the callback — the only point
 * at which those bytes are valid — and keeps the copy under explicit bounds.
 *
 * Memory only. Nothing reaches disk unless the user picks a destination, and [clear]
 * zeroizes every retained buffer rather than just dropping references.
 */
class DecryptedSessionRecorder(
    private val configuration: DecryptedSessionConfiguration = DecryptedSessionConfiguration(),
) {
    private val lock = Any()
    private val segments = ArrayDeque<DecryptedSessionSegment>()
    private var retainedBytes = 0
    private var dropped = 0L

    /**
     * Copies the segment. Must be called from inside the bridge's plaintext callback, while
     * the segment is still valid.
     */
    fun record(
        direction: TlsInspectionPlaintextDirection,
        segment: EphemeralTlsDecryptedSegment,
        observedAtMillis: Long,
    ) {
        if (!configuration.isActive || segment.size <= 0 || observedAtMillis < 0L) return
        val available = segment.size
        val keep = minOf(available, configuration.maximumSegmentBytes)
        if (keep > configuration.maximumTotalBytes) return
        val copy = ByteArray(keep)
        segment.useReadOnlyBytes { buffer -> buffer.get(copy, 0, keep) }
        synchronized(lock) {
            while (
                segments.isNotEmpty() &&
                (segments.size >= configuration.maximumSegments ||
                    retainedBytes + keep > configuration.maximumTotalBytes)
            ) {
                val evicted = segments.removeFirst()
                retainedBytes -= evicted.bytes.size
                evicted.bytes.fill(0)
                dropped = saturatingIncrement(dropped)
            }
            segments.addLast(
                DecryptedSessionSegment(
                    direction = direction,
                    observedAtMillis = observedAtMillis,
                    bytes = copy,
                    truncated = keep < available,
                ),
            )
            retainedBytes += keep
        }
    }

    fun snapshot(): DecryptedSessionSnapshot = synchronized(lock) {
        DecryptedSessionSnapshot(
            enabledForSession = configuration.isActive,
            segmentCount = segments.size,
            retainedBytes = retainedBytes,
            droppedSegments = dropped,
        )
    }

    /**
     * Writes the retained session to [output] as a direction-labelled transcript.
     *
     * Deliberately NOT a PCAP: the recorder holds application plaintext, not framed
     * packets, and emitting a capture container would imply packet-level fidelity that was
     * never captured. Returns the number of bytes written.
     */
    fun exportTo(output: OutputStream): Long {
        var written = 0L
        fun emit(text: String) {
            val encoded = text.toByteArray(StandardCharsets.UTF_8)
            output.write(encoded)
            written += encoded.size
        }
        val retained: List<DecryptedSessionSegment>
        val stats: DecryptedSessionSnapshot
        synchronized(lock) {
            retained = segments.toList()
            stats = DecryptedSessionSnapshot(
                enabledForSession = configuration.isActive,
                segmentCount = segments.size,
                retainedBytes = retainedBytes,
                droppedSegments = dropped,
            )
        }
        emit("# APK Sentinel decrypted session transcript\n")
        emit("# Application plaintext only. This is not a packet capture and is not replayable.\n")
        emit("# segments=${stats.segmentCount} bytes=${stats.retainedBytes} dropped=${stats.droppedSegments}\n")
        retained.forEach { segment ->
            val note = if (segment.truncated) " (truncated)" else ""
            emit("\n--- ${segment.direction.name} at ${segment.observedAtMillis}$note ---\n")
            output.write(segment.bytes)
            written += segment.bytes.size
        }
        output.flush()
        return written
    }

    /** Zeroizes every retained buffer. Call on stop, disposal, and user erase. */
    fun clear() = synchronized(lock) {
        segments.forEach { it.bytes.fill(0) }
        segments.clear()
        retainedBytes = 0
        dropped = 0L
    }

    private fun saturatingIncrement(value: Long): Long = if (value == Long.MAX_VALUE) value else value + 1
}
