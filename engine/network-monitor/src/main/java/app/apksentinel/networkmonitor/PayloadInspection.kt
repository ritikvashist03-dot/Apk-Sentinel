package app.apksentinel.networkmonitor

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.LinkedHashMap
import java.util.Locale
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * A separate, per-session acknowledgement for content inspection.  It is not
 * implied by VPN consent, metadata history, protocol evidence, or raw-PCAPNG
 * export.  A host must collect this acknowledgement from a prominent UI before
 * it supplies an enabled configuration.
 */
data class PayloadInspectionConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120) {
            "A payload-inspection disclosure version is required."
        }
        require(acknowledgedAtMillis > 0L) { "A payload-inspection acknowledgement time must be positive." }
    }
}

/**
 * Explicit configuration for a deliberately narrow, in-memory-only view of
 * likely cleartext transport payloads.  This never authorizes TLS decryption,
 * TCP/UDP reassembly, disk persistence, export, or remote upload.
 */
data class PayloadInspectionConfiguration(
    val enabled: Boolean = false,
    val consent: PayloadInspectionConsent? = null,
    val maximumSessionBytes: Int = 1 * 1_024 * 1_024,
    val maximumBytesPerFlow: Int = 16 * 1_024,
    val maximumRecords: Int = 128,
    val maximumBytesPerRecord: Int = 4 * 1_024,
    val maximumDurationMillis: Long = 5 * 60 * 1_000L,
    val ingressQueueCapacity: Int = 64,
) {
    init {
        require(!enabled || consent != null) { "Enabled payload inspection requires separate session consent." }
        require(maximumSessionBytes in 4 * 1_024..4 * 1_024 * 1_024) { "Session payload bound is outside the supported range." }
        require(maximumBytesPerFlow in 1 * 1_024..256 * 1_024) { "Per-flow payload bound is outside the supported range." }
        require(maximumBytesPerFlow <= maximumSessionBytes) { "Per-flow payload bound cannot exceed session payload bound." }
        require(maximumRecords in 1..512) { "Payload record count is outside the supported range." }
        require(maximumBytesPerRecord in 256..16 * 1_024) { "Per-record payload bound is outside the supported range." }
        require(maximumDurationMillis in 5_000L..30 * 60 * 1_000L) { "Payload duration is outside the supported range." }
        require(ingressQueueCapacity in 1..256) { "Payload ingress queue is outside the supported range." }
    }

    val isActive: Boolean get() = enabled && consent != null
}

enum class PayloadInspectionState { DISABLED, RUNNING, STOPPED, EXPIRED, FAILED }

/** Stable reason codes only; exception text never crosses the engine boundary. */
enum class PayloadInspectionFailureReason { CLOCK_UNAVAILABLE, INVALID_CLOCK_TIME, WORKER_START_FAILED, WORKER_INTERRUPTED, WORKER_RUNTIME_FAILURE }

enum class PayloadInspectionDropReason {
    NOT_PLAINTEXT_OR_ENCRYPTED,
    INGRESS_QUEUE_FULL,
    RECORD_LIMIT_REACHED,
    SESSION_BYTE_LIMIT_REACHED,
    FLOW_BYTE_LIMIT_REACHED,
    DURATION_EXPIRED,
    RECORD_TRUNCATED,
}

enum class PayloadInspectionTransport { TCP, UDP }

enum class PayloadInspectionLimitation {
    DISABLED_BY_SESSION,
    CONTENT_HIDDEN_UNTIL_REVEAL,
    NO_TLS_DECRYPTION,
    NO_REASSEMBLY,
    LIKELY_PLAINTEXT_ONLY,
    REDACTION_BEST_EFFORT,
    NO_DISK_OR_EXPORT,
    MALFORMED_UTF8_REDACTED,
}

enum class PayloadRenderFormat { TEXT, HEX }

/** Metadata only. The redacted content remains private to the collector until a reveal token is used. */
data class PayloadInspectionRecord(
    val id: Long,
    val direction: PacketDirection,
    val transport: PayloadInspectionTransport,
    val observedAtMillis: Long,
    val observedBytes: Int,
    val retainedBytes: Int,
    val wasTruncated: Boolean,
    val redactionApplied: Boolean,
    val malformedUtf8WasRedacted: Boolean,
) {
    init {
        require(id > 0L && observedAtMillis >= 0L && observedBytes >= 0 && retainedBytes >= 0) {
            "Payload record metadata is invalid."
        }
    }
}

data class PayloadInspectionSnapshot(
    val state: PayloadInspectionState = PayloadInspectionState.DISABLED,
    val enabledForSession: Boolean = false,
    val startedAtMillis: Long? = null,
    val retainedBytes: Long = 0L,
    val acceptedRecords: Long = 0L,
    val records: List<PayloadInspectionRecord> = emptyList(),
    val drops: Map<PayloadInspectionDropReason, Long> = emptyMap(),
    val failureReason: PayloadInspectionFailureReason? = null,
    val limitations: Set<PayloadInspectionLimitation> = setOf(PayloadInspectionLimitation.DISABLED_BY_SESSION),
) {
    init {
        require(retainedBytes >= 0L && acceptedRecords >= 0L) { "Payload inspection counters cannot be negative." }
        require(enabledForSession || PayloadInspectionLimitation.DISABLED_BY_SESSION in limitations) {
            "Disabled payload inspection must be explicit."
        }
    }
}

/** A second acknowledgement is required immediately before the host renders retained content. */
data class PayloadRevealAcknowledgement(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120) { "A reveal disclosure version is required." }
        require(acknowledgedAtMillis > 0L) { "A reveal acknowledgement time must be positive." }
    }
}

/** Opaque, session-local capability; callers cannot construct a valid token. */
class PayloadRevealToken internal constructor(internal val secret: Long)

data class RenderedPayloadContent(
    val recordId: Long,
    val format: PayloadRenderFormat,
    val content: String,
    val redactionApplied: Boolean,
    val limitations: Set<PayloadInspectionLimitation>,
)

/**
 * Bounded asynchronous collector. [offer] performs only a bounded copy and a
 * non-blocking queue offer on a forwarding thread. Classification, redaction,
 * record mutation, and text/hex rendering are outside the packet path.
 */
internal class BoundedPayloadInspectionCollector(
    private val configuration: PayloadInspectionConfiguration,
    private val clock: EpochClock = SystemEpochClock,
) {
    private val lock = Any()
    private val running = AtomicBoolean(configuration.isActive)
    private val queue = ArrayBlockingQueue<Candidate>(configuration.ingressQueueCapacity)
    private val drops = PayloadDropCounters()
    private val records = ArrayDeque<StoredPayload>()
    private val flowBytes = LinkedHashMap<PayloadFlowKey, Int>()
    private var revealSecret = SecureRandom().nextLong()
    private var state = if (configuration.isActive) PayloadInspectionState.RUNNING else PayloadInspectionState.DISABLED
    private var failureReason: PayloadInspectionFailureReason? = null
    private var startedAtMillis: Long? = null
    private var retainedBytes = 0L
    private var acceptedRecords = 0L
    private var nextId = 1L
    private val worker: Thread?

    init {
        if (!configuration.isActive) {
            worker = null
        } else {
            val now = safeNow()
            if (now == null) {
                state = PayloadInspectionState.FAILED
                failureReason = PayloadInspectionFailureReason.CLOCK_UNAVAILABLE
                running.set(false)
                worker = null
            } else if (now < 0L) {
                state = PayloadInspectionState.FAILED
                failureReason = PayloadInspectionFailureReason.INVALID_CLOCK_TIME
                running.set(false)
                worker = null
            } else {
                startedAtMillis = now
                worker = try {
                    thread(start = true, isDaemon = true, name = "apk-sentinel-payload-inspection") { workerLoop() }
                } catch (_: RuntimeException) {
                    state = PayloadInspectionState.FAILED
                    failureReason = PayloadInspectionFailureReason.WORKER_START_FAILED
                    running.set(false)
                    null
                }
            }
        }
    }

    /** Never blocks or retains the caller's byte array. */
    fun offer(
        flow: PayloadFlowKey,
        direction: PacketDirection,
        transport: PayloadInspectionTransport,
        payload: ByteArray,
        observedAtMillis: Long,
    ) {
        if (!running.get() || payload.isEmpty() || observedAtMillis < 0L) return
        if (!LikelyPlaintextPayload.isLikelyPlaintext(payload)) {
            drops.increment(PayloadInspectionDropReason.NOT_PLAINTEXT_OR_ENCRYPTED)
            return
        }
        val retainedLength = minOf(payload.size, configuration.maximumBytesPerRecord)
        val copied = payload.copyOfRange(0, retainedLength)
        val candidate = Candidate(flow, direction, transport, observedAtMillis, payload.size, copied, payload.size > retainedLength)
        if (!queue.offer(candidate)) {
            candidate.zeroize()
            drops.increment(PayloadInspectionDropReason.INGRESS_QUEUE_FULL)
        }
    }

    fun snapshot(): PayloadInspectionSnapshot = synchronized(lock) {
        PayloadInspectionSnapshot(
            state = state,
            enabledForSession = configuration.isActive,
            startedAtMillis = startedAtMillis,
            retainedBytes = retainedBytes,
            acceptedRecords = acceptedRecords,
            records = records.map { it.summary },
            drops = drops.snapshot(),
            failureReason = failureReason,
            limitations = limitationsForSnapshot(),
        )
    }

    /** Hosts call this only after a separate in-screen reveal acknowledgement. */
    fun issueRevealToken(acknowledgement: PayloadRevealAcknowledgement): PayloadRevealToken? {
        if (!running.get() || acknowledgement.disclosureVersion.isBlank()) return null
        return PayloadRevealToken(revealSecret)
    }

    fun render(recordId: Long, token: PayloadRevealToken, format: PayloadRenderFormat): RenderedPayloadContent? = synchronized(lock) {
        if (!running.get() || token.secret != revealSecret) return null
        val record = records.firstOrNull { it.summary.id == recordId } ?: return null
        val content = when (format) {
            PayloadRenderFormat.TEXT -> String(record.bytes, StandardCharsets.UTF_8)
            PayloadRenderFormat.HEX -> record.bytes.toSpacedHex()
        }
        RenderedPayloadContent(
            recordId = record.summary.id,
            format = format,
            content = content,
            redactionApplied = record.summary.redactionApplied,
            limitations = record.limitations,
        )
    }

    /** Revokes every previously issued reveal token without retaining more data. */
    fun revokeRevealTokens() = synchronized(lock) {
        revealSecret = SecureRandom().nextLong()
    }

    /** Zeroizes queued and retained bytes. Safe to call more than once. */
    fun stopAndClear() {
        running.set(false)
        worker?.interrupt()
        synchronized(lock) {
            state = if (state == PayloadInspectionState.RUNNING) PayloadInspectionState.STOPPED else state
            clearLocked()
        }
        drainQueueAndZeroize()
    }

    private fun workerLoop() {
        try {
            while (running.get()) {
                if (hasExpired()) {
                    expire()
                    return
                }
                val candidate = try {
                    queue.poll(200L, java.util.concurrent.TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    return
                } ?: continue
                try {
                    store(candidate)
                } finally {
                    candidate.zeroize()
                }
            }
        } catch (_: RuntimeException) {
            synchronized(lock) {
                if (state == PayloadInspectionState.RUNNING) {
                    state = PayloadInspectionState.FAILED
                    failureReason = PayloadInspectionFailureReason.WORKER_RUNTIME_FAILURE
                    clearLocked()
                }
            }
            running.set(false)
            drainQueueAndZeroize()
        } finally {
            drainQueueAndZeroize()
        }
    }

    private fun store(candidate: Candidate) {
        synchronized(lock) {
            if (!running.get() || state != PayloadInspectionState.RUNNING) return
            if (hasExpiredLocked()) {
                expireLocked()
                return
            }
            if (records.size >= configuration.maximumRecords) {
                drops.increment(PayloadInspectionDropReason.RECORD_LIMIT_REACHED)
                return
            }
            val flowRetained = flowBytes[candidate.flow] ?: 0
            if (flowRetained >= configuration.maximumBytesPerFlow) {
                drops.increment(PayloadInspectionDropReason.FLOW_BYTE_LIMIT_REACHED)
                return
            }
            val availableForFlow = configuration.maximumBytesPerFlow - flowRetained
            val availableForSession = (configuration.maximumSessionBytes.toLong() - retainedBytes).coerceAtLeast(0L).toInt()
            val keep = minOf(candidate.bytes.size, availableForFlow, availableForSession)
            if (keep <= 0) {
                drops.increment(if (availableForSession <= 0) PayloadInspectionDropReason.SESSION_BYTE_LIMIT_REACHED else PayloadInspectionDropReason.FLOW_BYTE_LIMIT_REACHED)
                return
            }
            val source = candidate.bytes.copyOf(keep)
            val sanitized = PayloadRedactor.sanitize(source, maximumOutputBytes = keep)
            source.fill(0)
            if (candidate.truncated || keep < candidate.bytes.size) drops.increment(PayloadInspectionDropReason.RECORD_TRUNCATED)
            val summary = PayloadInspectionRecord(
                id = nextId++,
                direction = candidate.direction,
                transport = candidate.transport,
                observedAtMillis = candidate.observedAtMillis,
                observedBytes = candidate.observedBytes,
                retainedBytes = sanitized.bytes.size,
                wasTruncated = candidate.truncated || keep < candidate.bytes.size,
                redactionApplied = sanitized.redactionApplied,
                malformedUtf8WasRedacted = sanitized.malformedUtf8,
            )
            records.addLast(StoredPayload(summary, sanitized.bytes, sanitized.limitations))
            flowBytes[candidate.flow] = flowRetained + sanitized.bytes.size
            retainedBytes += sanitized.bytes.size.toLong()
            acceptedRecords = payloadSaturatingIncrement(acceptedRecords)
        }
    }

    private fun hasExpired(): Boolean = synchronized(lock) { hasExpiredLocked() }

    private fun hasExpiredLocked(): Boolean {
        val start = startedAtMillis ?: return false
        val now = safeNow()
        if (now == null) {
            failLocked(PayloadInspectionFailureReason.CLOCK_UNAVAILABLE)
            return true
        }
        if (now < start) {
            failLocked(PayloadInspectionFailureReason.INVALID_CLOCK_TIME)
            return true
        }
        return now - start >= configuration.maximumDurationMillis
    }

    private fun expire() = synchronized(lock) { expireLocked() }

    private fun expireLocked() {
        if (state != PayloadInspectionState.RUNNING) return
        state = PayloadInspectionState.EXPIRED
        running.set(false)
        drops.increment(PayloadInspectionDropReason.DURATION_EXPIRED)
        clearLocked()
    }

    private fun failLocked(reason: PayloadInspectionFailureReason) {
        if (state != PayloadInspectionState.RUNNING) return
        state = PayloadInspectionState.FAILED
        failureReason = reason
        running.set(false)
        clearLocked()
    }

    private fun safeNow(): Long? = try {
        clock.nowMillis()
    } catch (_: RuntimeException) {
        null
    }

    private fun limitationsForSnapshot(): Set<PayloadInspectionLimitation> = buildSet {
        if (!configuration.isActive) add(PayloadInspectionLimitation.DISABLED_BY_SESSION)
        add(PayloadInspectionLimitation.CONTENT_HIDDEN_UNTIL_REVEAL)
        add(PayloadInspectionLimitation.NO_TLS_DECRYPTION)
        add(PayloadInspectionLimitation.NO_REASSEMBLY)
        add(PayloadInspectionLimitation.LIKELY_PLAINTEXT_ONLY)
        add(PayloadInspectionLimitation.REDACTION_BEST_EFFORT)
        add(PayloadInspectionLimitation.NO_DISK_OR_EXPORT)
        if (records.any { it.summary.malformedUtf8WasRedacted }) add(PayloadInspectionLimitation.MALFORMED_UTF8_REDACTED)
    }

    private fun clearLocked() {
        records.forEach { it.zeroize() }
        records.clear()
        flowBytes.clear()
        retainedBytes = 0L
    }

    private fun drainQueueAndZeroize() {
        while (true) {
            val candidate = queue.poll() ?: return
            candidate.zeroize()
        }
    }

    private data class Candidate(
        val flow: PayloadFlowKey,
        val direction: PacketDirection,
        val transport: PayloadInspectionTransport,
        val observedAtMillis: Long,
        val observedBytes: Int,
        val bytes: ByteArray,
        val truncated: Boolean,
    ) {
        fun zeroize() = bytes.fill(0)
    }

    private data class StoredPayload(
        val summary: PayloadInspectionRecord,
        val bytes: ByteArray,
        val limitations: Set<PayloadInspectionLimitation>,
    ) {
        fun zeroize() = bytes.fill(0)
    }
}

/** Internal only; endpoint values never appear in a public payload-inspection result. */
internal data class PayloadFlowKey(
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String,
    val destinationPort: Int,
    val transport: PayloadInspectionTransport,
)

private class PayloadDropCounters {
    private val values = PayloadInspectionDropReason.entries.associateWith { AtomicLong(0L) }

    fun increment(reason: PayloadInspectionDropReason) {
        val value = values.getValue(reason)
        while (true) {
            val old = value.get()
            if (old == Long.MAX_VALUE || value.compareAndSet(old, old + 1L)) return
        }
    }

    fun snapshot(): Map<PayloadInspectionDropReason, Long> = values.mapValues { it.value.get() }.filterValues { it > 0L }
}

/** Conservative classifier: opaque/binary and TLS-shaped bytes are never retained. */
private object LikelyPlaintextPayload {
    fun isLikelyPlaintext(bytes: ByteArray): Boolean {
        if (bytes.isEmpty() || looksLikeTlsRecord(bytes)) return false
        val sample = minOf(bytes.size, 4 * 1_024)
        var printable = 0
        for (index in 0 until sample) {
            val value = bytes[index].toInt() and 0xff
            when {
                value in 0x20..0x7e || value == '\n'.code || value == '\r'.code || value == '\t'.code -> printable++
            }
        }
        return printable * 100 >= sample * 85
    }

    private fun looksLikeTlsRecord(bytes: ByteArray): Boolean =
        bytes.size >= 5 && (bytes[0].toInt() and 0xff) in 20..23 &&
            (bytes[1].toInt() and 0xff) == 3 && (bytes[2].toInt() and 0xff) in 0..4
}

private object PayloadRedactor {
    private val sensitiveHeader = Regex(
        "(?im)^(\\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|[a-z0-9-]*(?:token|secret|password|credential|api[-_]?key)[a-z0-9-]*)\\s*:)\\s*[^\\r\\n]*",
    )
    private val queryOrFormSecret = Regex(
        "(?im)([?&;]|^)([a-z0-9_.-]*(?:token|secret|password|credential|api[-_]?key|auth)[a-z0-9_.-]*)=([^&#;\\r\\n\\s]*)",
    )
    private val bearerValue = Regex("(?i)\\b(bearer|basic)\\s+[a-z0-9._~+/=-]+")

    fun sanitize(bytes: ByteArray, maximumOutputBytes: Int): SanitizedPayload {
        require(maximumOutputBytes > 0) { "Payload output bound must be positive." }
        val decoded = decodeStrictly(bytes)
        if (decoded == null) {
            val placeholder = "[invalid UTF-8 payload redacted]".truncateUtf8(maximumOutputBytes)
            return SanitizedPayload(
                bytes = placeholder.toByteArray(StandardCharsets.UTF_8),
                redactionApplied = true,
                malformedUtf8 = true,
                limitations = setOf(
                    PayloadInspectionLimitation.MALFORMED_UTF8_REDACTED,
                    PayloadInspectionLimitation.REDACTION_BEST_EFFORT,
                ),
            )
        }
        val neutralized = neutralizeControls(decoded)
        var redacted = sensitiveHeader.replace(neutralized) { match -> "${match.groupValues[1]} [REDACTED]" }
        redacted = queryOrFormSecret.replace(redacted) { match -> "${match.groupValues[1]}${match.groupValues[2]}=[REDACTED]" }
        redacted = bearerValue.replace(redacted) { match -> "${match.groupValues[1]} [REDACTED]" }
        val content = redacted.take(MAX_RENDERED_TEXT_CHARS).truncateUtf8(maximumOutputBytes)
        return SanitizedPayload(
            bytes = content.toByteArray(StandardCharsets.UTF_8),
            redactionApplied = content != decoded,
            malformedUtf8 = false,
            limitations = setOf(PayloadInspectionLimitation.REDACTION_BEST_EFFORT),
        )
    }

    private fun decodeStrictly(bytes: ByteArray): String? = try {
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        decoder.decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: CharacterCodingException) {
        null
    }

    private fun neutralizeControls(value: String): String = buildString(value.length) {
        value.forEach { char ->
            when {
                char == '\n' || char == '\r' || char == '\t' -> append(char)
                char.isISOControl() || char in BIDI_CONTROLS -> append('\uFFFD')
                else -> append(char)
            }
        }
    }

    private val BIDI_CONTROLS = setOf(
        '\u061C', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069',
    )
    private const val MAX_RENDERED_TEXT_CHARS = 16 * 1_024
}

private fun String.truncateUtf8(maximumBytes: Int): String {
    if (toByteArray(StandardCharsets.UTF_8).size <= maximumBytes) return this
    val output = StringBuilder()
    var used = 0
    for (codePoint in codePoints().toArray()) {
        val characters = String(Character.toChars(codePoint))
        val bytes = characters.toByteArray(StandardCharsets.UTF_8).size
        if (used + bytes > maximumBytes) break
        output.append(characters)
        used += bytes
    }
    return output.toString()
}

private data class SanitizedPayload(
    val bytes: ByteArray,
    val redactionApplied: Boolean,
    val malformedUtf8: Boolean,
    val limitations: Set<PayloadInspectionLimitation>,
)

private fun ByteArray.toSpacedHex(): String = joinToString(separator = " ") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xff) }

private fun payloadSaturatingIncrement(value: Long): Long = if (value == Long.MAX_VALUE) value else value + 1L
