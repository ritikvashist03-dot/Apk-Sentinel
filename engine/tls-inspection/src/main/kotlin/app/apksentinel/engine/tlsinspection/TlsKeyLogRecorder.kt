package app.apksentinel.engine.tlsinspection

import java.io.OutputStream
import java.nio.charset.StandardCharsets

/** A fresh acknowledgement, required before any TLS secret is retained at all. */
data class TlsKeyLogConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank()) { "A key-log disclosure version is required." }
        require(acknowledgedAtMillis > 0L) { "A key-log acknowledgement time must be positive." }
    }
}

/**
 * Opt-in settings for retaining TLS secrets.
 *
 * Off by default. A key log is the single most sensitive artefact this product can produce:
 * anyone holding it plus the matching capture can read the traffic, and unlike a decrypted
 * transcript it stays useful for as long as the capture exists.
 */
data class TlsKeyLogConfiguration(
    val enabled: Boolean = false,
    val consent: TlsKeyLogConsent? = null,
    val maximumLines: Int = 4_096,
) {
    init {
        require(!enabled || consent != null) { "Retaining TLS secrets requires separate key-log consent." }
        require(maximumLines in 1..65_536) { "Key-log line bound is out of range." }
    }

    val isActive: Boolean get() = enabled && consent != null
}

data class TlsKeyLogSnapshot(
    val enabledForSession: Boolean = false,
    val lineCount: Int = 0,
    val droppedLines: Long = 0L,
)

/**
 * Retains the TLS secrets captured from legs this app terminated, so the user can decrypt
 * the capture they deliberately made.
 *
 * Secrets are held as bytes rather than formatted text because a [String] cannot be wiped:
 * lines are rendered only at the moment they are written out, and [clear] zeroizes every
 * retained buffer.
 *
 * When the bound is reached this stops accepting rather than evicting. A key log that
 * silently dropped its oldest entries would decrypt an arbitrary subset of the capture with
 * no indication which part was missing, which is harder to interpret than a short log whose
 * cut-off is reported.
 */
class TlsKeyLogRecorder(
    private val configuration: TlsKeyLogConfiguration = TlsKeyLogConfiguration(),
) {
    private val lock = Any()
    private val retained = ArrayList<TlsKeyLogSecrets>()
    private var lineCount = 0
    private var drainedThrough = 0
    private var dropped = 0L

    /** Records whatever [BcTlsKeyLogSampler] just found. A no-op unless retention was consented. */
    fun record(secrets: List<TlsKeyLogSecrets>) {
        if (!configuration.isActive || secrets.isEmpty()) return
        synchronized(lock) {
            secrets.forEach { candidate ->
                val lines = TlsKeyLog.linesFor(candidate).size
                if (lines == 0) return@forEach
                if (lineCount + lines > configuration.maximumLines) {
                    dropped = saturatingAdd(dropped, lines.toLong())
                    zeroize(candidate)
                    return@forEach
                }
                retained += candidate
                lineCount += lines
            }
        }
    }

    fun snapshot(): TlsKeyLogSnapshot = synchronized(lock) {
        TlsKeyLogSnapshot(
            enabledForSession = configuration.isActive,
            lineCount = lineCount,
            droppedLines = dropped,
        )
    }

    /**
     * The key-log text for everything recorded since the last drain, or null when nothing is
     * pending. Used to inject secrets into a running capture as they are learned.
     *
     * The caller owns the returned bytes and should zeroize them once written.
     */
    fun drainPendingBlock(): ByteArray? = synchronized(lock) {
        if (drainedThrough >= retained.size) return@synchronized null
        val pending = retained.subList(drainedThrough, retained.size).flatMap(TlsKeyLog::linesFor)
        drainedThrough = retained.size
        if (pending.isEmpty()) null else pending.joinToString(separator = "", postfix = "") { "$it\n" }
            .toByteArray(StandardCharsets.US_ASCII)
    }

    /** Writes every retained secret in NSS key-log format. Returns the number of bytes written. */
    fun exportTo(output: OutputStream): Long {
        val all = synchronized(lock) { retained.toList() }
        var written = 0L
        all.forEach { secrets ->
            written += TlsKeyLog.appendToCountingBytes(output, secrets)
        }
        output.flush()
        return written
    }

    /** Zeroizes every retained secret. Call on stop, disposal, and user erase. */
    fun clear() = synchronized(lock) {
        retained.forEach(::zeroize)
        retained.clear()
        lineCount = 0
        drainedThrough = 0
        dropped = 0L
    }

    private fun zeroize(secrets: TlsKeyLogSecrets) {
        secrets.clientRandom.fill(0)
        secrets.masterSecret?.fill(0)
        secrets.clientHandshakeTrafficSecret?.fill(0)
        secrets.serverHandshakeTrafficSecret?.fill(0)
        secrets.clientApplicationTrafficSecret?.fill(0)
        secrets.serverApplicationTrafficSecret?.fill(0)
        secrets.exporterSecret?.fill(0)
    }

    private fun saturatingAdd(left: Long, right: Long): Long =
        if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right
}
