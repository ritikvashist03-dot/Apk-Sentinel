package app.apksentinel.engine.tlsinspection

import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.Locale
import org.bouncycastle.tls.crypto.TlsSecret

/**
 * Non-destructive access to a BouncyCastle TLS secret.
 *
 * [TlsSecret] exposes only `extract()`, which returns the bytes AND destroys the secret —
 * calling it on a live session's master secret would break that session. BouncyCastle's
 * own implementation keeps the value in a private `byte[] data` on
 * `org.bouncycastle.tls.crypto.impl.AbstractTlsSecret`, so a key log can read it without
 * consuming it.
 *
 * This is deliberately narrow and FAILS CLOSED: any change to BouncyCastle's internals, any
 * security-manager refusal, or any unexpected type yields null, and the caller simply
 * produces no key log. It must never throw into a live TLS path, and it must never be the
 * reason a connection fails.
 *
 * It is reflection into a third-party library's private state, which is a real maintenance
 * cost: a BouncyCastle upgrade can silently turn key logging off. [isAvailable] exists so a
 * caller can say that honestly instead of appearing to work.
 */
object BcTlsSecretAccess {
    private const val ABSTRACT_SECRET = "org.bouncycastle.tls.crypto.impl.AbstractTlsSecret"

    /** Bytes of [secret], or null when they cannot be read without destroying it. */
    fun copyOf(secret: TlsSecret?): ByteArray? {
        if (secret == null) return null
        return runCatching {
            if (!secret.isAlive) return null
            var type: Class<*>? = secret.javaClass
            while (type != null && type.name != ABSTRACT_SECRET) type = type.superclass
            val field = type?.getDeclaredField("data") ?: return null
            field.isAccessible = true
            (field.get(secret) as? ByteArray)?.copyOf()
        }.getOrNull()
    }

    /** True when secrets can actually be read on this runtime and library version. */
    fun isAvailable(probe: TlsSecret?): Boolean = copyOf(probe) != null
}

/** The secrets a key log line needs, already copied out of the live session. */
data class TlsKeyLogSecrets(
    val clientRandom: ByteArray,
    val masterSecret: ByteArray? = null,
    val clientHandshakeTrafficSecret: ByteArray? = null,
    val serverHandshakeTrafficSecret: ByteArray? = null,
    val clientApplicationTrafficSecret: ByteArray? = null,
    val serverApplicationTrafficSecret: ByteArray? = null,
    val exporterSecret: ByteArray? = null,
) {
    init {
        require(clientRandom.size == CLIENT_RANDOM_BYTES) { "A TLS client random is 32 bytes." }
    }

    companion object {
        const val CLIENT_RANDOM_BYTES = 32
    }
}

/**
 * Writes the NSS key log format that Wireshark reads.
 *
 * TLS 1.2 sessions produce a single CLIENT_RANDOM line; TLS 1.3 produces one line per
 * traffic secret. Only the labels whose secrets were actually captured are emitted — a key
 * log with a fabricated or zero-filled line is worse than a shorter one, because it makes a
 * session look decryptable when it is not.
 */
object TlsKeyLog {
    const val LABEL_CLIENT_RANDOM = "CLIENT_RANDOM"
    const val LABEL_CLIENT_HANDSHAKE = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
    const val LABEL_SERVER_HANDSHAKE = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
    const val LABEL_CLIENT_APPLICATION = "CLIENT_TRAFFIC_SECRET_0"
    const val LABEL_SERVER_APPLICATION = "SERVER_TRAFFIC_SECRET_0"
    const val LABEL_EXPORTER = "EXPORTER_SECRET"

    /** The NSS key log format is line-oriented and always uses LF, on every platform. */
    const val LINE_TERMINATOR = "\n"

    /** The lines for one session, in the order Wireshark expects. Empty when nothing usable. */
    fun linesFor(secrets: TlsKeyLogSecrets): List<String> {
        val clientRandom = hex(secrets.clientRandom)
        return buildList {
            fun add(label: String, value: ByteArray?) {
                if (value != null && value.isNotEmpty()) add("$label $clientRandom ${hex(value)}")
            }
            add(LABEL_CLIENT_RANDOM, secrets.masterSecret)
            add(LABEL_CLIENT_HANDSHAKE, secrets.clientHandshakeTrafficSecret)
            add(LABEL_SERVER_HANDSHAKE, secrets.serverHandshakeTrafficSecret)
            add(LABEL_CLIENT_APPLICATION, secrets.clientApplicationTrafficSecret)
            add(LABEL_SERVER_APPLICATION, secrets.serverApplicationTrafficSecret)
            add(LABEL_EXPORTER, secrets.exporterSecret)
        }
    }

    /** Appends [secrets] to [output]. Returns the number of BYTES written. */
    fun appendToCountingBytes(output: OutputStream, secrets: TlsKeyLogSecrets): Long {
        var written = 0L
        linesFor(secrets).forEach { line ->
            val encoded = (line + LINE_TERMINATOR).toByteArray(StandardCharsets.US_ASCII)
            output.write(encoded)
            written += encoded.size
        }
        return written
    }

    /** Appends [secrets] to [output]. Returns the number of lines written. */
    fun appendTo(output: OutputStream, secrets: TlsKeyLogSecrets): Int {
        val lines = linesFor(secrets)
        lines.forEach { line ->
            output.write((line + "\n").toByteArray(StandardCharsets.US_ASCII))
        }
        output.flush()
        return lines.size
    }

    private fun hex(value: ByteArray): String =
        value.joinToString(separator = "") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xff) }
}
