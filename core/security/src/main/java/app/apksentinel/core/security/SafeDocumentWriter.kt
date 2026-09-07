package app.apksentinel.core.security

import android.content.Context
import android.net.Uri
import java.io.OutputStream

/**
 * One place to write to a user-chosen SAF document.
 *
 * Seventeen call sites across six files each re-implemented the same three concerns:
 * `openOutputStream(uri, "w")` can return null, it can throw (a revoked or stale grant
 * raises SecurityException, and a removed volume raises IOException), and the stream must
 * be closed on every path. Each site also invented its own way to signal that failure.
 *
 * This owns only that IO step. It deliberately does NOT own threading or user-facing
 * status text: callers legitimately differ there — some use coroutines, some an executor,
 * and one must zeroize a byte array after writing — and folding those differences into a
 * single helper would have meant rewriting careful code that already works.
 *
 * [useOutputStream] and [runCatchingWrite] are `inline` for a reason that is easy to undo
 * by accident: several callers pass a lambda that invokes a `suspend` function
 * (InstalledAppRepository.exportBaseApk, RootCaptureComposition.export, …). A suspend
 * call is only legal inside an inline lambda, which is what made the original
 * `stream.use { … }` form work. Removing `inline` here breaks those call sites.
 */
object SafeDocumentWriter {

    /**
     * Opens [uri] for writing and runs [block] against it, always closing the stream.
     *
     * Returns null when the destination cannot be opened or the write fails, which every
     * current caller maps onto its own failure state. Use [runCatchingWrite] when the
     * cause matters.
     */
    inline fun <T> useOutputStream(context: Context, uri: Uri, block: (OutputStream) -> T): T? =
        runCatching {
            context.contentResolver.openOutputStream(uri, "w")?.use(block)
        }.getOrNull()

    /**
     * As [useOutputStream], but preserves the failure. A null stream is reported as
     * [DestinationUnavailable] rather than being conflated with a write error.
     */
    inline fun <T> runCatchingWrite(context: Context, uri: Uri, block: (OutputStream) -> T): Result<T> =
        runCatching {
            val stream = context.contentResolver.openOutputStream(uri, "w")
                ?: throw DestinationUnavailable()
            stream.use(block)
        }

    /** Convenience for the common "write these bytes" case. Returns true when written. */
    fun writeBytes(context: Context, uri: Uri, bytes: ByteArray): Boolean =
        useOutputStream(context, uri) { output -> output.write(bytes) } != null

    /** Convenience for UTF-8 text. Returns true when written. */
    fun writeText(context: Context, uri: Uri, text: String): Boolean =
        writeBytes(context, uri, text.toByteArray(Charsets.UTF_8))

    /** The document picker returned a URI that cannot be opened for writing. */
    class DestinationUnavailable : java.io.IOException("The selected document could not be opened for writing.")
}
