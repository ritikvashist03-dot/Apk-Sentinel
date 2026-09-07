package app.apksentinel.core.security

import android.util.Log
import app.apksentinel.core.model.RedactionPolicy

enum class SafeLogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
}

/**
 * A sink receives messages only after RedactingSafeLogger has normalized and
 * redacted them. It intentionally has no Throwable parameter because exception
 * messages and stack attachments can contain sensitive input.
 */
fun interface SafeLogSink {
    fun write(level: SafeLogLevel, message: String)
}

interface SafeLogger {
    fun log(
        level: SafeLogLevel,
        event: String,
        metadata: Map<String, String> = emptyMap(),
    )
}

object NoOpSafeLogger : SafeLogger {
    override fun log(level: SafeLogLevel, event: String, metadata: Map<String, String>) = Unit
}

/**
 * The only logger supplied by this module. It applies standard redaction to
 * every metadata value, uses a fixed event grammar, stable map ordering, and
 * caps the final message. Do not call Android Log directly from security code.
 */
class RedactingSafeLogger(
    private val sink: SafeLogSink,
    private val policy: RedactionPolicy = RedactionPolicy.Standard,
) : SafeLogger {
    override fun log(
        level: SafeLogLevel,
        event: String,
        metadata: Map<String, String>,
    ) {
        val safeEvent = if (EVENT_PATTERN.matches(event)) event else "security_event"
        val safeMetadata = RedactionHelpers.redactMetadata(metadata, policy)
        val message = buildString {
            append(safeEvent)
            safeMetadata.forEach { (key, value) ->
                append(' ')
                append(SafeTextNormalizer.normalizeDisplayText(key, "field", MAX_KEY_LENGTH))
                append('=')
                append(
                    SafeTextNormalizer.normalizeDisplayText(
                        value,
                        policy.replacement,
                        MAX_VALUE_LENGTH,
                    ),
                )
            }
        }.take(MAX_MESSAGE_LENGTH)
        sink.write(level, message)
    }

    private companion object {
        val EVENT_PATTERN = Regex("^[a-z][a-z0-9_.-]{0,79}$")
        const val MAX_KEY_LENGTH = 64
        const val MAX_VALUE_LENGTH = 256
        const val MAX_MESSAGE_LENGTH = 2_000
    }
}

/**
 * Android platform sink. The tag is normalized once; callers should use a
 * compile-time tag rather than a user or device value.
 */
class AndroidSafeLogSink(tag: String = "ApkSentinel") : SafeLogSink {
    private val safeTag = SafeTextNormalizer.normalizeDisplayText(tag, "ApkSentinel", 23)

    override fun write(level: SafeLogLevel, message: String) {
        when (level) {
            SafeLogLevel.DEBUG -> Log.d(safeTag, message)
            SafeLogLevel.INFO -> Log.i(safeTag, message)
            SafeLogLevel.WARN -> Log.w(safeTag, message)
            SafeLogLevel.ERROR -> Log.e(safeTag, message)
        }
    }
}
