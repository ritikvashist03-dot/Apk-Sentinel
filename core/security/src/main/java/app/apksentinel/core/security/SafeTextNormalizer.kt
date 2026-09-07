package app.apksentinel.core.security

import java.text.Normalizer

/**
 * Normalizes text before it becomes a filename or a user-visible label. It
 * removes controls and bidirectional override marks that can make one value
 * look like another or disguise an extension. This is normalization, not a
 * replacement for storage access controls.
 */
object SafeTextNormalizer {
    const val DEFAULT_FILENAME = "export"
    const val DEFAULT_DISPLAY_TEXT = "Unknown"

    fun normalizeFileName(
        input: String?,
        fallback: String = DEFAULT_FILENAME,
        maxCodePoints: Int = DEFAULT_FILENAME_MAX_CODE_POINTS,
    ): String {
        require(maxCodePoints in 1..MAX_ALLOWED_CODE_POINTS) {
            "maxCodePoints must be within the supported bound."
        }

        var candidate = clean(input.orEmpty(), filenameMode = true)
            .trim { it.isWhitespace() || it == '.' }
        if (candidate.isBlank()) {
            candidate = clean(fallback, filenameMode = true)
                .trim { it.isWhitespace() || it == '.' }
        }
        if (candidate.isBlank()) {
            candidate = DEFAULT_FILENAME
        }

        candidate = candidate.replace(WHITESPACE, " ")
        if (isReservedDeviceName(candidate)) {
            candidate = "_" + candidate
        }
        return truncateFileName(candidate, maxCodePoints)
    }

    fun normalizeDisplayText(
        input: String?,
        fallback: String = DEFAULT_DISPLAY_TEXT,
        maxCodePoints: Int = DEFAULT_DISPLAY_MAX_CODE_POINTS,
    ): String {
        require(maxCodePoints in 1..MAX_ALLOWED_CODE_POINTS) {
            "maxCodePoints must be within the supported bound."
        }

        val cleaned = clean(input.orEmpty(), filenameMode = false)
            .replace(WHITESPACE, " ")
            .trim()
        val value = cleaned.ifBlank {
            clean(fallback, filenameMode = false)
                .replace(WHITESPACE, " ")
                .trim()
                .ifBlank { DEFAULT_DISPLAY_TEXT }
        }
        return truncateCodePoints(value, maxCodePoints)
    }

    private fun clean(value: String, filenameMode: Boolean): String {
        val normalized = Normalizer.normalize(value, Normalizer.Form.NFKC)
        return buildString(normalized.length) {
            normalized.forEach { character ->
                when {
                    character.isISOControl() || character in INVISIBLE_OR_BIDI -> append(' ')
                    filenameMode && character in FILENAME_UNSAFE_CHARACTERS -> append(' ')
                    else -> append(character)
                }
            }
        }
    }

    private fun isReservedDeviceName(fileName: String): Boolean {
        val baseName = fileName
            .substringBeforeLast('.', missingDelimiterValue = fileName)
            .trim()
            .uppercase()
        return baseName in RESERVED_DEVICE_NAMES
    }

    private fun truncateFileName(value: String, maxCodePoints: Int): String {
        if (value.codePointCount(0, value.length) <= maxCodePoints) {
            return value
        }

        val extensionStart = value.lastIndexOf('.')
        val extension = if (extensionStart > 0) value.substring(extensionStart) else ""
        val extensionCodePoints = extension.codePointCount(0, extension.length)
        if (extensionCodePoints in 1 until maxCodePoints) {
            val base = value.substring(0, extensionStart)
            return truncateCodePoints(base, maxCodePoints - extensionCodePoints).trimEnd('.', ' ') + extension
        }
        return truncateCodePoints(value, maxCodePoints).trimEnd('.', ' ')
    }

    private fun truncateCodePoints(value: String, maxCodePoints: Int): String {
        if (value.codePointCount(0, value.length) <= maxCodePoints) {
            return value
        }
        var index = 0
        var count = 0
        while (index < value.length && count < maxCodePoints) {
            val codePoint = Character.codePointAt(value, index)
            index += Character.charCount(codePoint)
            count += 1
        }
        return value.substring(0, index)
    }

    private val WHITESPACE = Regex("\\s+")
    private val FILENAME_UNSAFE_CHARACTERS = setOf('<', '>', ':', '"', '/', '\\', '|', '?', '*')
    private val INVISIBLE_OR_BIDI = setOf(
        '\u200B',
        '\u200C',
        '\u200D',
        '\u200E',
        '\u200F',
        '\u202A',
        '\u202B',
        '\u202C',
        '\u202D',
        '\u202E',
        '\u2060',
        '\u2066',
        '\u2067',
        '\u2068',
        '\u2069',
        '\uFEFF',
    )
    private val RESERVED_DEVICE_NAMES = buildSet {
        addAll(setOf("CON", "PRN", "AUX", "NUL", "CLOCK$"))
        (1..9).forEach { index ->
            add("COM" + index)
            add("LPT" + index)
        }
    }

    private const val DEFAULT_FILENAME_MAX_CODE_POINTS = 96
    private const val DEFAULT_DISPLAY_MAX_CODE_POINTS = 120
    private const val MAX_ALLOWED_CODE_POINTS = 512
}
