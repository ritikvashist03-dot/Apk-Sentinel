package app.apksentinel.inspector.internal

import app.apksentinel.inspector.DecodedManifestText
import com.android.apksig.internal.apk.AndroidBinXmlParser
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.zip.ZipFile

/** Bounded, read-only AXML rendering using the parser shipped with pinned apksig. */
internal object DecodedManifestRenderer {
    fun decode(apkFile: File, maximumBytes: Int): Result<DecodedManifestText> =
        decodeWithIntentFilters(apkFile, maximumBytes, app.apksentinel.inspector.InspectionLimits(maxDecodedManifestBytes = maximumBytes))
            .map { it.decodedManifest }

    fun decodeWithIntentFilters(
        apkFile: File,
        maximumBytes: Int,
        limits: app.apksentinel.inspector.InspectionLimits,
    ): Result<DecodedManifestArtifacts> = runCatching {
        require(maximumBytes in MINIMUM_RENDERED_MANIFEST_BYTES..MAXIMUM_RENDERED_MANIFEST_BYTES) {
            "Readable manifest output limit is outside the supported bounded range."
        }
        val bytes = ZipFile(apkFile).use { zip ->
            val entry = requireNotNull(zip.getEntry("AndroidManifest.xml")) { "Manifest entry missing" }
            require(entry.size < 0 || entry.size <= maximumBytes) { "Manifest exceeds decode limit" }
            zip.getInputStream(entry).use { input ->
                val data = input.readAtMost(maximumBytes + 1)
                require(data.size <= maximumBytes) { "Manifest exceeds decode limit" }
                data
            }
        }
        val parser = AndroidBinXmlParser(ByteBuffer.wrap(bytes))
        val output = BoundedManifestXmlWriter(maximumBytes)
        val intentFilters = BoundedIntentFilterEvidenceCollector(limits)
        var unresolvedReferences = 0
        var event = parser.eventType
        while (event != AndroidBinXmlParser.EVENT_END_DOCUMENT && !output.isTruncated) {
            when (event) {
                AndroidBinXmlParser.EVENT_START_ELEMENT -> {
                    val attributes = buildList {
                        for (index in 0 until parser.attributeCount) {
                            val rendered = when (parser.getAttributeValueType(index)) {
                                AndroidBinXmlParser.VALUE_TYPE_STRING -> parser.getAttributeStringValue(index)
                                AndroidBinXmlParser.VALUE_TYPE_BOOLEAN -> parser.getAttributeBooleanValue(index).toString()
                                AndroidBinXmlParser.VALUE_TYPE_INT -> parser.getAttributeIntValue(index).toString()
                                AndroidBinXmlParser.VALUE_TYPE_REFERENCE -> {
                                    unresolvedReferences++
                                    "@0x${parser.getAttributeIntValue(index).toUInt().toString(16).padStart(8, '0')}"
                                }
                                else -> {
                                    unresolvedReferences++
                                    "0x${parser.getAttributeIntValue(index).toUInt().toString(16)}"
                                }
                            }
                            add(
                                RenderedManifestAttribute(
                                    namespace = parser.getAttributeNamespace(index),
                                    name = parser.getAttributeName(index),
                                    fallbackName = "attr_${parser.getAttributeNameResourceId(index).toUInt().toString(16)}",
                                    value = rendered.orEmpty(),
                                ),
                            )
                        }
                    }
                    intentFilters.startElement(parser.name, attributes)
                    output.startElement(parser.name, attributes)
                }

                AndroidBinXmlParser.EVENT_END_ELEMENT -> {
                    intentFilters.endElement(parser.name)
                    output.endElement()
                }
            }
            if (!output.isTruncated) {
                event = parser.next()
            }
        }
        if (output.isTruncated) intentFilters.markManifestTruncated()
        DecodedManifestArtifacts(
            decodedManifest = DecodedManifestText(
                xml = output.finish(),
                unresolvedResourceReferenceCount = unresolvedReferences,
                isTruncated = output.isTruncated,
            ),
            intentFilters = intentFilters.finish(),
        )
    }
}

internal data class DecodedManifestArtifacts(
    val decodedManifest: DecodedManifestText,
    val intentFilters: IntentFilterEvidenceCollection,
)

/**
 * API-1-compatible equivalent of reading at most [maximumBytes] bytes. The
 * caller deliberately asks for limit + 1, so an over-limit manifest is detected
 * before it is passed to the binary XML parser. The decoder limits its input to
 * 8 MiB, so this probe cannot overflow or allocate an unbounded buffer.
 */
internal fun InputStream.readAtMost(maximumBytes: Int): ByteArray {
    require(maximumBytes >= 0)
    val output = ByteArray(maximumBytes)
    var offset = 0
    while (offset < output.size) {
        val read = read(output, offset, output.size - offset)
        when {
            read < 0 -> break
            read > 0 -> offset += read
            else -> {
                // InputStream permits a zero-length return from some wrappers.
                // A one-byte probe avoids an unbounded busy loop without reading
                // beyond the same fixed maximum.
                val next = read()
                if (next < 0) break
                output[offset] = next.toByte()
                offset += 1
            }
        }
    }
    return if (offset == output.size) output else output.copyOf(offset)
}

/**
 * A byte-accurate XML writer for decoded data from an untrusted APK. It reserves
 * the truncation comment and every still-open closing tag before accepting a
 * new fragment, so a limit never leaves a partial attribute or malformed XML.
 */
internal class BoundedManifestXmlWriter(
    private val maximumBytes: Int,
) {
    private val output = StringBuilder()
    private val openElements = ArrayDeque<String>()
    private val namespacePrefixes = linkedMapOf(ANDROID_NAMESPACE to "android")
    private var nextNamespaceIndex = 1
    private var outputBytes = 0
    private var reservedClosingBytes = 0
    private var rootStarted = false

    var isTruncated: Boolean = false
        private set

    init {
        require(maximumBytes >= MINIMUM_RENDERED_MANIFEST_BYTES)
        appendUnchecked(XML_DECLARATION)
    }

    fun startElement(
        rawName: String?,
        attributes: List<RenderedManifestAttribute>,
    ) {
        if (isTruncated) return
        if (openElements.size >= MAX_RENDERED_NESTING_DEPTH) {
            isTruncated = true
            return
        }

        val elementName = xmlName(rawName, "element")
        val elementClose = closeTag(elementName)
        val header = StringBuilder("<$elementName")
        var headerBytes = utf8Bytes(header.toString())
        var prospectivePrefixes = LinkedHashMap(namespacePrefixes)
        var prospectiveNamespaceIndex = nextNamespaceIndex
        var namespacesDeclaredOnElement = linkedSetOf<String>()

        // Android attributes remain recognizable even when the original AXML
        // namespace events are unavailable from the parser.
        if (!rootStarted) {
            val declaration = " xmlns:android=\"$ANDROID_NAMESPACE\""
            header.append(declaration)
            headerBytes += utf8Bytes(declaration)
        }

        for (attribute in attributes) {
            val namespace = attribute.namespace?.takeIf { it.isNotBlank() }
            val nextPrefixes = LinkedHashMap(prospectivePrefixes)
            var nextIndex = prospectiveNamespaceIndex
            val nextNamespacesDeclaredOnElement = LinkedHashSet(namespacesDeclaredOnElement)
            val prefix = when (namespace) {
                null -> ""
                ANDROID_NAMESPACE -> "android:"
                else -> {
                    val existing = nextPrefixes[namespace]
                    val namespacePrefix = existing ?: "ns${nextIndex++}".also {
                        nextPrefixes[namespace] = it
                    }
                    "$namespacePrefix:"
                }
            }
            val attributeName = xmlName(attribute.name, attribute.fallbackName)
            val namespaceDeclaration = when {
                namespace == null || namespace == ANDROID_NAMESPACE -> ""
                !nextNamespacesDeclaredOnElement.add(namespace) -> ""
                else -> {
                    val escapedNamespace = escapeXmlAttribute(namespace, MAX_NAMESPACE_URI_BYTES)
                    if (escapedNamespace.wasTruncated) {
                        isTruncated = true
                        break
                    }
                    " xmlns:${prefix.removeSuffix(":")}=${quoted(escapedNamespace.value)}"
                }
            }
            val escapedValue = escapeXmlAttribute(attribute.value, MAX_ATTRIBUTE_VALUE_BYTES)
            val attributeFragment = namespaceDeclaration +
                " $prefix$attributeName=${quoted(escapedValue.value)}"
            val candidateBytes = headerBytes + utf8Bytes(attributeFragment) + UTF8_NEWLINE_AND_TAG_CLOSE_BYTES
            if (!fitsWithReservedClosings(candidateBytes, elementClose)) {
                isTruncated = true
                break
            }
            header.append(attributeFragment)
            headerBytes += utf8Bytes(attributeFragment)
            prospectivePrefixes = nextPrefixes
            prospectiveNamespaceIndex = nextIndex
            namespacesDeclaredOnElement = nextNamespacesDeclaredOnElement
            if (escapedValue.wasTruncated) {
                isTruncated = true
                break
            }
        }

        if (!fitsWithReservedClosings(headerBytes + UTF8_NEWLINE_AND_TAG_CLOSE_BYTES, elementClose)) {
            isTruncated = true
            return
        }
        val renderedElement = header.append(">\n").toString()
        appendUnchecked(renderedElement)
        openElements.addLast(elementName)
        reservedClosingBytes += utf8Bytes(elementClose)
        namespacePrefixes.clear()
        namespacePrefixes.putAll(prospectivePrefixes)
        nextNamespaceIndex = prospectiveNamespaceIndex
        rootStarted = true
    }

    fun endElement() {
        if (openElements.isEmpty()) return
        val name = openElements.last()
        val closing = closeTag(name)
        if (!fitsAfterClosingCurrentElement(closing)) {
            // This should be impossible because every successful append reserved
            // the close tags. Keeping the failure explicit avoids malformed XML.
            isTruncated = true
            return
        }
        appendUnchecked(closing)
        openElements.removeLast()
        reservedClosingBytes -= utf8Bytes(closing)
    }

    fun finish(): String {
        if (!rootStarted) {
            // A malformed/bound-exhausted binary XML stream still receives a
            // parseable, explicit placeholder rather than a fragment.
            return FALLBACK_TRUNCATED_DOCUMENT.also { isTruncated = true }
        }
        if (isTruncated) {
            appendUnchecked(TRUNCATION_COMMENT)
        }
        while (openElements.isNotEmpty()) {
            appendUnchecked(closeTag(openElements.removeLast()))
        }
        return output.toString()
    }

    private fun fitsWithReservedClosings(
        candidateBytes: Int,
        additionalClose: String?,
    ): Boolean {
        val additionalCloseBytes = additionalClose?.let(::utf8Bytes) ?: 0
        return outputBytes + candidateBytes + utf8Bytes(TRUNCATION_COMMENT) + reservedClosingBytes + additionalCloseBytes <= maximumBytes
    }

    private fun fitsAfterClosingCurrentElement(candidate: String): Boolean {
        val remainingClosings = reservedClosingBytes - utf8Bytes(candidate)
        return outputBytes + utf8Bytes(candidate) + utf8Bytes(TRUNCATION_COMMENT) + remainingClosings <= maximumBytes
    }

    private fun appendUnchecked(value: String) {
        output.append(value)
        outputBytes += utf8Bytes(value)
    }
}

internal data class RenderedManifestAttribute(
    val namespace: String?,
    val name: String?,
    val fallbackName: String,
    val value: String,
)

private data class EscapedXmlAttribute(
    val value: String,
    val wasTruncated: Boolean,
)

private fun escapeXmlAttribute(raw: String, maximumBytes: Int): EscapedXmlAttribute {
    val marker = "... [truncated]"
    val contentBudget = maximumBytes - utf8Bytes(marker)
    val output = StringBuilder()
    var bytes = 0
    var changed = false
    var index = 0
    while (index < raw.length) {
        val character = raw[index]
        val fragment = when {
            Character.isHighSurrogate(character) &&
                index + 1 < raw.length && Character.isLowSurrogate(raw[index + 1]) -> {
                raw.substring(index, index + 2).also { index += 2 }
            }

            Character.isHighSurrogate(character) || Character.isLowSurrogate(character) -> {
                changed = true
                index += 1
                "&#xfffd;"
            }

            else -> {
                index += 1
                when (character) {
                    '&' -> "&amp;"
                    '<' -> "&lt;"
                    '>' -> "&gt;"
                    '\"' -> "&quot;"
                    '\'' -> "&apos;"
                    else -> when {
                        character.isISOControl() && character !in setOf('\t', '\n', '\r') -> {
                            changed = true
                            "&#xfffd;"
                        }
                        else -> character.toString()
                    }
                }
            }
        }
        val fragmentBytes = utf8Bytes(fragment)
        if (bytes + fragmentBytes > contentBudget) {
            return EscapedXmlAttribute(output.append(marker).toString(), wasTruncated = true)
        }
        output.append(fragment)
        bytes += fragmentBytes
    }
    return EscapedXmlAttribute(output.toString(), wasTruncated = changed)
}

private fun quoted(value: String): String = "\"$value\""

private fun closeTag(name: String): String = "</$name>\n"

private fun xmlName(raw: String?, fallback: String): String {
    // apksig currently exposes local names, but stripping a supplied prefix
    // keeps the renderer correct if that behaviour changes.
    val source = raw.orEmpty().substringAfterLast(':').ifBlank { fallback }.take(MAX_XML_NAME_CHARACTERS)
    val normalized = buildString(source.length) {
        source.forEachIndexed { index, character ->
            val allowed = character in 'A'..'Z' || character in 'a'..'z' ||
                character in '0'..'9' || character == '_' || character == '-' || character == '.'
            append(if (!allowed || (index == 0 && character in '0'..'9')) '_' else character)
        }
    }
    return normalized.ifBlank { fallback }
}

private fun utf8Bytes(value: String): Int = value.toByteArray(StandardCharsets.UTF_8).size

internal const val MINIMUM_RENDERED_MANIFEST_BYTES = 128
private const val MAXIMUM_RENDERED_MANIFEST_BYTES = 8 * 1024 * 1024
private const val MAX_XML_NAME_CHARACTERS = 96
// Keep the emitted tree below the JDK XML parser's default maxElementDepth so
// truncated hostile manifests remain parseable by downstream consumers.
private const val MAX_RENDERED_NESTING_DEPTH = 96
private const val MAX_ATTRIBUTE_VALUE_BYTES = 8 * 1024
private const val MAX_NAMESPACE_URI_BYTES = 2 * 1024
private const val UTF8_NEWLINE_AND_TAG_CLOSE_BYTES = 2
private const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"
private const val XML_DECLARATION = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
private const val TRUNCATION_COMMENT = "<!-- Readable manifest view truncated at the configured safety limit. -->\n"
private const val FALLBACK_TRUNCATED_DOCUMENT =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?><manifest data-apksentinel-render-truncated=\"true\"/>"
