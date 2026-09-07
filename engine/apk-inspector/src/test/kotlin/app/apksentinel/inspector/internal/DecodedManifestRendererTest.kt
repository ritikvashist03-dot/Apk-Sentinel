package app.apksentinel.inspector.internal

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DecodedManifestRendererTest {
    @Test
    fun readsAtMostTheRequestedProbeLimitWithApiOneInputStreamMethods() {
        val source = ZeroReturningInputStream("abcdef".toByteArray())

        assertEquals("abcd", source.readAtMost(4).toString(StandardCharsets.UTF_8))

        val overflowProbe = ByteArrayInputStream("abcdef".toByteArray()).readAtMost(5)
        assertEquals(5, overflowProbe.size)
        assertEquals("abcde", overflowProbe.toString(StandardCharsets.UTF_8))
    }

    @Test
    fun boundsUtf8AttributeOutputBeforeAppendAndFinishesValidXml() {
        val writer = BoundedManifestXmlWriter(maximumBytes = 256)
        writer.startElement(
            rawName = "manifest",
            attributes = listOf(
                RenderedManifestAttribute(
                    namespace = null,
                    name = "label",
                    fallbackName = "label",
                    value = "\uD83D\uDD10".repeat(2_000),
                ),
            ),
        )
        writer.endElement()
        val xml = writer.finish()

        assertTrue(writer.isTruncated)
        assertTrue(xml.toByteArray(StandardCharsets.UTF_8).size <= 256)
        assertTrue(xml.contains("truncated"))
        parse(xml)
    }

    @Test
    fun decoratesNonAndroidAttributeNamespacesInsteadOfDroppingThem() {
        val namespace = "https://example.test/apk-sentinel/custom"
        val writer = BoundedManifestXmlWriter(maximumBytes = 2_048)
        writer.startElement(
            rawName = "manifest",
            attributes = listOf(
                RenderedManifestAttribute(
                    namespace = namespace,
                    name = "policy",
                    fallbackName = "policy",
                    value = "enabled \uD83D\uDD10",
                ),
                RenderedManifestAttribute(
                    namespace = namespace,
                    name = "mode",
                    fallbackName = "mode",
                    value = "offline",
                ),
            ),
        )
        writer.endElement()
        val xml = writer.finish()
        val document = parse(xml)

        assertFalse(writer.isTruncated)
        assertTrue(xml.contains("xmlns:ns1=\"$namespace\""))
        assertEquals("enabled \uD83D\uDD10", document.documentElement.getAttributeNS(namespace, "policy"))
        assertEquals("offline", document.documentElement.getAttributeNS(namespace, "mode"))
    }

    @Test
    fun hostileDeepNestingIsBoundedAndStillFinishesParseableXml() {
        val writer = BoundedManifestXmlWriter(maximumBytes = 16_384)
        repeat(10_000) { writer.startElement("nested", emptyList()) }
        val xml = writer.finish()

        assertTrue(writer.isTruncated)
        assertTrue(xml.toByteArray(StandardCharsets.UTF_8).size <= 16_384)
        parse(xml)
    }

    private fun parse(xml: String) = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
    }.newDocumentBuilder().parse(
        ByteArrayInputStream(xml.toByteArray(StandardCharsets.UTF_8)),
    )

    private class ZeroReturningInputStream(
        private val delegate: ByteArrayInputStream,
    ) : InputStream() {
        constructor(bytes: ByteArray) : this(ByteArrayInputStream(bytes))

        private var shouldReturnZero = true

        override fun read(): Int = delegate.read()

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (shouldReturnZero && length > 0) {
                shouldReturnZero = false
                return 0
            }
            return delegate.read(buffer, offset, length)
        }
    }
}
