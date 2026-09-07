package app.apksentinel.mobile

import java.io.ByteArrayInputStream
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SignedBundleUpdateClientTest {
    @Test
    fun endpointPolicyRequiresAnExactHttpsOriginWithoutCredentialsOrQuery() {
        assertEquals("https://updates.example.test/feed", SignedBundleUpdateClient.validateEndpoint("https://updates.example.test/feed")?.toString())
        assertNull(SignedBundleUpdateClient.validateEndpoint("http://updates.example.test/feed"))
        assertNull(SignedBundleUpdateClient.validateEndpoint("https://user:password@updates.example.test/feed"))
        assertNull(SignedBundleUpdateClient.validateEndpoint("https://updates.example.test/feed?token=secret"))
        assertNull(SignedBundleUpdateClient.validateEndpoint("https://updates.example.test/feed#fragment"))
        assertNull(SignedBundleUpdateClient.validateEndpoint("https://updates.example.test:8443/feed"))
        assertNull(SignedBundleUpdateClient.validateEndpoint("https://updates.example.test/feed with spaces"))
    }

    @Test
    fun detachedSignatureHeaderIsSingleCanonicalBoundedBase64Value() {
        val value = Base64.getEncoder().encodeToString(ByteArray(64) { it.toByte() })
        val headers = mapOf<String?, List<String>?>(SignedBundleUpdateClient.SIGNATURE_HEADER to listOf(value))
        assertEquals(value, SignedBundleUpdateClient.parseDetachedSignature(headers))
        assertNull(SignedBundleUpdateClient.parseDetachedSignature(emptyMap()))
        assertNull(
            SignedBundleUpdateClient.parseDetachedSignature(
                mapOf<String?, List<String>?>(SignedBundleUpdateClient.SIGNATURE_HEADER to listOf(value, value)),
            ),
        )
        assertNull(
            SignedBundleUpdateClient.parseDetachedSignature(
                mapOf<String?, List<String>?>(SignedBundleUpdateClient.SIGNATURE_HEADER to listOf("not base64")),
            ),
        )
        assertNull(
            SignedBundleUpdateClient.parseDetachedSignature(
                mapOf<String?, List<String>?>(SignedBundleUpdateClient.SIGNATURE_HEADER to listOf("A".repeat(4_097))),
            ),
        )
    }

    @Test
    fun bodyReaderRejectsOneByteOverTheConfiguredCapWithoutReturningPartialData() {
        val accepted = ByteArrayInputStream(byteArrayOf(1, 2, 3)).use {
            SignedBundleUpdateClient.run { it.readBounded(3) }
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), requireNotNull(accepted))
        val oversized = ByteArrayInputStream(byteArrayOf(1, 2, 3, 4)).use {
            SignedBundleUpdateClient.run { it.readBounded(3) }
        }
        assertNull(oversized)
        assertTrue(SignedBundleUpdateClient.run { ByteArrayInputStream(ByteArray(128)).readBounded(127) == null })
    }

    @Test
    fun bodyReaderRejectsAStalledStreamAfterBoundedZeroProgressReads() {
        val stalled = object : java.io.InputStream() {
            override fun read(): Int = 0

            override fun read(buffer: ByteArray, offset: Int, length: Int): Int = 0
        }
        assertNull(SignedBundleUpdateClient.run { stalled.readBounded(8) })
    }
}
