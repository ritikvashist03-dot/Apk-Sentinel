package app.apksentinel.core.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedStorageTest {
    @Test
    fun encryptedStorageRoundTripsAndBindsCiphertextToItsLogicalKey() {
        val backingStore = InMemoryStringKeyValueStore()
        val storage = AuthenticatedEncryptedStorage(
            backingStore = backingStore,
            cipher = AadBoundTestCipher(),
            namespace = "test_store",
        )
        val firstKey = SecureStorageKey("alpha")
        val secondKey = SecureStorageKey("beta")
        val plaintext = "sensitive payload".encodeToByteArray()

        assertTrue(storage.write(firstKey, plaintext) is SecureStorageResult.Success)
        val encoded = backingStore.read("test_store.alpha")
        assertFalse(encoded.orEmpty().contains("sensitive payload"))

        val readResult = storage.read(firstKey) as SecureStorageResult.Success
        assertArrayEquals(plaintext, readResult.value)

        backingStore.write("test_store.beta", encoded.orEmpty())
        val replayResult = storage.read(secondKey) as SecureStorageResult.Failure
        assertEquals(SecureStorageFailure.DECRYPTION_FAILED, replayResult.reason)
    }

    @Test
    fun malformedPayloadIsRejectedWithoutLeakingItsContents() {
        val backingStore = InMemoryStringKeyValueStore()
        val storage = AuthenticatedEncryptedStorage(
            backingStore = backingStore,
            cipher = AadBoundTestCipher(),
            namespace = "test_store",
        )
        backingStore.write("test_store.alpha", "v1|not-base64!|also-not-base64!")

        val result = storage.read(SecureStorageKey("alpha")) as SecureStorageResult.Failure

        assertEquals(SecureStorageFailure.MALFORMED_PAYLOAD, result.reason)
    }

    private class AadBoundTestCipher : AuthenticatedCipher {
        override fun encrypt(
            plaintext: ByteArray,
            associatedData: ByteArray,
        ): CryptoResult<Ciphertext> {
            val tag = tagFor(associatedData)
            val encrypted = ByteArray(TAG_LENGTH + plaintext.size)
            writeTag(tag, encrypted)
            plaintext.forEachIndexed { index, byte ->
                encrypted[index + TAG_LENGTH] = (byte.toInt() xor maskFor(tag, index)).toByte()
            }
            return CryptoResult.Success(Ciphertext(byteArrayOf(1), encrypted))
        }

        override fun decrypt(
            ciphertext: Ciphertext,
            associatedData: ByteArray,
        ): CryptoResult<ByteArray> {
            if (ciphertext.bytes.size < TAG_LENGTH || readTag(ciphertext.bytes) != tagFor(associatedData)) {
                return CryptoResult.Failure(CryptoFailure.OPERATION_FAILED)
            }
            val tag = tagFor(associatedData)
            val plaintext = ByteArray(ciphertext.bytes.size - TAG_LENGTH)
            plaintext.indices.forEach { index ->
                plaintext[index] = (
                    ciphertext.bytes[index + TAG_LENGTH].toInt() xor maskFor(tag, index)
                ).toByte()
            }
            return CryptoResult.Success(plaintext)
        }

        private fun tagFor(associatedData: ByteArray): Int =
            associatedData.fold(17) { accumulator, byte -> 31 * accumulator + byte.toInt() }

        private fun maskFor(tag: Int, index: Int): Int =
            (tag ushr ((index % 4) * 8)) and 0xff

        private fun writeTag(tag: Int, output: ByteArray) {
            output[0] = (tag ushr 24).toByte()
            output[1] = (tag ushr 16).toByte()
            output[2] = (tag ushr 8).toByte()
            output[3] = tag.toByte()
        }

        private fun readTag(input: ByteArray): Int =
            ((input[0].toInt() and 0xff) shl 24) or
                ((input[1].toInt() and 0xff) shl 16) or
                ((input[2].toInt() and 0xff) shl 8) or
                (input[3].toInt() and 0xff)

        private companion object {
            const val TAG_LENGTH = 4
        }
    }
}
