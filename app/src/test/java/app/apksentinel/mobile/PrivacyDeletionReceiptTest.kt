package app.apksentinel.mobile

import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PrivacyDeletionReceiptTest {
    private class MemoryStorage : EncryptedStorage {
        var payload: ByteArray? = null
        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> {
            payload = plaintext.copyOf()
            return SecureStorageResult.Success(Unit)
        }
        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> =
            SecureStorageResult.Success(payload?.copyOf())
        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> {
            payload = null
            return SecureStorageResult.Success(Unit)
        }
    }

    @Test fun strictCodecRoundTripsTypedReceipt() {
        val receipt = sample()
        val encoded = PrivacyDeletionReceiptCodec.encode(receipt)
        requireNotNull(encoded)
        assertTrue(encoded.size <= PrivacyDeletionReceiptCodec.MAX_BYTES)
        assertEquals(receipt, PrivacyDeletionReceiptCodec.decode(encoded, receipt.completedAtMillis))
    }

    @Test fun codecRejectsMalformedFutureAndUnboundedCounts() {
        val now = 1_000_000L
        assertNull(PrivacyDeletionReceiptCodec.decode("v1|1|0".toByteArray(), now))
        assertNull(PrivacyDeletionReceiptCodec.decode("v1|2000000|0|0|0|1|1|1|1|1|1|1|1".toByteArray(), now))
        assertNull(PrivacyDeletionReceiptCodec.decode("v1|1|1000001|0|0|1|1|1|1|1|1|1|1".toByteArray(), now))
        assertNull(PrivacyDeletionReceiptCodec.decode("v1|1|0|0|0|true|1|1|1|1|1|1|1".toByteArray(), now))
    }

    @Test fun controllerPersistsOnlyBoundedReceipt() {
        val storage = MemoryStorage()
        val controller = PrivacyDeletionReceiptController(storage)
        assertEquals(PrivacyReceiptReadState.ABSENT, controller.read(100).state)
        assertTrue(controller.save(sample(100)))
        assertEquals(sample(100), controller.read(100).receipt)
        assertFalse(controller.save(sample(100).copy(networkEventsCleared = -1)))
    }

    private fun sample(at: Long = 1_000L) = PrivacyDeletionReceipt(
        completedAtMillis = at,
        grantsReleased = 2,
        networkEventsCleared = 3,
        firewallRulesCleared = 1,
        firewallPolicyConfirmed = true,
        threatDataConfirmed = true,
        installedHistoryConfirmed = true,
        networkHistoryConfirmed = false,
        postureHistoryConfirmed = true,
        privateFilesConfirmed = true,
        preferencesConfirmed = true,
        documentGrantsConfirmed = true,
        monitorStopped = true,
    )
}
