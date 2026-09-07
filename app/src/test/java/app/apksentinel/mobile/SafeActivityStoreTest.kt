package app.apksentinel.mobile

import app.apksentinel.core.security.AuthenticatedCipher
import app.apksentinel.core.security.AuthenticatedEncryptedStorage
import app.apksentinel.core.security.Ciphertext
import app.apksentinel.core.security.CryptoResult
import app.apksentinel.core.security.InMemoryStringKeyValueStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeActivityStoreTest {
    private val now = 1_800_000_000_000L

    @Test fun codecRejectsUnknownFieldsAndFutureTime() {
        val unknown = "v1\n$now|APK_CHECK|COMPLETED|NOT_A_CODE\n".encodeToByteArray()
        val future = "v1\n${now + 600_000L}|APK_CHECK|COMPLETED|NONE\n".encodeToByteArray()

        assertEquals(null, SafeActivityCodec.decode(unknown, now))
        assertEquals(null, SafeActivityCodec.decode(future, now))
    }

    @Test fun controllerRetainsOnlyTypedBoundedRecordsAndErasesKey() {
        var keyDeleted = false
        val storage = AuthenticatedEncryptedStorage(InMemoryStringKeyValueStore(), CopyCipher())
        val controller = SafeActivityStoreController(storage) { keyDeleted = true; true }

        assertTrue(controller.append(SafeActivityRecord(SafeActivityCategory.APK_CHECK, SafeActivityOutcome.COMPLETED, now), now))
        val loaded = controller.read(now)

        assertEquals(SafeActivityReadState.READY, loaded.state)
        assertEquals(1, loaded.records.size)
        assertEquals(SafeActivityCategory.APK_CHECK, loaded.records.single().category)
        assertTrue(controller.erase())
        assertTrue(keyDeleted)
        assertTrue(controller.read(now).records.isEmpty())
    }

    @Test fun filterUsesOnlyProjectedTextAndTypedFields() {
        val rows = listOf(
            ActivityRow(ActivitySourceCategory.NETWORK, ActivitySourceOutcome.COMPLETED, now),
            ActivityRow(ActivitySourceCategory.PRIVACY_ERASE, ActivitySourceOutcome.ATTENTION, now - 40L * 24 * 60 * 60 * 1_000L),
        )

        val result = filterActivityRows(
            rows = rows,
            query = "network",
            category = null,
            outcome = ActivitySourceOutcome.COMPLETED,
            dateFilter = ActivityDateFilter.LAST_7_DAYS,
            nowMillis = now,
        ) { row -> if (row.category == ActivitySourceCategory.NETWORK) "network" to "completed" else "privacy" to "needs review" }

        assertEquals(1, result.size)
        assertEquals(ActivitySourceCategory.NETWORK, result.single().category)
    }

    private class CopyCipher : AuthenticatedCipher {
        override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): CryptoResult<Ciphertext> =
            CryptoResult.Success(Ciphertext(byteArrayOf(1), plaintext))

        override fun decrypt(ciphertext: Ciphertext, associatedData: ByteArray): CryptoResult<ByteArray> =
            CryptoResult.Success(ciphertext.bytes)
    }
}
