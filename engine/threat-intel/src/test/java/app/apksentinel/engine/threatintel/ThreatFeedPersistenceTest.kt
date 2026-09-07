package app.apksentinel.engine.threatintel

import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageFailure
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ThreatFeedPersistenceTest {
    private val keyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private val now = 1_800_000_000_000L
    private val store = InMemoryThreatFeedSnapshotStore()
    private val repository = ThreatFeedRepository(verifier(), store)

    @Test
    fun safeAddSaturatesBothDirectionsWithoutWrapping() {
        assertEquals(Long.MAX_VALUE, safeAdd(Long.MAX_VALUE - 1L, 2L))
        assertEquals(Long.MIN_VALUE, safeAdd(Long.MIN_VALUE + 1L, -2L))
        assertEquals(42L, safeAdd(100L, -58L))
    }

    @Test
    fun installsLoadsAndPreservesPreviousFeedWhenRollbackIsRejected() {
        val first = payload(version = 2L)
        val installed = repository.install(first, sign(first), now)
        assertEquals(2L, (installed as ThreatFeedInstallResult.Installed).feed.version)

        val loaded = repository.loadActive(now) as ThreatFeedLoadResult.Active
        assertEquals(2L, loaded.feed.version)

        val rollback = payload(version = 1L)
        val rejected = repository.install(rollback, sign(rollback), now)
        assertEquals("ROLLBACK", (rejected as ThreatFeedInstallResult.Rejected).code)
        assertEquals(2L, (repository.loadActive(now) as ThreatFeedLoadResult.Active).feed.version)
    }

    @Test
    fun refusesStoredSnapshotWithInconsistentSignedLifecycleMetadata() {
        val expiry = now + 10_000L
        val bytes = payload(version = 2L, expiry = expiry)
        store.write(
            ThreatFeedSnapshot(
                canonicalPayload = bytes,
                signatureBase64 = sign(bytes),
                highestAcceptedVersion = 1L,
                activatedAtMillis = now,
                declaredExpiresAtMillis = expiry,
            ),
        )

        val loaded = repository.loadActive(now) as ThreatFeedLoadResult.Unavailable

        assertEquals("SNAPSHOT", loaded.code)

        store.write(
            ThreatFeedSnapshot(
                canonicalPayload = bytes,
                signatureBase64 = sign(bytes),
                highestAcceptedVersion = 2L,
                activatedAtMillis = now,
                declaredExpiresAtMillis = expiry + 1L,
            ),
        )

        assertEquals(
            "SNAPSHOT",
            (repository.loadActive(now) as ThreatFeedLoadResult.Unavailable).code,
        )
    }

    @Test
    fun marksExpiredFeedUnavailableThenPrunesItAndErasesOnRequest() {
        val expiry = now + 10L
        val bytes = payload(expiry = expiry)
        assertTrue(repository.install(bytes, sign(bytes), now) is ThreatFeedInstallResult.Installed)
        assertEquals("EXPIRED", (repository.loadActive(expiry) as ThreatFeedLoadResult.Unavailable).code)
        assertEquals(ThreatFeedRetentionResult.RETAINED, repository.pruneExpired(expiry))
        assertEquals(
            ThreatFeedRetentionResult.DELETED,
            repository.pruneExpired(expiry + 14L * 24L * 60L * 60L * 1_000L),
        )
        assertTrue(repository.loadActive(now) is ThreatFeedLoadResult.Missing)

        assertTrue(repository.install(bytes, sign(bytes), now) is ThreatFeedInstallResult.Installed)
        assertEquals(ThreatFeedRetentionResult.DELETED, repository.erase())
        assertTrue(repository.loadActive(now) is ThreatFeedLoadResult.Missing)
    }

    @Test
    fun snapshotCodecRejectsTrailingAndOversizedOrMalformedDataAndCopiesBytes() {
        val bytes = payload()
        val snapshot = ThreatFeedSnapshot(bytes, sign(bytes), 2L, now, now + 10_000L)
        bytes[0] = 'X'.code.toByte()
        assertFalse(snapshot.canonicalPayload[0] == 'X'.code.toByte())
        val leakedPayload = snapshot.canonicalPayload
        leakedPayload[1] = 'X'.code.toByte()
        assertFalse(snapshot.canonicalPayload[1] == 'X'.code.toByte())

        val codec = ThreatFeedSnapshotCodec()
        val encoded = (codec.encode(snapshot) as ThreatFeedStoreResult.Success).value
        val decoded = (codec.decode(encoded) as ThreatFeedStoreResult.Success).value!!
        assertEquals(2L, decoded.highestAcceptedVersion)
        assertTrue(codec.decode(encoded + byteArrayOf(1)) is ThreatFeedStoreResult.Failure)
        assertTrue(codec.decode(byteArrayOf(1, 2, 3)) is ThreatFeedStoreResult.Failure)
    }

    @Test
    fun encryptedStoreMapsCiphertextFailuresWithoutExposingSnapshotData() {
        val fakeStorage = FakeEncryptedStorage()
        val encryptedStore = EncryptedThreatFeedSnapshotStore(fakeStorage)
        val bytes = payload()
        val snapshot = ThreatFeedSnapshot(bytes, sign(bytes), 2L, now, now + 10_000L)

        assertTrue(encryptedStore.write(snapshot) is ThreatFeedStoreResult.Success)
        assertEquals(2L, ((encryptedStore.read() as ThreatFeedStoreResult.Success).value!!).highestAcceptedVersion)

        fakeStorage.readFailure = SecureStorageResult.Failure(SecureStorageFailure.DECRYPTION_FAILED)
        assertEquals(
            ThreatFeedStoreFailure.STORAGE_UNAVAILABLE,
            (encryptedStore.read() as ThreatFeedStoreResult.Failure).reason,
        )
    }

    @Test
    fun updatePlannerIsManualByDefaultAndThrottlesUserEnabledBackgroundWork() {
        val active = ThreatFeedLoadResult.Active(
            feed = (repository.install(payload(version = 2L), sign(payload(version = 2L)), now) as ThreatFeedInstallResult.Installed).feed,
            activatedAtMillis = now,
        )
        assertEquals(null, ThreatFeedUpdatePlanner().nextPlan(active, now))

        val planner = ThreatFeedUpdatePlanner(
            ThreatFeedRefreshPolicy(
                mode = ThreatFeedUpdateMode.USER_ENABLED_BACKGROUND,
                refreshIntervalMillis = 24L * 60L * 60L * 1_000L,
                expiryLeadMillis = 1_000L,
                minimumRetryIntervalMillis = 60L * 60L * 1_000L,
            ),
        )
        val noFeed = planner.nextPlan(null, now, lastAttemptAtMillis = now)
        assertEquals(ThreatFeedUpdateReason.NO_ACTIVE_FEED, noFeed!!.reason)
        assertEquals(now + 60L * 60L * 1_000L, noFeed.dueAtMillis)

        val routine = planner.nextPlan(active, now)
        assertEquals(ThreatFeedUpdateReason.ROUTINE_REFRESH, routine!!.reason)
        assertEquals(now + 9_000L, routine.dueAtMillis)
    }

    private fun verifier(): ThreatFeedVerifier = ThreatFeedVerifier(
        listOf(ThreatFeedKey("test-key", Base64.getEncoder().encodeToString(keyPair.public.encoded))),
    )

    private fun payload(
        version: Long = 2L,
        expiry: Long = now + 10_000L,
    ): ByteArray = """APK_SENTINEL_FEED_V1
version=$version
issuedAtMillis=${now - 1_000L}
expiresAtMillis=$expiry
keyId=test-key
entries:
HOST|bad.example|phishing|HIGH|source-1
""".toByteArray()

    private fun sign(bytes: ByteArray): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(bytes)
            sign()
        },
    )

    private class FakeEncryptedStorage : EncryptedStorage {
        private var stored: ByteArray? = null
        var readFailure: SecureStorageResult.Failure? = null

        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> {
            stored = plaintext.copyOf()
            return SecureStorageResult.Success(Unit)
        }

        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> {
            val failure = readFailure
            return if (failure != null) failure else SecureStorageResult.Success(stored?.copyOf())
        }

        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> {
            stored = null
            return SecureStorageResult.Success(Unit)
        }
    }
}
