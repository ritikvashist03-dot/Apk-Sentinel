package app.apksentinel.networkmonitor

import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageFailure
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.nio.ByteBuffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EncryptedNetworkHistoryTest {
    @Test
    fun defaultPolicyIsSevenDaysButNothingPersistsUntilComposedAndOffered() {
        val storage = RecordingStorage()
        val history = EncryptedNetworkHistoryController(storage)

        assertEquals(DurableHistoryRetentionPolicy.SEVEN_DAYS, history.snapshot().policy)
        assertEquals(DurableHistoryReadState.NOT_LOADED, history.snapshot().state)
        assertEquals(0, storage.writeCount)
        history.close()
    }

    @Test
    fun sessionOnlyNeverWritesAndSafeProjectionExcludesDetailAndEndpointData() {
        val storage = RecordingStorage()
        val history = EncryptedNetworkHistoryController(
            storage = storage,
            policy = DurableHistoryRetentionPolicy.SESSION_ONLY,
        )
        history.offer(packetEvent(at = 1L))
        history.offer(MonitorStateEvent("session-secret", 2L, MonitorLifecycleState.ACTIVE, "detail-secret-should-not-persist"))

        assertFalse(history.flush(100L))
        assertEquals(DurableHistoryReadState.SESSION_ONLY, history.snapshot().state)
        assertEquals(0, storage.writeCount)
        history.close()
    }

    @Test
    fun writesOnlyMetadataAndRoundTripsLengthPrefixedRecords() {
        val storage = RecordingStorage()
        val history = EncryptedNetworkHistoryController(storage = storage, clock = FixedClock(10_000L))
        history.offer(packetEvent(at = 9_000L))
        history.offer(MonitorStateEvent("session-secret", 9_100L, MonitorLifecycleState.ACTIVE, "detail-secret-should-not-persist"))
        assertTrue(history.flush(1_000L))

        assertTrue(storage.writeCount >= 1)
        val stored = requireNotNull(storage.value)
        assertFalse(stored.decodeToString().contains("detail-secret-should-not-persist"))
        assertFalse(stored.decodeToString().contains("198.51.100.99"))
        assertFalse(stored.decodeToString().contains("example.test"))

        val reopened = EncryptedNetworkHistoryController(storage = storage, clock = FixedClock(10_000L))
        reopened.requestLoad()
        assertTrue(reopened.flush(1_000L))
        val snapshot = reopened.snapshot()
        assertEquals(DurableHistoryReadState.READY, snapshot.state)
        assertEquals(2, snapshot.records.size)
        assertTrue(snapshot.records.any { it is DurableHistoryRecord.Packet })
        history.close()
        reopened.close()
    }

    @Test
    fun corruptAndDecryptFailuresAreTypedAndNeverOverwritten() {
        val corrupt = RecordingStorage(byteArrayOf(1, 2, 3))
        val corruptHistory = EncryptedNetworkHistoryController(corrupt, clock = FixedClock(10_000L))
        corruptHistory.requestLoad()
        assertTrue(corruptHistory.flush(1_000L))
        assertEquals(DurableHistoryFailure.CORRUPT_OR_UNSUPPORTED, corruptHistory.snapshot().failure)
        corruptHistory.offer(packetEvent(at = 9_000L))
        assertTrue(corruptHistory.flush(1_000L))
        assertEquals(0, corrupt.writeCount)

        val decrypt = FailingReadStorage(SecureStorageFailure.DECRYPTION_FAILED)
        val decryptHistory = EncryptedNetworkHistoryController(decrypt, clock = FixedClock(10_000L))
        decryptHistory.requestLoad()
        assertTrue(decryptHistory.flush(1_000L))
        assertEquals(DurableHistoryFailure.DECRYPTION_FAILED, decryptHistory.snapshot().failure)
        corruptHistory.close()
        decryptHistory.close()
    }

    @Test
    fun hostileOversizedLengthPrefixIsRejectedBeforeAllocation() {
        val hostile = ByteBuffer.allocate(14)
            .putInt(0x41534831) // ASH1
            .putShort(1)
            .putInt(1)
            .putInt(4_096)
            .array()
        val storage = RecordingStorage(hostile)
        val history = EncryptedNetworkHistoryController(storage, clock = FixedClock(10_000L))

        history.requestLoad()
        assertTrue(history.flush(1_000L))
        assertEquals(DurableHistoryFailure.CORRUPT_OR_UNSUPPORTED, history.snapshot().failure)
        assertEquals(0, storage.writeCount)
        history.close()
    }

    @Test
    fun explicitTimestampPruningSurvivesClockRollbackAndLimitsRemainBounded() {
        val storage = RecordingStorage()
        val limits = DurableHistoryLimits(maximumRecords = 2, maximumPlaintextBytes = 2_048, maximumRecordBytes = 256, maximumIngressRecords = 8)
        val initial = EncryptedNetworkHistoryController(storage, limits = limits, clock = FixedClock(10L * DAY))
        initial.offer(MonitorStateEvent("s", 9L * DAY, MonitorLifecycleState.ACTIVE, "ignored"))
        initial.offer(MonitorStateEvent("s", 9L * DAY + 1L, MonitorLifecycleState.STOPPING, "ignored"))
        initial.offer(MonitorStateEvent("s", 9L * DAY + 2L, MonitorLifecycleState.STOPPED, "ignored"))
        assertTrue(initial.flush(1_000L))
        assertTrue(initial.snapshot().records.size <= 2)
        assertTrue(initial.snapshot().droppedByLimitRecords >= 1L)

        val afterRollback = EncryptedNetworkHistoryController(storage, limits = limits, clock = FixedClock(1L * DAY))
        afterRollback.requestLoad()
        assertTrue(afterRollback.flush(1_000L))
        assertTrue(afterRollback.snapshot().records.isNotEmpty())
        initial.close()
        afterRollback.close()
    }

    @Test
    fun explicitEraseRemovesCiphertextThenDedicatedKey() {
        val storage = RecordingStorage()
        var erasedKey = false
        val history = EncryptedNetworkHistoryController(
            storage = storage,
            keyEraser = DurableHistoryKeyEraser { erasedKey = true; true },
            clock = FixedClock(10_000L),
        )
        history.offer(packetEvent(at = 9_000L))
        assertTrue(history.flush(1_000L))
        val erased = history.erase(1_000L)

        assertEquals(DurableHistoryReadState.ERASED, erased.state)
        assertTrue(erasedKey)
        assertTrue(storage.removeCount >= 1)
        assertEquals(null, storage.value)
        history.close()
    }

    @Test
    fun writeFailureCountsDrainedIngressAsDropped() {
        val history = EncryptedNetworkHistoryController(FailingWriteStorage(), clock = FixedClock(10_000L))
        history.offer(packetEvent(at = 9_000L))

        assertTrue(history.flush(1_000L))
        assertEquals(DurableHistoryFailure.STORAGE_WRITE_FAILED, history.snapshot().failure)
        assertTrue(history.snapshot().droppedIngressRecords >= 1L)
        history.close()
    }

    @Test
    fun closeRaceRejectsLateOfferAndFlushWithoutThrowing() {
        val history = EncryptedNetworkHistoryController(RecordingStorage(), clock = FixedClock(10_000L))
        history.close()

        history.offer(packetEvent(at = 9_000L))
        assertFalse(history.flush(10L))
        assertTrue(history.snapshot().records.isEmpty())
    }

    private fun packetEvent(at: Long): PacketObservedEvent = PacketObservedEvent(
        sessionId = "session-secret",
        atMillis = at,
        flowId = "flow-secret",
        direction = PacketDirection.OUTBOUND,
        attribution = AppAttribution.Known("app.example.secret", uid = 10_001),
        metadata = PacketMetadata(
            ipVersion = IpVersion.IPV4,
            ipProtocolNumber = 6,
            transportProtocol = TransportProtocol.TCP,
            source = NetworkEndpoint("10.0.0.2", 44_444),
            destination = NetworkEndpoint("198.51.100.99", 443),
            declaredIpPacketBytes = null,
            capturedPacketBytes = 120,
            dns = DnsMetadata(
                messageKind = DnsMessageKind.QUERY,
                transactionId = 4,
                questionCount = 1,
                responseCode = null,
                questionName = SafeDnsName.PlaintextAfterExplicitConsent("example.test"),
                questionType = 1,
                status = DnsParseStatus.PARSED,
            ),
        ),
    )

    private class FixedClock(private val now: Long) : EpochClock {
        override fun nowMillis(): Long = now
    }

    private class RecordingStorage(initial: ByteArray? = null) : EncryptedStorage {
        var value: ByteArray? = initial?.copyOf()
        var writeCount = 0
        var removeCount = 0
        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> {
            writeCount += 1
            value = plaintext.copyOf()
            return SecureStorageResult.Success(Unit)
        }
        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> = SecureStorageResult.Success(value?.copyOf())
        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> {
            removeCount += 1
            value = null
            return SecureStorageResult.Success(Unit)
        }
    }

    private class FailingReadStorage(private val failure: SecureStorageFailure) : EncryptedStorage {
        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> = SecureStorageResult.Success(Unit)
        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> = SecureStorageResult.Failure(failure)
        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> = SecureStorageResult.Success(Unit)
    }

    private class FailingWriteStorage : EncryptedStorage {
        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> =
            SecureStorageResult.Failure(SecureStorageFailure.BACKING_STORE_FAILURE)
        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> = SecureStorageResult.Success(null)
        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> = SecureStorageResult.Success(Unit)
    }

    private companion object {
        const val DAY = 24L * 60L * 60L * 1_000L
    }
}
