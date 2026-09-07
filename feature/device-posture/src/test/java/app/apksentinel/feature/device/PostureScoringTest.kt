package app.apksentinel.feature.device

import org.junit.Assert.assertEquals
import org.junit.Test
import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.time.YearMonth

class PostureCoverageTest {
    private class FakeStorage : EncryptedStorage {
        var value: ByteArray? = null
        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> { value = plaintext.copyOf(); return SecureStorageResult.Success(Unit) }
        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> = SecureStorageResult.Success(value?.copyOf())
        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> { value = null; return SecureStorageResult.Success(Unit) }
    }

    private fun snapshot(state: CheckState, mode: PostureEvidenceMode = PostureEvidenceMode.AUTOMATICALLY_OBSERVED, time: Long = 1_000L) =
        DevicePostureSnapshot(listOf(PostureCheck("screen_lock", "", "", state, evidenceMode = mode)), time)

    @Test fun coverageKeepsUnknownSeparateFromVerifiedEvidence() {
        val snapshot = DevicePostureSnapshot(
            checks = listOf(
                PostureCheck("a", "a", "", CheckState.PASS),
                PostureCheck("b", "b", "", CheckState.UNKNOWN),
                PostureCheck("c", "c", "", CheckState.ATTENTION),
            ),
            generatedAtMillis = 1L,
        )
        assertEquals(2, snapshot.coverage.verifiedCount)
        assertEquals(1, snapshot.coverage.attentionCount)
        assertEquals(1, snapshot.coverage.unknownCount)
    }

    @Test fun missingCommonRootIndicatorsDoesNotClaimVerifiedSafety() {
        assertEquals(CheckState.UNKNOWN, rootIndicatorState(indicatorFound = false))
        assertEquals(CheckState.ATTENTION, rootIndicatorState(indicatorFound = true))
    }

    @Test fun guidedReviewIsNotCountedAsVerifiedEvidence() {
        val guided = PostureCheck(
            id = "guided",
            title = "guided",
            explanation = "",
            state = CheckState.UNKNOWN,
            evidenceMode = PostureEvidenceMode.USER_GUIDED_REVIEW,
        )
        val coverage = DevicePostureSnapshot(listOf(guided), 1L).coverage
        assertEquals(0, coverage.verifiedCount)
        assertEquals(1, coverage.unknownCount)
    }

    @Test fun partlyObservedPassIsAResultButNotFullyVerified() {
        val partial = PostureCheck(
            id = "partial",
            title = "partial",
            explanation = "",
            state = CheckState.PASS,
            evidenceMode = PostureEvidenceMode.PARTLY_OBSERVED,
        )
        val coverage = DevicePostureSnapshot(listOf(partial), 1L).coverage
        assertEquals(1, coverage.resultCount)
        assertEquals(0, coverage.verifiedCount)
        assertEquals(1, coverage.partialResultCount)
    }

    @Test fun patchDateClassificationKeepsMalformedAndFutureEvidenceUnknown() {
        val now = YearMonth.of(2026, 8)
        assertEquals(CheckState.UNKNOWN, securityPatchState("", now))
        assertEquals(CheckState.UNKNOWN, securityPatchState("not-a-date", now))
        assertEquals(CheckState.UNKNOWN, securityPatchState("2026-09-01", now))
        assertEquals(CheckState.PASS, securityPatchState("2026-05-05", now))
        assertEquals(CheckState.ATTENTION, securityPatchState("2026-04-05", now))
    }

    @Test fun codecRejectsHostileOrOversizedRecordsAndKeepsOnlyTypedFields() {
        assertEquals(null, PostureHistoryCodec.decode("v1\n1|bad-id!|PASS|AUTOMATICALLY_OBSERVED\n".encodeToByteArray(), 2_000L))
        assertEquals(null, PostureHistoryCodec.decode(ByteArray(PostureHistoryCodec.MAX_BYTES + 1), 2_000L))
        val encoded = requireNotNull(PostureHistoryCodec.encode(listOf(PostureObservation("screen_lock", CheckState.PASS, PostureEvidenceMode.AUTOMATICALLY_OBSERVED, 1_000L))))
        assertEquals(1, requireNotNull(PostureHistoryCodec.decode(encoded, 2_000L)).size)
    }

    @Test fun historyComparesObservableStatesButNeverAttributesGuidedReviewChanges() {
        val controller = DevicePostureHistoryController(FakeStorage())
        assertEquals(PostureComparison.UNVERIFIABLE, controller.compareAndRecord(snapshot(CheckState.PASS), 1_000L).comparisons.single())
        assertEquals(PostureComparison.UNCHANGED, controller.compareAndRecord(snapshot(CheckState.PASS, time = 2_000L), 2_000L).comparisons.single())
        assertEquals(PostureComparison.CHANGED, controller.compareAndRecord(snapshot(CheckState.ATTENTION, time = 3_000L), 3_000L).comparisons.single())
        assertEquals(PostureComparison.UNVERIFIABLE, controller.compareAndRecord(snapshot(CheckState.UNKNOWN, PostureEvidenceMode.USER_GUIDED_REVIEW, 4_000L), 4_000L).comparisons.single())
    }

    @Test fun historyNeverComparesPartialOrUnavailableEvidence() {
        val partial = DevicePostureHistoryController(FakeStorage())
        partial.compareAndRecord(snapshot(CheckState.PASS, PostureEvidenceMode.PARTLY_OBSERVED, 1_000L), 1_000L)
        assertEquals(PostureComparison.UNVERIFIABLE, partial.compareAndRecord(snapshot(CheckState.PASS, PostureEvidenceMode.PARTLY_OBSERVED, 2_000L), 2_000L).comparisons.single())

        val unavailable = DevicePostureHistoryController(FakeStorage())
        unavailable.compareAndRecord(snapshot(CheckState.PASS, PostureEvidenceMode.UNAVAILABLE, 1_000L), 1_000L)
        assertEquals(PostureComparison.UNVERIFIABLE, unavailable.compareAndRecord(snapshot(CheckState.PASS, PostureEvidenceMode.UNAVAILABLE, 2_000L), 2_000L).comparisons.single())
    }

    @Test fun eraseRemovesEncryptedHistoryAndClockFailureDoesNotWrite() {
        val storage = FakeStorage()
        val controller = DevicePostureHistoryController(storage)
        controller.compareAndRecord(snapshot(CheckState.PASS), 1_000L)
        assertEquals(true, controller.erase())
        assertEquals(null, storage.value)
        assertEquals(PostureHistoryFailure.CLOCK_UNTRUSTWORTHY, controller.compareAndRecord(snapshot(CheckState.PASS, time = 0L), 0L).failure)
        assertEquals(null, storage.value)
    }
}
