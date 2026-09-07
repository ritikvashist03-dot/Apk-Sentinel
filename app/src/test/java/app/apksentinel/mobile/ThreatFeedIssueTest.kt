package app.apksentinel.mobile

import app.apksentinel.engine.threatintel.ThreatFeedStoreFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatFeedIssueTest {
    @Test
    fun verifierCodes_mapToStableLocalizedIssueCategories() {
        assertEquals(ThreatFeedIssue.SIGNATURE_INVALID, ThreatFeedIssue.fromEngineCode("SIGNATURE"))
        assertEquals(ThreatFeedIssue.SIGNING_KEY_UNTRUSTED, ThreatFeedIssue.fromEngineCode("KEY_REVOKED"))
        assertEquals(ThreatFeedIssue.UNKNOWN, ThreatFeedIssue.fromEngineCode("FUTURE_ENGINE_CODE"))
    }

    @Test
    fun persistenceFailures_mapWithoutFormattingEngineNamesForTheUi() {
        assertEquals(
            ThreatFeedIssue.SECURE_STORAGE_UNAVAILABLE,
            ThreatFeedIssue.fromStoreFailure(ThreatFeedStoreFailure.STORAGE_UNAVAILABLE),
        )
        assertEquals(
            ThreatFeedIssue.SNAPSHOT_TOO_LARGE,
            ThreatFeedIssue.fromStoreFailure(ThreatFeedStoreFailure.SNAPSHOT_TOO_LARGE),
        )
    }
}
