package app.apksentinel.mobile

import app.apksentinel.networkmonitor.MonitorLifecycleState
import org.junit.Assert.assertEquals
import org.junit.Test

class HomeEvidenceAggregatorTest {
    @Test
    fun untouchedHomeChoosesOneBeginnerNextAction() {
        val summary = HomeEvidenceAggregator.from(MonitorLifecycleState.STOPPED)

        assertEquals("device", summary.nextActionKey)
        assertEquals(HomeEvidenceState.NOT_CHECKED, summary.items.first { it.key == "device" }.state)
    }

    @Test
    fun checkedNetworkDoesNotHideUnknownAppAndAnalysisCoverage() {
        val summary = HomeEvidenceAggregator.from(MonitorLifecycleState.ACTIVE)

        assertEquals(HomeEvidenceState.LOCAL_EVIDENCE, summary.items.first { it.key == "network" }.state)
        assertEquals(HomeEvidenceState.NOT_CHECKED, summary.items.first { it.key == "apps" }.state)
        assertEquals(HomeEvidenceState.NOT_CHECKED, summary.items.first { it.key == "analyze" }.state)
    }
}
