package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Test

class OnboardingAccessibilityTest {
    @Test
    fun pageAnnouncementCombinesLocalizedHeadingAndProgressExactlyOnce() {
        assertEquals(
            "अपने ऐप को समझें। चरण 2 / 3",
            OnboardingAccessibilityContract.pageAnnouncement("अपने ऐप को समझें", "चरण 2 / 3"),
        )
        assertEquals(1, OnboardingAccessibilityContract.LIVE_REGION_NODE_COUNT)
    }

    @Test
    fun reducedMotionRemovesThePageTransitionDuration() {
        assertEquals(0, OnboardingAccessibilityContract.contentChangeDurationMillis(true, 240))
        assertEquals(240, OnboardingAccessibilityContract.contentChangeDurationMillis(false, 240))
        assertEquals(0, OnboardingAccessibilityContract.contentChangeDurationMillis(false, -1))
    }
}
