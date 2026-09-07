package app.apksentinel.mobile

import app.apksentinel.design.SentinelMotion
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SentinelMotionTest {
    @Test
    fun reducedMotionMakesOwnedTransitionsImmediate() {
        val motion = SentinelMotion(reducedMotion = true)

        assertEquals(0, motion.pressDurationMillis)
        assertEquals(0, motion.stateChangeDurationMillis)
        assertEquals(0, motion.contentChangeDurationMillis)
        assertTrue(motion.reducedMotion)
    }
}
