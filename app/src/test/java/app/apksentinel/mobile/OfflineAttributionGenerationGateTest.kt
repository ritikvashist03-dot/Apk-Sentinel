package app.apksentinel.mobile

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineAttributionGenerationGateTest {
    @Test
    fun eraseInvalidatesQueuedWorkButAllowsALaterExplicitInstall() {
        val gate = OfflineAttributionGenerationGate()
        val inFlightInstall = gate.capture()
        val inFlightInitialize = gate.capture()

        gate.advance()

        assertFalse(gate.isCurrent(inFlightInstall))
        assertFalse(gate.isCurrent(inFlightInitialize))
        val postEraseAction = gate.capture()
        assertTrue(gate.isCurrent(postEraseAction))
    }
}
