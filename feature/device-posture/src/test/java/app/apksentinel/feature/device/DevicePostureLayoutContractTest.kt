package app.apksentinel.feature.device

import org.junit.Assert.assertEquals
import org.junit.Test

class DevicePostureLayoutContractTest {
    @Test
    fun postureKeepsOneResponsiveReadingSurfaceAndOneScrollOwner() {
        assertEquals(720, DevicePostureLayoutContract.READING_MAX_WIDTH_DP)
        assertEquals(1, DevicePostureLayoutContract.VERTICAL_SCROLL_OWNER_COUNT)
    }
}
