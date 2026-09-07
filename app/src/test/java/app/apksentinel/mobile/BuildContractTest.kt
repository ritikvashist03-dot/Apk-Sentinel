package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Test

class BuildContractTest {
    @Test
    fun applicationId_isStablePrototypeIdentity() {
        assertEquals("app.apksentinel.mobile", BuildConfig.APPLICATION_ID.removeSuffix(".debug"))
    }
}

