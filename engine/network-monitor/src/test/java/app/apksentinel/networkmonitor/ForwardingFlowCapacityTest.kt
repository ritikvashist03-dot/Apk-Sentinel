package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ForwardingFlowCapacityTest {
    @Test
    fun neverAdmitsMoreFlowsThanItsBoundAndCanRecoverAfterClose() {
        val capacity = ForwardingFlowCapacity(2)

        assertTrue(capacity.tryAcquire())
        assertTrue(capacity.tryAcquire())
        assertFalse(capacity.tryAcquire())
        assertEquals(2, capacity.activeCount())

        capacity.release()
        assertEquals(1, capacity.activeCount())
        assertTrue(capacity.tryAcquire())
        assertEquals(2, capacity.activeCount())
    }
}
