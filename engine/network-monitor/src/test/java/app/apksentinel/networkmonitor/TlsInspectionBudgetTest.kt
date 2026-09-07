package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

class TlsInspectionBudgetTest {
    @Test
    fun consentIsFreshOneShotAndRejectsWrongNonceOrVersion() {
        TlsInspectionSessionConsentRegistry.resetForTests()
        val issued = TlsInspectionSessionConsentRegistry.issue("tls-session-v2", nowMillis = 1_000L)

        assertFalse(
            TlsInspectionSessionConsentRegistry.consume(
                issued.copy(nonce = "wrong"),
                nowMillis = 1_001L,
            ),
        )
        assertTrue(TlsInspectionSessionConsentRegistry.consume(issued, nowMillis = 1_001L))
        assertFalse(TlsInspectionSessionConsentRegistry.consume(issued, nowMillis = 1_002L))

        val mismatched = TlsInspectionSessionConsentRegistry.issue("tls-session-v2", nowMillis = 2_000L)
        assertFalse(
            TlsInspectionSessionConsentRegistry.consume(
                mismatched.copy(version = "wrong-version"),
                nowMillis = 2_001L,
            ),
        )
        assertFalse(TlsInspectionSessionConsentRegistry.consume(mismatched, nowMillis = 2_002L))
    }

    @Test
    fun staleConsentAndRejectedAttemptCannotBeReused() {
        TlsInspectionSessionConsentRegistry.resetForTests()
        val issued = TlsInspectionSessionConsentRegistry.issue("tls-session-v2", nowMillis = 10_000L)
        assertFalse(
            TlsInspectionSessionConsentRegistry.consume(
                issued,
                nowMillis = 10_000L + TlsInspectionSessionConsentRegistry.MAX_AGE_MILLIS + 1L,
            ),
        )
        assertFalse(TlsInspectionSessionConsentRegistry.consume(issued, nowMillis = 10_001L))

        val rejected = TlsInspectionSessionConsentRegistry.issue("tls-session-v2", nowMillis = 20_000L)
        TlsInspectionSessionConsentRegistry.revoke(rejected.nonce)
        assertFalse(TlsInspectionSessionConsentRegistry.consume(rejected, nowMillis = 20_001L))
    }

    @Test
    fun budgetCountsBothDirectionsAndEnforcesPerFlowAndAggregateCaps() {
        var now = 1_000_000_000L
        val budget = TlsInspectionBudget(
            maximumSessionBytes = 10,
            maximumBytesPerFlow = 6,
            maximumDurationMillis = 10_000L,
            nowNanos = { now },
        )
        val first = (budget.openFlow() as TlsInspectionBudgetOpenResult.Accepted).flowId
        assertNull(budget.admit(first, 4)) // client direction
        assertNull(budget.admit(first, 2)) // upstream direction
        assertEquals(TlsInspectionRouteFailure.BUFFER_LIMIT, budget.admit(first, 1))

        val second = (budget.openFlow() as TlsInspectionBudgetOpenResult.Accepted).flowId
        assertNull(budget.admit(second, 4))
        assertEquals(TlsInspectionRouteFailure.BUFFER_LIMIT, budget.admit(second, 1))
        assertEquals(10, budget.snapshot().sessionBytes)

        // Aggregate exhaustion is terminal for this budget. Use a fresh
        // budget to exercise the independent monotonic-duration boundary.
        val timeoutBudget = TlsInspectionBudget(
            maximumSessionBytes = 10,
            maximumBytesPerFlow = 6,
            maximumDurationMillis = 10_000L,
            nowNanos = { now },
        )
        val timeoutFlow = (timeoutBudget.openFlow() as TlsInspectionBudgetOpenResult.Accepted).flowId
        now = 11_001_000_000L
        assertEquals(TlsInspectionRouteFailure.HANDSHAKE_TIMEOUT, timeoutBudget.admit(timeoutFlow, 0))
    }

    @Test
    fun durationStopAndIntegerBoundaryAreFailClosedWithoutOverflow() {
        var now = 100L
        val budget = TlsInspectionBudget(
            maximumSessionBytes = Int.MAX_VALUE,
            maximumBytesPerFlow = Int.MAX_VALUE,
            maximumDurationMillis = Long.MAX_VALUE,
            nowNanos = { now },
        )
        val flow = (budget.openFlow() as TlsInspectionBudgetOpenResult.Accepted).flowId
        assertNull(budget.admit(flow, Int.MAX_VALUE))
        assertEquals(TlsInspectionRouteFailure.BUFFER_LIMIT, budget.admit(flow, 1))
        budget.stop()
        assertEquals(TlsInspectionRouteFailure.CLOSED, budget.admit(flow, 0))
        now = Long.MAX_VALUE
        assertEquals(TlsInspectionRouteFailure.CLOSED, budget.admit(flow, 0))
    }

    @Test
    fun monotonicDurationDoesNotResetAfterClockRollback() {
        var nowNanos = 1_000_000_000L
        val budget = TlsInspectionBudget(
            maximumSessionBytes = 4_096,
            maximumBytesPerFlow = 4_096,
            maximumDurationMillis = 1_000L,
            nowNanos = { nowNanos },
        )
        val flow = (budget.openFlow() as TlsInspectionBudgetOpenResult.Accepted).flowId
        nowNanos = 500_000_000L
        assertNull(budget.admit(flow, 0))
        nowNanos = 1_999_999_999L
        assertNull(budget.admit(flow, 0))
        nowNanos = 2_000_000_000L
        assertEquals(TlsInspectionRouteFailure.HANDSHAKE_TIMEOUT, budget.admit(flow, 0))
    }

    @Test
    fun concurrentAdmissionsNeverExceedAggregateCap() {
        val budget = TlsInspectionBudget(
            maximumSessionBytes = 16,
            maximumBytesPerFlow = 16,
            maximumDurationMillis = 10_000L,
        )
        val flow = (budget.openFlow() as TlsInspectionBudgetOpenResult.Accepted).flowId
        val executor = Executors.newFixedThreadPool(8)
        val ready = CountDownLatch(1)
        val done = CountDownLatch(16)
        val successes = AtomicInteger()
        repeat(16) {
            executor.execute {
                ready.await()
                if (budget.admit(flow, 1) == null) successes.incrementAndGet()
                done.countDown()
            }
        }
        ready.countDown()
        done.await()
        executor.shutdownNow()
        assertEquals(16, successes.get())
        assertEquals(16, budget.snapshot().sessionBytes)
    }
}
