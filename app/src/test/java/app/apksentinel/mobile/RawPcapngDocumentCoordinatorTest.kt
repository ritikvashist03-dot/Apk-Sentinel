package app.apksentinel.mobile

import app.apksentinel.networkmonitor.RawPcapngCaptureLimits
import app.apksentinel.networkmonitor.RawPcapngCaptureStartRejection
import app.apksentinel.networkmonitor.RawPcapngCaptureStartResult
import app.apksentinel.networkmonitor.RawPcapngCaptureState
import app.apksentinel.networkmonitor.RawPcapngCaptureStatus
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RawPcapngDocumentCoordinatorTest {
    @Test
    fun stop_waitsForTerminalWriter_thenClosesCallerDocument() {
        val runtime = FakeRuntime()
        var watcher: (() -> Unit)? = null
        val coordinator = RawPcapngDocumentCoordinator(
            runtime = runtime,
            worker = { task -> watcher = task },
            terminalWaitMillis = 1L,
        )
        val output = CloseTrackingOutputStream()

        coordinator.start(output, RawPcapngCaptureLimits())
        assertTrue(coordinator.ownsDocumentStream())
        assertFalse(output.closed)

        coordinator.requestStopAndClose()
        watcher!!.invoke()

        assertTrue(runtime.stopRequested)
        assertTrue(output.closed)
        assertFalse(coordinator.ownsDocumentStream())
        assertEquals(RawPcapngDocumentCloseOutcome.CLOSED, coordinator.documentCloseOutcome())
    }

    @Test
    fun rejectedStart_closesNewlyOpenedDocumentImmediately() {
        val runtime = FakeRuntime(startResult = RawPcapngCaptureStartResult.Rejected(
            RawPcapngCaptureStartRejection.WRITER_START_FAILED,
        ))
        val coordinator = RawPcapngDocumentCoordinator(runtime = runtime)
        val output = CloseTrackingOutputStream()

        coordinator.start(output, RawPcapngCaptureLimits())

        assertTrue(output.closed)
        assertFalse(coordinator.ownsDocumentStream())
    }

    @Test
    fun secondDocumentRequestDoesNotOverwriteActiveDocumentState() {
        val runtime = FakeRuntime()
        val coordinator = RawPcapngDocumentCoordinator(runtime = runtime, worker = { })
        val active = CloseTrackingOutputStream()
        val rejected = CloseTrackingOutputStream()
        coordinator.start(active, RawPcapngCaptureLimits())

        val result = coordinator.start(rejected, RawPcapngCaptureLimits())

        assertTrue(result is RawPcapngCaptureStartResult.Rejected)
        assertTrue(rejected.closed)
        assertFalse(active.closed)
        assertTrue(coordinator.ownsDocumentStream())
        assertEquals(RawPcapngDocumentCloseOutcome.OPEN, coordinator.documentCloseOutcome())
    }

    @Test
    fun terminalStatus_closesDocumentEvenWhenVpnStoppedItFirst() {
        val runtime = FakeRuntime()
        var watcher: (() -> Unit)? = null
        val coordinator = RawPcapngDocumentCoordinator(runtime = runtime, worker = { task -> watcher = task })
        val output = CloseTrackingOutputStream()

        coordinator.start(output, RawPcapngCaptureLimits())
        runtime.status = RawPcapngCaptureStatus(state = RawPcapngCaptureState.STOPPED)
        coordinator.status()

        assertTrue(output.closed)
        assertFalse(coordinator.ownsDocumentStream())
        // The daemon watcher may still be queued, but has no document left to close.
        watcher!!.invoke()
        assertTrue(output.closed)
    }

    @Test
    fun documentCloseFailureIsExposedWithoutExceptionText() {
        val runtime = FakeRuntime()
        val coordinator = RawPcapngDocumentCoordinator(runtime = runtime, worker = { })
        val output = CloseFailingOutputStream()
        coordinator.start(output, RawPcapngCaptureLimits())
        runtime.status = RawPcapngCaptureStatus(state = RawPcapngCaptureState.STOPPED)

        coordinator.status()

        assertFalse(coordinator.ownsDocumentStream())
        assertEquals(RawPcapngDocumentCloseOutcome.FAILED, coordinator.documentCloseOutcome())
    }

    private class FakeRuntime(
        private val startResult: RawPcapngCaptureStartResult = RawPcapngCaptureStartResult.Started(1L),
    ) : RawPcapngRuntime {
        var status = RawPcapngCaptureStatus(state = RawPcapngCaptureState.RUNNING)
        var stopRequested = false

        override fun start(output: OutputStream, limits: RawPcapngCaptureLimits): RawPcapngCaptureStartResult = startResult

        override fun stop() {
            stopRequested = true
            status = RawPcapngCaptureStatus(state = RawPcapngCaptureState.STOPPED)
        }

        override fun awaitStopped(timeoutMillis: Long): Boolean =
            status.state == RawPcapngCaptureState.STOPPED || status.state == RawPcapngCaptureState.FAILED

        override fun status(): RawPcapngCaptureStatus = status
    }

    private class CloseTrackingOutputStream : ByteArrayOutputStream() {
        var closed = false
        override fun close() {
            closed = true
            super.close()
        }
    }

    private class CloseFailingOutputStream : ByteArrayOutputStream() {
        override fun close() {
            throw java.io.IOException("provider detail must not escape")
        }
    }
}
