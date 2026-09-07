package app.apksentinel.mobile

import app.apksentinel.networkmonitor.RawPcapngCaptureLimits
import app.apksentinel.networkmonitor.RawPcapngCaptureRuntime
import app.apksentinel.networkmonitor.RawPcapngCaptureStartRejection
import app.apksentinel.networkmonitor.RawPcapngCaptureStartResult
import app.apksentinel.networkmonitor.RawPcapngCaptureState
import app.apksentinel.networkmonitor.RawPcapngCaptureStatus
import java.io.OutputStream
import kotlin.concurrent.thread

/**
 * Owns the caller-selected document stream for an explicitly started PCAPNG
 * export. The engine deliberately does not own that stream, so this app-layer
 * coordinator keeps it alive across recomposition/configuration changes and
 * closes it only after the writer is terminal.
 *
 * It exposes status counters and stable reason codes only; packet bytes are
 * never retained, inspected, or sent anywhere by this class.
 */
internal class RawPcapngDocumentCoordinator(
    private val runtime: RawPcapngRuntime = EngineRawPcapngRuntime,
    private val worker: ((() -> Unit) -> Unit) = { task ->
        thread(name = "apk-sentinel-pcapng-document-close", isDaemon = true) { task() }
    },
    private val terminalWaitMillis: Long = TERMINAL_WAIT_MILLIS,
) {
    private val lock = Any()
    private var ownedOutput: OutputStream? = null
    private var closingOutput = false
    private var terminalWatcherRunning = false
    private var closeOutcome = RawPcapngDocumentCloseOutcome.NONE

    fun start(output: OutputStream, limits: RawPcapngCaptureLimits): RawPcapngCaptureStartResult {
        val result = synchronized(lock) {
            if (ownedOutput != null) {
                RawPcapngCaptureStartResult.Rejected(RawPcapngCaptureStartRejection.ALREADY_ACTIVE)
            } else {
                runtime.start(output, limits).also { startResult ->
                    if (startResult is RawPcapngCaptureStartResult.Started) {
                        ownedOutput = output
                        closeOutcome = RawPcapngDocumentCloseOutcome.OPEN
                    }
                }
            }
        }
        if (result is RawPcapngCaptureStartResult.Rejected) {
            // The engine never owns a caller stream. A rejected app request
            // must therefore release the newly opened document immediately.
            val closed = closeQuietly(output)
            synchronized(lock) {
                // Do not overwrite the OPEN state of an existing capture when
                // a second document request is rejected.
                if (ownedOutput == null && !closed) {
                    closeOutcome = RawPcapngDocumentCloseOutcome.FAILED
                }
            }
        } else {
            ensureTerminalWatcher()
        }
        return result
    }

    /** Requests a graceful drain. The stream stays open until it is safe to close. */
    fun requestStopAndClose() {
        val shouldStop = synchronized(lock) { ownedOutput != null }
        if (shouldStop) runtime.stop()
        ensureTerminalWatcher()
    }

    /** Call after a monitor stop/revoke or privacy erase to finish document cleanup. */
    fun onMonitoringStopped() = requestStopAndClose()

    fun status(): RawPcapngCaptureStatus {
        val status = runtime.status()
        if (status.state.isTerminal()) closeWhenTerminal(status)
        return status
    }

    fun ownsDocumentStream(): Boolean = synchronized(lock) { ownedOutput != null }

    fun documentCloseOutcome(): RawPcapngDocumentCloseOutcome = synchronized(lock) { closeOutcome }

    private fun ensureTerminalWatcher() {
        val shouldStart = synchronized(lock) {
            if (ownedOutput == null || terminalWatcherRunning) false else {
                terminalWatcherRunning = true
                true
            }
        }
        if (!shouldStart) return
        worker {
            try {
                // awaitStopped is deliberately bounded. Repeating the bounded
                // wait prevents a blocked document provider from being closed
                // while its writer still owns it, without leaking the stream.
                while (ownsDocumentStream()) {
                    if (runtime.awaitStopped(terminalWaitMillis)) {
                        closeWhenTerminal(runtime.status())
                        break
                    }
                }
            } finally {
                synchronized(lock) { terminalWatcherRunning = false }
                // A close/start race cannot occur while a stream is owned, but
                // restart a watcher if a terminal state appeared just after it
                // finished its last bounded wait.
                if (ownsDocumentStream() && runtime.status().state.isTerminal()) ensureTerminalWatcher()
            }
        }
    }

    private fun closeWhenTerminal(status: RawPcapngCaptureStatus) {
        if (!status.state.isTerminal()) return
        val output = synchronized(lock) {
            if (closingOutput) return
            val current = ownedOutput ?: return
            closingOutput = true
            current
        }
        val closed = closeQuietly(output)
        synchronized(lock) {
            if (ownedOutput === output) {
                ownedOutput = null
                closeOutcome = if (closed) {
                    RawPcapngDocumentCloseOutcome.CLOSED
                } else {
                    RawPcapngDocumentCloseOutcome.FAILED
                }
            }
            closingOutput = false
        }
    }

    private fun closeQuietly(output: OutputStream): Boolean = runCatching { output.close() }.isSuccess

    private fun RawPcapngCaptureState.isTerminal(): Boolean =
        this == RawPcapngCaptureState.STOPPED || this == RawPcapngCaptureState.FAILED

    private companion object {
        const val TERMINAL_WAIT_MILLIS = 1_000L
    }
}

/** Payload-free state for the caller-owned document finalization step. */
internal enum class RawPcapngDocumentCloseOutcome {
    NONE,
    OPEN,
    CLOSED,
    FAILED,
}

/** Narrow adapter keeps lifecycle behaviour unit-testable without Android or packet payloads. */
internal interface RawPcapngRuntime {
    fun start(output: OutputStream, limits: RawPcapngCaptureLimits): RawPcapngCaptureStartResult
    fun stop()
    fun awaitStopped(timeoutMillis: Long): Boolean
    fun status(): RawPcapngCaptureStatus
}

private object EngineRawPcapngRuntime : RawPcapngRuntime {
    override fun start(output: OutputStream, limits: RawPcapngCaptureLimits): RawPcapngCaptureStartResult =
        RawPcapngCaptureRuntime.start(output, limits)

    override fun stop() = RawPcapngCaptureRuntime.stop()

    override fun awaitStopped(timeoutMillis: Long): Boolean = RawPcapngCaptureRuntime.awaitStopped(timeoutMillis)

    override fun status(): RawPcapngCaptureStatus = RawPcapngCaptureRuntime.status()
}

/** Process-lifetime ownership is intentional: a Compose configuration change must not close an active export. */
internal object AppRawPcapngDocumentCoordinator {
    private val delegate = RawPcapngDocumentCoordinator()

    fun start(output: OutputStream, limits: RawPcapngCaptureLimits) = delegate.start(output, limits)
    fun requestStopAndClose() = delegate.requestStopAndClose()
    fun onMonitoringStopped() = delegate.onMonitoringStopped()
    fun status() = delegate.status()
    fun ownsDocumentStream() = delegate.ownsDocumentStream()
    fun documentCloseOutcome() = delegate.documentCloseOutcome()
}
