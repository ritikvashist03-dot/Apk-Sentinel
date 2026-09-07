package app.apksentinel.engine.rootcapture

import java.io.OutputStream
import java.util.UUID

/**
 * State machine for one small, temporary rooted capture. It has no
 * persistence, no background restart, no VPN, no networking, and no UI.
 */
class RootCaptureController(
    private val runner: RootCapturePrivilegeRunner,
    private val outputStore: RootCaptureOutputStore,
    private val interfaces: RootCaptureTrustedInterfaceMap = RootCaptureTrustedInterfaceMap(),
    private val clock: RootCaptureClock = SystemRootCaptureClock,
    private val scheduler: RootCaptureScheduler,
    private val pumpExecutor: RootCapturePumpExecutor,
) {
    private val lock = Any()
    private var active: ActiveCapture? = null
    private var starting = false
    private var startGeneration = 0L
    private var cancelledStartGeneration: Long? = null
    private val completed = LinkedHashMap<String, CompletedCapture>()
    /** Nonces are single-use across capability and capture actions. */
    private val consentUseLedger = RootCaptureConsentUseLedger()

    /** This call may invoke the device root manager, so the explicit capability-check consent is mandatory. */
    fun checkCapability(consent: RootCaptureConsent, androidApiLevel: Int): RootCaptureCapabilityResult =
        checkCapability(consent, androidApiLevel, RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY)

    /** A full-capture capability check is separately scoped and separately consented. */
    fun checkCapability(
        consent: RootCaptureConsent,
        androidApiLevel: Int,
        scope: RootCaptureScope,
    ): RootCaptureCapabilityResult {
        val consentResult = RootCaptureConsentValidator.validate(
            consent, RootCaptureConsentAction.CAPABILITY_CHECK, scope, clock,
        )
        if (consentResult !is RootCaptureConsentCheck.Accepted) {
            return capability(RootCaptureCapability.ROOT_PROBE_FAILED, scope)
        }
        synchronized(lock) {
            if (!consentUseLedger.consumeNonce(consent.sessionNonce)) {
                return capability(RootCaptureCapability.ROOT_PROBE_FAILED, scope)
            }
        }
        return probe(androidApiLevel, scope)
    }

    fun start(consent: RootCaptureConsent, request: RootCaptureStartRequest): RootCaptureStartResult {
        if (!request.featureEnabled) return RootCaptureStartResult.Rejected(RootCaptureStartRejection.DISABLED_BY_DEFAULT)
        if (request.androidApiLevel < RootCaptureDefaults.MIN_API) {
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.UNSUPPORTED_ANDROID_API)
        }
        if (!RootCaptureCommandFactory.isRequestAllowed(request)) {
            // Keep scope/filter mismatches inside the existing privacy-safe
            // typed rejection surface used by the app integration.
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.CONSENT_REJECTED)
        }
        val action = request.scope.requiredConsentAction()
        val consentResult = RootCaptureConsentValidator.validate(
            consent, action, request.scope, clock,
        )
        if (consentResult !is RootCaptureConsentCheck.Accepted) {
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.CONSENT_REJECTED)
        }
        val generation = synchronized(lock) {
            if (active != null || starting) return RootCaptureStartResult.Rejected(RootCaptureStartRejection.ANOTHER_CAPTURE_ACTIVE)
            if (!consentUseLedger.consumeNonce(consent.sessionNonce)) {
                return RootCaptureStartResult.Rejected(RootCaptureStartRejection.CONSENT_REJECTED)
            }
            starting = true
            startGeneration += 1L
            cancelledStartGeneration = null
            startGeneration
        }
        return try {
            startReserved(consent, request, generation)
        } finally {
            synchronized(lock) {
                if (startGeneration == generation) {
                    starting = false
                    cancelledStartGeneration = null
                }
            }
        }
    }

    private fun startReserved(
        consent: RootCaptureConsent,
        request: RootCaptureStartRequest,
        generation: Long,
    ): RootCaptureStartResult {
        if (isStartCancelled(generation)) return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        when (probe(request.androidApiLevel, request.scope).capability) {
            RootCaptureCapability.USABLE -> Unit
            RootCaptureCapability.TCPDUMP_UNAVAILABLE, RootCaptureCapability.TCPDUMP_PROBE_FAILED ->
                return RootCaptureStartResult.Rejected(RootCaptureStartRejection.TCPDUMP_UNAVAILABLE)
            RootCaptureCapability.UNSUPPORTED_ANDROID_API ->
                return RootCaptureStartResult.Rejected(RootCaptureStartRejection.UNSUPPORTED_ANDROID_API)
            else -> return RootCaptureStartResult.Rejected(RootCaptureStartRejection.ROOT_UNAVAILABLE)
        }
        // A root-manager dialog/tool probe can take time. Re-check immediately
        // before launching capture so a formerly fresh acknowledgement cannot
        // be replayed after its short validity window.
        if (RootCaptureConsentValidator.validate(
                consent, action = request.scope.requiredConsentAction(), scope = request.scope, clock = clock,
            ) !is RootCaptureConsentCheck.Accepted
        ) {
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.CONSENT_REJECTED)
        }
        if (isStartCancelled(generation)) return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        val sessionId = UUID.randomUUID().toString()
        val output = outputStore.create(sessionId) as? RootCaptureOutputCreate.Ready
            ?: return RootCaptureStartResult.Rejected(RootCaptureStartRejection.TEMPORARY_OUTPUT_UNAVAILABLE)
        if (isStartCancelled(generation)) {
            output.stream.closeQuietly()
            outputStore.erase(sessionId)
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        }
        val command = RootCaptureCommandFactory.create(request, interfaces)
        val launched = runner.start(command) as? RootCaptureProcessLaunch.Started
        if (launched == null) {
            output.stream.closeQuietly()
            outputStore.erase(sessionId)
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        }
        val stdout = launched.process.stdout()
        if (stdout == null) {
            launched.process.stop()
            output.stream.closeQuietly()
            outputStore.erase(sessionId)
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        }
        if (isStartCancelled(generation)) {
            launched.process.stop()
            stdout.closeQuietly()
            output.stream.closeQuietly()
            outputStore.erase(sessionId)
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        }
        val startedAt = safeNow() ?: run {
            launched.process.stop()
            stdout.closeQuietly()
            output.stream.closeQuietly()
            outputStore.erase(sessionId)
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        }
        val state = ActiveCapture(sessionId, request, launched.process, stdout, output.stream, startedAt)
        val installed = synchronized(lock) {
            if (isStartCancelledLocked(generation) || active != null) {
                false
            } else {
                active = state
                true
            }
        }
        if (!installed) {
            launched.process.stop()
            stdout.closeQuietly()
            output.stream.closeQuietly()
            outputStore.erase(sessionId)
            return RootCaptureStartResult.Rejected(RootCaptureStartRejection.PROCESS_START_FAILED)
        }
        launched.process.setTerminationListener { termination ->
            if (termination == RootCaptureProcessTermination.DIED) requestStop(
                sessionId,
                RootCaptureTerminalReason.PROCESS_DIED,
                eraseOutput = true,
            )
        }
        state.deadline = scheduler.once(request.limits.maximumDurationMillis) {
            requestStop(sessionId, RootCaptureTerminalReason.DURATION_CAP_REACHED)
        }
        state.watchdog = scheduler.repeating(250L) { checkDuration(sessionId) }
        pumpExecutor.execute {
            val result = try {
                RootCaptureBoundedOutputPump.copy(
                    input = stdout,
                    output = output.stream,
                    maximumBytes = request.limits.maximumBytes,
                    maximumPackets = request.limits.maximumPackets,
                    snapLengthBytes = if (state.request.scope == RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY) 96 else request.limits.snapLengthBytes,
                    onProgress = { bytes, packets -> updateProgress(sessionId, bytes, packets) },
                )
            } catch (_: Throwable) {
                RootCapturePumpResult.Failed
            } finally {
                // The pump owns finalization. Close both ends before publishing
                // a completed record so export cannot race a pending write or
                // retain a live privileged pipe.
                stdout.closeQuietly()
                output.stream.closeQuietly()
            }
            when (result) {
                is RootCapturePumpResult.Complete -> finalizeCapture(
                    sessionId,
                    state.requestedReason ?: RootCaptureTerminalReason.PROCESS_EXITED,
                    observedBytes = result.bytes,
                    observedPackets = result.packets,
                    outputStatus = RootCaptureOutputStatus.COMPLETE,
                )
                is RootCapturePumpResult.ByteCap -> {
                    requestStop(sessionId, RootCaptureTerminalReason.BYTE_CAP_REACHED)
                    finalizeCapture(
                        sessionId,
                        RootCaptureTerminalReason.BYTE_CAP_REACHED,
                        observedBytes = result.bytes,
                        observedPackets = result.packets,
                        outputStatus = RootCaptureOutputStatus.TRUNCATED_AT_BYTE_CAP,
                    )
                }
                is RootCapturePumpResult.PacketCap -> {
                    requestStop(sessionId, RootCaptureTerminalReason.PACKET_CAP_REACHED)
                    finalizeCapture(
                        sessionId,
                        RootCaptureTerminalReason.PACKET_CAP_REACHED,
                        observedBytes = result.bytes,
                        observedPackets = result.packets,
                        outputStatus = RootCaptureOutputStatus.TRUNCATED_AT_PACKET_CAP,
                    )
                }
                RootCapturePumpResult.Failed -> {
                    requestStop(sessionId, RootCaptureTerminalReason.OUTPUT_UNAVAILABLE, eraseOutput = true)
                    finalizeCapture(sessionId, RootCaptureTerminalReason.OUTPUT_UNAVAILABLE, eraseOutput = true)
                }
            }
        }
        return RootCaptureStartResult.Started(state.snapshot())
    }

    fun snapshot(sessionId: String): RootCaptureSessionSnapshot? = synchronized(lock) {
        active?.takeIf { it.sessionId == sessionId }?.snapshot() ?: completed[sessionId]?.snapshot
    }

    fun stop(sessionId: String): RootCaptureSessionSnapshot? {
        requestStop(sessionId, RootCaptureTerminalReason.USER_STOPPED)
        return snapshot(sessionId)
    }

    fun prepareExport(request: RootCaptureExportRequest): RootCaptureExportResult = synchronized(lock) {
        when {
            active?.sessionId == request.sessionId -> RootCaptureExportResult.Rejected(RootCaptureExportRejection.SESSION_ACTIVE)
            completed[request.sessionId]?.snapshot?.exportable == true -> RootCaptureExportResult.UserMediatedDestinationRequired
            completed.containsKey(request.sessionId) -> RootCaptureExportResult.Rejected(RootCaptureExportRejection.OUTPUT_UNAVAILABLE)
            else -> RootCaptureExportResult.Rejected(RootCaptureExportRejection.SESSION_UNKNOWN)
        }
    }

    /** The host must obtain [destination] from the Android Storage Access Framework; no filesystem path is accepted. */
    fun exportToUserChosenDestination(request: RootCaptureExportRequest, destination: OutputStream): RootCaptureExportResult {
        val record = synchronized(lock) { completed[request.sessionId] }
        if (record == null) {
            return synchronized(lock) {
                if (active?.sessionId == request.sessionId) {
                    RootCaptureExportResult.Rejected(RootCaptureExportRejection.SESSION_ACTIVE)
                } else {
                    RootCaptureExportResult.Rejected(RootCaptureExportRejection.SESSION_UNKNOWN)
                }
            }
        }
        if (!record.snapshot.exportable) return RootCaptureExportResult.Rejected(RootCaptureExportRejection.OUTPUT_UNAVAILABLE)
        if (!outputStore.copyTo(request.sessionId, destination, record.snapshot.maximumBytes)) {
            return RootCaptureExportResult.Rejected(RootCaptureExportRejection.DESTINATION_WRITE_FAILED)
        }
        val erased = outputStore.erase(request.sessionId)
        if (erased) {
            synchronized(lock) { completed.remove(request.sessionId) }
            return RootCaptureExportResult.ExportedAndErased
        }
        return RootCaptureExportResult.Rejected(RootCaptureExportRejection.OUTPUT_UNAVAILABLE)
    }

    /** Call from the product's local-data erase flow and once at process startup to remove orphaned private capture files. */
    fun eraseAll(): RootCaptureEraseResult {
        val running = synchronized(lock) {
            cancelledStartGeneration = startGeneration.takeIf { starting }
            active
        }
        running?.let { capture ->
            requestStop(
                sessionId = capture.sessionId,
                reason = RootCaptureTerminalReason.ERASURE_REQUESTED,
                eraseOutput = true,
            )
        }
        synchronized(lock) {
            running?.cancelTimers()
            active = null
            completed.clear()
        }
        return if (outputStore.eraseAll()) RootCaptureEraseResult.Erased else RootCaptureEraseResult.CleanupIncomplete
    }

    private fun probe(
        apiLevel: Int,
        scope: RootCaptureScope = RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
    ): RootCaptureCapabilityResult {
        if (apiLevel < RootCaptureDefaults.MIN_API) {
            return RootCaptureCapabilityResult(
                capability = RootCaptureCapability.UNSUPPORTED_ANDROID_API,
                limitations = RootCaptureLimitationSets.forScope(scope),
                scope = scope,
            )
        }
        return when (runner.rootAvailability()) {
            RootCaptureRootAvailability.AVAILABLE -> when (runner.commandAvailability(RootCaptureCommandFactory.tcpdumpProbe())) {
                RootCaptureCommandAvailability.AVAILABLE -> capability(RootCaptureCapability.USABLE, scope)
                RootCaptureCommandAvailability.UNAVAILABLE -> capability(RootCaptureCapability.TCPDUMP_UNAVAILABLE, scope)
                RootCaptureCommandAvailability.PROBE_FAILED -> capability(RootCaptureCapability.TCPDUMP_PROBE_FAILED, scope)
            }
            RootCaptureRootAvailability.SU_UNAVAILABLE -> capability(RootCaptureCapability.ROOT_BINARY_UNAVAILABLE, scope)
            RootCaptureRootAvailability.ACCESS_DENIED -> capability(RootCaptureCapability.ROOT_ACCESS_DENIED, scope)
            RootCaptureRootAvailability.PROBE_FAILED -> capability(RootCaptureCapability.ROOT_PROBE_FAILED, scope)
        }
    }

    private fun capability(capability: RootCaptureCapability, scope: RootCaptureScope) = RootCaptureCapabilityResult(
        capability = capability,
        limitations = RootCaptureLimitationSets.forScope(scope),
        scope = scope,
    )

    private fun checkDuration(sessionId: String) {
        val current = synchronized(lock) { active?.takeIf { it.sessionId == sessionId } } ?: return
        val now = safeNow() ?: run {
            requestStop(sessionId, RootCaptureTerminalReason.OUTPUT_UNAVAILABLE, eraseOutput = true)
            return
        }
        if (now - current.startedAtMillis >= current.request.limits.maximumDurationMillis) {
            requestStop(sessionId, RootCaptureTerminalReason.DURATION_CAP_REACHED)
        }
    }

    private fun updateProgress(sessionId: String, observedBytes: Long, observedPackets: Int) {
        synchronized(lock) {
            active?.takeIf { it.sessionId == sessionId }?.apply {
                this.observedBytes = observedBytes
                this.observedPackets = observedPackets
            }
        }
    }

    private fun requestStop(
        sessionId: String,
        reason: RootCaptureTerminalReason,
        eraseOutput: Boolean = false,
    ) {
        val state = synchronized(lock) {
            active?.takeIf { it.sessionId == sessionId }?.also { current ->
                if (current.requestedReason == null || reason == RootCaptureTerminalReason.ERASURE_REQUESTED) {
                    current.requestedReason = reason
                }
                current.eraseOutputOnFinalize = current.eraseOutputOnFinalize || eraseOutput
                current.stopRequested = true
            }
        }
        state ?: return
        state.cancelTimers()
        runCatching { state.process.stop() }
        state.stdout.closeQuietly()
    }

    private fun finalizeCapture(
        sessionId: String,
        fallbackReason: RootCaptureTerminalReason,
        eraseOutput: Boolean = false,
        observedBytes: Long? = null,
        observedPackets: Int? = null,
        outputStatus: RootCaptureOutputStatus = RootCaptureOutputStatus.COMPLETE,
    ) {
        val state = synchronized(lock) {
            active?.takeIf { it.sessionId == sessionId }
        } ?: return
        state.cancelTimers()
        state.stdout.closeQuietly()
        state.output.closeQuietly()
        val mustErase = eraseOutput || state.eraseOutputOnFinalize || fallbackReason == RootCaptureTerminalReason.OUTPUT_UNAVAILABLE
        if (mustErase) {
            val rejectedSnapshot = state.snapshot(
                active = false,
                finalizing = false,
                reason = state.requestedReason ?: fallbackReason,
                observedBytes = observedBytes,
                observedPackets = observedPackets,
                outputStatus = RootCaptureOutputStatus.PARTIAL_OUTPUT_REJECTED,
                exportable = false,
            )
            synchronized(lock) {
                if (active === state) {
                    active = null
                    completed[sessionId] = CompletedCapture(rejectedSnapshot)
                }
            }
            outputStore.erase(sessionId)
            return
        }
        val snapshot = state.snapshot(
            active = false,
            finalizing = false,
            reason = state.requestedReason ?: fallbackReason,
            observedBytes = observedBytes,
            observedPackets = observedPackets,
            outputStatus = outputStatus,
        )
        synchronized(lock) {
            if (active === state) {
                active = null
                completed[sessionId] = CompletedCapture(snapshot)
            }
        }
    }

    private fun isStartCancelled(generation: Long): Boolean = synchronized(lock) { isStartCancelledLocked(generation) }

    private fun isStartCancelledLocked(generation: Long): Boolean = cancelledStartGeneration == generation

    private fun safeNow(): Long? = runCatching(clock::nowMillis).getOrNull()?.takeIf { it > 0L }

    private class ActiveCapture(
        val sessionId: String,
        val request: RootCaptureStartRequest,
        val process: RootCaptureRunningProcess,
        val stdout: java.io.InputStream,
        val output: OutputStream,
        val startedAtMillis: Long,
        var deadline: RootCaptureScheduledTask? = null,
        var watchdog: RootCaptureScheduledTask? = null,
        var observedBytes: Long = 0L,
        var observedPackets: Int = 0,
        var requestedReason: RootCaptureTerminalReason? = null,
        var eraseOutputOnFinalize: Boolean = false,
        var stopRequested: Boolean = false,
    ) {
        fun cancelTimers() {
            deadline?.cancel()
            watchdog?.cancel()
        }

        fun snapshot(
            active: Boolean = !stopRequested,
            finalizing: Boolean = stopRequested,
            reason: RootCaptureTerminalReason? = null,
            observedBytes: Long? = null,
            observedPackets: Int? = null,
            outputStatus: RootCaptureOutputStatus = RootCaptureOutputStatus.COMPLETE,
            exportable: Boolean? = null,
        ) = RootCaptureSessionSnapshot(
            sessionId = sessionId,
            startedAtMillis = startedAtMillis,
            maximumDurationMillis = request.limits.maximumDurationMillis,
            maximumBytes = request.limits.maximumBytes,
            maximumPackets = request.limits.maximumPackets,
            active = active,
            terminalReason = reason ?: requestedReason,
            observedBytes = observedBytes ?: this.observedBytes,
            observedPackets = observedPackets ?: this.observedPackets,
            finalizing = finalizing,
            scope = request.scope,
            filter = request.filter,
            outputStatus = outputStatus,
            exportable = exportable ?: (!active && outputStatus != RootCaptureOutputStatus.PARTIAL_OUTPUT_REJECTED),
        )
    }

    private data class CompletedCapture(val snapshot: RootCaptureSessionSnapshot)
}

private fun OutputStream.closeQuietly() {
    runCatching { close() }
}

private fun java.io.InputStream.closeQuietly() {
    runCatching { close() }
}
