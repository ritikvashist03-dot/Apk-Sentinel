package app.apksentinel.networkmonitor

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.net.DatagramSocket
import java.net.Socket
import java.util.UUID

/**
 * User-started local-VPN lifecycle service. It establishes a route only after
 * Android consent and an installed data plane confirm the requested family,
 * MTU, and documented coverage.
 */
class NetworkMonitorService : VpnService() {
    private val stateLock = Any()
    private lateinit var notification: NetworkMonitorNotification
    private var activeSession: ActiveSession? = null
    /** Prevents an old teardown from stopping or overwriting a newly accepted session. */
    private var stopping = false

    @Volatile
    private var foregroundRunning = false

    override fun onCreate() {
        super.onCreate()
        notification = NetworkMonitorNotification(this)
        notification.createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> decodeStartRequest(intent)?.let(::startMonitoring)
                ?: recordInvalidStart("The requested monitoring configuration was incomplete or invalid.")

            ACTION_ATTACH_REMOTE_STREAM -> intent.getStringExtra(EXTRA_REMOTE_STREAM_ATTACHMENT_TOKEN)
                ?.let(::attachRemoteStream)

            ACTION_STOP -> stopMonitoring("Stopped by the user.")
            else -> if (intent != null) recordInvalidStart("Unknown network-monitor service action.")
        }
        // A VPN session must be explicitly started by the user again after process death or interruption.
        return START_NOT_STICKY
    }

    /**
     * Attaches a stream created after the VPN service was already started. The
     * token is an explicit process-local capability; it is never discovered or
     * reconstructed from pairing data.
     */
    private fun attachRemoteStream(token: String) {
        if (!RemoteStreamAttachmentRegistry.contains(token)) return
        val session = synchronized(stateLock) { activeSession }
        if (session == null || session.finishing) {
            RemoteStreamAttachmentRegistry.stop(token, RemoteStreamAttachmentStopReason.SERVICE_DESTROYED)
            return
        }
        if ((session.listener as? SessionPacketListener)?.attachRemoteStream(token) != true) {
            RemoteStreamAttachmentRegistry.stop(token, RemoteStreamAttachmentStopReason.SERVICE_DESTROYED)
        }
    }

    override fun onRevoke() {
        RemoteStreamAttachmentRegistry.stopAll(RemoteStreamAttachmentStopReason.VPN_REVOKED)
        val session = synchronized(stateLock) { activeSession }
        if (session != null) {
            session.record(
                EngineLimitationEvent(
                    sessionId = session.id,
                    atMillis = session.dependencies.clock.nowMillis(),
                    limitation = EngineLimitation(
                        EngineLimitationCode.ANOTHER_VPN_OR_SYSTEM_REVOKED_ACCESS,
                        "Android revoked this local VPN session. Monitoring and protection have stopped.",
                    ),
                ),
            )
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.REVOKED_BY_SYSTEM,
                detail = "Android revoked local VPN access.",
            )
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        RemoteStreamAttachmentRegistry.stopAll(RemoteStreamAttachmentStopReason.SERVICE_DESTROYED)
        val session = synchronized(stateLock) { activeSession }
        if (session != null) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.STOPPED,
                detail = "Network-monitor service was destroyed.",
            )
        }
        super.onDestroy()
    }

    private fun startMonitoring(request: NetworkMonitorStartRequest) {
        val dependencies = NetworkMonitorRuntime.snapshot()
        val now = dependencies.clock.nowMillis()
        val tlsRequest = request.tunnel.tlsInspection.sessionConfigurationOrNull()
        if (tlsRequest != null && !TlsInspectionSessionConsentRegistry.consume(
                TlsInspectionSessionConsent(
                    version = tlsRequest.sessionConsentVersion,
                    acknowledgedAtMillis = tlsRequest.sessionConsentAcknowledgedAtMillis,
                    nonce = tlsRequest.sessionConsentNonce,
                ),
                nowMillis = now,
            )) {
            recordInvalidStart("The TLS session consent was missing, stale, mismatched, or already consumed.")
            return
        }
        if (!VpnDisclosureAcknowledgementGate.consume(request.disclosureAcknowledgement, now)) {
            recordInvalidStart("The VPN disclosure acknowledgement was missing, stale, outdated, or already used.")
            return
        }
        val sessionId = UUID.randomUUID().toString()
        val tlsInspectionSession = if (tlsRequest != null) {
            runCatching { dependencies.tlsInspectionRoute?.openSession(tlsRequest) }.getOrNull()
        } else null
        if (tlsRequest != null && tlsInspectionSession == null) {
            dependencies.eventStore.append(
                MonitorStateEvent(
                    sessionId = sessionId,
                    atMillis = now,
                    state = MonitorLifecycleState.FAILED,
                    detail = "TLS inspection was requested but its process-local CA/route integration was unavailable; no VPN route was created.",
                ),
            )
            NetworkMonitorRuntime.updateStatus(
                NetworkMonitorStatus(
                    sessionId = sessionId,
                    state = MonitorLifecycleState.FAILED,
                    detail = "TLS inspection setup is incomplete or unavailable.",
                    endedAtMillis = now,
                ),
            )
            return
        }
        val dataPlane = runCatching { dependencies.forwardingDataPlaneFactory.create() }
            .getOrElse { FailedForwardingDataPlane("The forwarding data plane could not be created.") }
        // Android only permits connection-owner lookup to the active VPN. The
        // built-in forwarder invokes this provider solely from its active TUN
        // runtime, and a provider failure falls back to explicit unknowns.
        val provider = runCatching {
            dependencies.appAttributionProviderFactory.create(applicationContext)
        }.getOrDefault(NoFlowAppAttributionProvider)
        runCatching { dataPlane.installBuiltInAppAttributionProvider(provider) }
        val initialCapabilities = capabilitySnapshot(
            configuration = request.tunnel,
            forwarder = dataPlane.capabilities,
            vpnConsentGranted = false,
        )
        val session = ActiveSession(
            id = sessionId,
            request = request,
            dependencies = dependencies,
            dataPlane = dataPlane,
            capabilities = initialCapabilities,
            startedAtMillis = now,
            tlsInspectionSession = tlsInspectionSession,
        )
        session.listener = SessionPacketListener(session)

        val accepted = synchronized(stateLock) {
            if (activeSession != null || stopping) {
                false
            } else {
                activeSession = session
                true
            }
        }
        if (!accepted) {
            runCatching { tlsInspectionSession?.stop() }
            // Do not let a start racing an existing teardown create a second route.
            dependencies.eventStore.append(
                MonitorStateEvent(
                    sessionId = sessionId,
                    atMillis = now,
                    state = MonitorLifecycleState.FAILED,
                    detail = "A network-monitor session is already active or the service is stopping.",
                ),
            )
            return
        }
        val socketProtector = ServiceSocketProtector()
        if (!RemoteStreamSocketProtectionRuntime.install(socketProtector)) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.FAILED,
                detail = "A protected receiver socket owner is already active.",
                stopDataPlane = false,
            )
            return
        }
        NetworkMonitorRuntime.attachSessionResources(
            sessionId = session.id,
            eventStore = dependencies.eventStore,
            firewallRuleProvider = dependencies.firewallRuleProvider,
            dataPlane = dataPlane,
            flowRegistry = session.flowRegistry,
        )

        publishState(session, MonitorLifecycleState.STARTING, "Preparing a user-consented local VPN session.")
        if (!promoteToForeground(notification.preparing())) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.FAILED,
                detail = "Android did not allow the foreground monitoring service to start.",
                stopDataPlane = false,
            )
            return
        }

        val vpnConsentGranted = VpnService.prepare(this) == null
        session.capabilities = capabilitySnapshot(request.tunnel, dataPlane.capabilities, vpnConsentGranted)
        if (!vpnConsentGranted) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.CONSENT_REQUIRED,
                detail = "Android VPN consent is required before monitoring can start.",
                stopDataPlane = false,
            )
            return
        }

        emitLimitations(session)
        if (!dataPlane.capabilities.supports(request.tunnel)) {
            session.record(
                EngineLimitationEvent(
                    sessionId = session.id,
                    atMillis = session.dependencies.clock.nowMillis(),
                    limitation = EngineLimitation(
                        EngineLimitationCode.FORWARDING_DATA_PLANE_UNAVAILABLE_FOR_CONFIGURATION,
                        dataPlane.capabilities.detail,
                    ),
                ),
            )
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.CAPABILITY_UNAVAILABLE,
                detail = "Traffic forwarding is unavailable for the selected IP families or MTU; no VPN route was created.",
                stopDataPlane = false,
            )
            return
        }
        if (request.tunnel.mode == MonitoringMode.FIREWALL_ENFORCEMENT && !dataPlane.capabilities.canEnforceFirewallRules) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.CAPABILITY_UNAVAILABLE,
                detail = "Firewall enforcement was requested, but the installed data plane cannot confirm enforcement. No VPN route was created.",
                stopDataPlane = false,
            )
            return
        }

        val tunnelResult = LocalVpnTunnelBuilder(this).establish(request.tunnel)
        val established = tunnelResult as? TunnelEstablishmentResult.Established
        if (established == null) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.FAILED,
                detail = (tunnelResult as TunnelEstablishmentResult.Failed).detail,
                stopDataPlane = false,
            )
            return
        }
        session.tunnelDescriptor = established.descriptor
        if (established.skippedUninstalledPackages.isNotEmpty()) {
            publishState(
                session,
                MonitorLifecycleState.STARTING,
                "Skipped ${established.skippedUninstalledPackages.size} selected app package(s) that are no longer installed.",
            )
        }

        val startResult = runCatching {
            dataPlane.start(
                tunnel = established.descriptor,
                configuration = request.tunnel,
                 socketProtector = socketProtector,
                listener = session.listener,
                tlsInspectionSession = session.tlsInspectionSession,
            )
        }.getOrElse {
            ForwardingStartResult.Rejected("The forwarding data plane failed while starting.")
        }
        if (startResult !is ForwardingStartResult.Started) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.FAILED,
                detail = (startResult as ForwardingStartResult.Rejected).detail,
            )
            return
        }
        if (session.finishing) return

        // Update the same foreground notification only after the forwarder has started.
        if (!promoteToForeground(notification.active())) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.FAILED,
                detail = "Android did not allow the active monitoring notification to be shown.",
            )
            return
        }
        if (session.finishing) {
            // A worker can finish the session while the foreground update is in
            // flight. Teardown has already made restarts ineligible, so this
            // cannot remove a newer session's notification.
            stopForegroundAndRemoveNotification()
            return
        }
        publishState(
            session,
            MonitorLifecycleState.ACTIVE,
            "Local VPN monitoring is active with the installed data plane's documented coverage limits.",
        )
    }

    private fun stopMonitoring(detail: String) {
        val session = synchronized(stateLock) { activeSession }
        if (session == null) {
            synchronized(stateLock) { stopping = true }
            if (foregroundRunning) stopForegroundAndRemoveNotification()
            stopSelf()
            return
        }
        if (foregroundRunning) promoteToForeground(notification.stopping())
        finishSession(session, MonitorLifecycleState.STOPPED, detail)
    }

    private fun recordInvalidStart(detail: String) {
        val existingSession = synchronized(stateLock) { activeSession }
        if (existingSession != null) {
            // A malformed or unknown follow-up intent must not tear down a
            // healthy route or strand its forwarding workers without a
            // foreground notification.
            existingSession.record(
                MonitorStateEvent(
                    sessionId = existingSession.id,
                    atMillis = existingSession.dependencies.clock.nowMillis(),
                    state = existingSession.lifecycleState,
                    detail = "Ignored invalid network-monitor service request: $detail",
                ),
            )
            return
        }
        synchronized(stateLock) { stopping = true }
        // A malformed explicit start must still satisfy Android's foreground-service deadline.
        if (!foregroundRunning) promoteToForeground(notification.preparing())
        NetworkMonitorRuntime.updateStatus(
            NetworkMonitorStatus(
                state = MonitorLifecycleState.FAILED,
                detail = detail,
                endedAtMillis = System.currentTimeMillis(),
            ),
        )
        stopForegroundAndRemoveNotification()
        stopSelf()
    }

    private fun emitLimitations(session: ActiveSession) {
        session.capabilities.limitations().forEach { limitation ->
            session.record(
                EngineLimitationEvent(
                    sessionId = session.id,
                    atMillis = session.dependencies.clock.nowMillis(),
                    limitation = limitation,
                ),
            )
        }
    }

    private fun publishState(
        session: ActiveSession,
        state: MonitorLifecycleState,
        detail: String,
        endedAtMillis: Long? = null,
        uiText: NetworkUiText = NetworkUiText.forLifecycle(state),
    ) {
        session.lifecycleState = state
        session.record(
            MonitorStateEvent(
                sessionId = session.id,
                atMillis = session.dependencies.clock.nowMillis(),
                state = state,
                detail = detail,
                uiText = uiText,
            ),
        )
        NetworkMonitorRuntime.updateStatus(
            NetworkMonitorStatus(
                sessionId = session.id,
                state = state,
                detail = detail,
                uiText = uiText,
                capabilities = session.capabilities,
                startedAtMillis = session.startedAtMillis,
                endedAtMillis = endedAtMillis,
            ),
        )
    }

    private fun finishSession(
        session: ActiveSession,
        finalState: MonitorLifecycleState,
        detail: String,
        stopDataPlane: Boolean = true,
    ) {
        val shouldFinish = synchronized(stateLock) {
            if (session.finishing) {
                false
            } else {
                session.finishing = true
                stopping = true
                true
            }
        }
        if (!shouldFinish) return

        publishState(session, MonitorLifecycleState.STOPPING, "Stopping local VPN monitoring.")
        // The VPN service owns every attached remote stream. Detach before
        // closing the tunnel so no writer can outlive VPN ownership.
        RemoteStreamAttachmentRegistry.stopAll(
            if (finalState == MonitorLifecycleState.REVOKED_BY_SYSTEM) {
                RemoteStreamAttachmentStopReason.VPN_REVOKED
            } else {
                RemoteStreamAttachmentStopReason.USER_STOPPED
            },
        )
        // A raw capture is meaningful only while this local VPN owns the TUN
        // path. Request its bounded writer to drain/flush; it never owns or
        // closes the caller-selected document stream.
        RawPcapngCaptureRuntime.stop()
        if (stopDataPlane) runCatching { session.dataPlane.stop() }
        runCatching { session.tlsInspectionSession?.stop() }
        // Do not wait indefinitely on storage the app does not own. A normal
        // capture drains deterministically; a stalled provider remains visible
        // as STOPPING rather than blocking VPN teardown forever.
        RawPcapngCaptureRuntime.awaitStopped(timeoutMillis = CAPTURE_FLUSH_WAIT_MILLIS)
        // This asks an explicitly composed history controller to drain its
        // metadata-only ingress on its own writer thread. It never performs
        // Keystore or SharedPreferences work on forwarding threads.
        session.dependencies.durableHistory?.flush(HISTORY_FLUSH_WAIT_MILLIS)
        runCatching { session.tunnelDescriptor?.close() }
        session.tunnelDescriptor = null
        RemoteStreamSocketProtectionRuntime.clear()
        // Observed domain bindings are session evidence and must not outlive the session.
        NetworkMonitorRuntime.detachDomainBindings()

        val endedAt = session.dependencies.clock.nowMillis()
        publishState(session, finalState, detail, endedAt)
        // Keep UI reads pinned through the terminal state event, then retain
        // the final aggregate counters after the data plane is stopped.
        NetworkMonitorRuntime.detachSessionResources(session.id, session.dataPlane)
        stopForegroundAndRemoveNotification()
        synchronized(stateLock) {
            if (activeSession === session) activeSession = null
        }
        stopSelf()
    }

    private fun promoteToForeground(value: android.app.Notification): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NetworkMonitorNotification.NOTIFICATION_ID,
                value,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NetworkMonitorNotification.NOTIFICATION_ID, value)
        }
        foregroundRunning = true
        true
    } catch (_: RuntimeException) {
        false
    }

    private fun stopForegroundAndRemoveNotification() {
        if (foregroundRunning) {
            stopForeground(Service.STOP_FOREGROUND_REMOVE)
            foregroundRunning = false
        }
    }

    private inner class ServiceSocketProtector : TunnelSocketProtector {
        override fun protect(socket: Socket): Boolean = this@NetworkMonitorService.protect(socket)

        override fun protect(socket: DatagramSocket): Boolean = this@NetworkMonitorService.protect(socket)

        override fun protect(fileDescriptor: Int): Boolean = this@NetworkMonitorService.protect(fileDescriptor)
    }

    private inner class SessionPacketListener(
        private val session: ActiveSession,
    ) : ForwardingDataPlaneListener {
        private val dnsNameHandling = session.dependencies.dnsNameHandlingFactory.forSession(session.id)
        private val parser = PacketMetadataParser(dnsNameHandling)
        // Observed DNS answers are what make a domain firewall rule enforceable at all.
        private val domainBindings = DomainBindingRegistry()
            .also { NetworkMonitorRuntime.attachDomainBindings(it, dnsNameHandling) }
        private val firewall = FirewallRuleEngine(
            ruleProvider = session.dependencies.firewallRuleProvider,
            idSource = { UUID.randomUUID().toString() },
        )

        override fun onPacket(packet: ForwardedPacket): PacketForwardingDirective {
            if (session.finishing) return PacketForwardingDirective(shouldForward = true)
            // The packet array is ephemeral. The attachment callback must copy
            // and encrypt immediately; this service never retains it.
            remoteAttachmentToken?.let { token ->
                RemoteStreamAttachmentRegistry.offer(
                    token = token,
                    category = "METADATA",
                    observedAtMillis = packet.observedAtMillis,
                    bytes = packet.direction.name.encodeToByteArray(),
                )
                RemoteStreamAttachmentRegistry.offer(
                    token = token,
                    category = "RAW_ENCRYPTED_PACKET",
                    observedAtMillis = packet.observedAtMillis,
                    bytes = packet.bytes,
                )
            }
            return when (val parsed = parser.parse(packet.bytes)) {
                is PacketParseResult.Parsed -> {
                    // Record before evaluating, so a response and the traffic that follows
                    // it can be bound within the same session.
                    domainBindings.observe(parsed.metadata.dns, packet.observedAtMillis)
                    val flow = session.flowRegistry.observe(
                        metadata = parsed.metadata,
                        attribution = packet.attribution,
                        direction = packet.direction,
                        atMillis = packet.observedAtMillis,
                    ).flow
                    session.record(
                        PacketObservedEvent(
                            sessionId = session.id,
                            atMillis = packet.observedAtMillis,
                            flowId = flow.id,
                            direction = packet.direction,
                            attribution = packet.attribution,
                            metadata = parsed.metadata,
                        ),
                    )
                    val decision = if (
                        session.request.tunnel.mode == MonitoringMode.FIREWALL_ENFORCEMENT &&
                        packet.direction == PacketDirection.OUTBOUND
                    ) {
                        firewall.evaluate(
                            context = FirewallEvaluationContext(
                                metadata = parsed.metadata,
                                attribution = packet.attribution,
                            ),
                            atMillis = packet.observedAtMillis,
                            forwarderCanEnforceRules = session.dataPlane.capabilities.canEnforceFirewallRules,
                        ).also { value ->
                            session.record(
                                FirewallDecisionEvent(
                                    sessionId = session.id,
                                    atMillis = packet.observedAtMillis,
                                    flowId = flow.id,
                                    decision = value,
                                ),
                            )
                        }
                    } else {
                        null
                    }
                    decision?.let { session.rememberFirewallDecision(it) }
                    PacketForwardingDirective(
                        shouldForward = decision?.requestsBlock != true,
                        firewallDecision = decision,
                    )
                }

                is PacketParseResult.Malformed -> {
                    session.record(
                        PacketParseFailureEvent(
                            session.id,
                            packet.observedAtMillis,
                            parsed.reason,
                            PacketParseFailureCode.MALFORMED_PACKET,
                        ),
                    )
                    PacketForwardingDirective(shouldForward = true)
                }

                is PacketParseResult.Ignored -> {
                    session.record(
                        PacketParseFailureEvent(
                            session.id,
                            packet.observedAtMillis,
                            parsed.reason,
                            PacketParseFailureCode.IGNORED_PACKET,
                        ),
                    )
                    PacketForwardingDirective(shouldForward = true)
                }
            }
        }

        @Volatile
        private var remoteAttachmentToken: String? = session.request.remoteStreamAttachmentToken

        fun attachRemoteStream(token: String): Boolean {
            if (!RemoteStreamAttachmentRegistry.contains(token)) return false
            remoteAttachmentToken = token
            return true
        }

        override fun onFirewallEnforcementResult(result: FirewallEnforcementResult) {
            session.takeFirewallDecision(result.directiveId)?.let { decision ->
                session.dependencies.firewallEnforcementObserver?.onConfirmedOutcome(
                    decision,
                    result,
                    session.dependencies.clock.nowMillis(),
                )
            }
            session.record(
                ForwarderEnforcementEvent(
                    sessionId = session.id,
                    atMillis = session.dependencies.clock.nowMillis(),
                    result = result,
                ),
            )
        }

        override fun onDataPlaneStopped(detail: String) {
            finishSession(
                session = session,
                finalState = MonitorLifecycleState.FAILED,
                detail = "The forwarding data plane stopped unexpectedly.",
                stopDataPlane = false,
            )
        }
    }

    private class ActiveSession(
        val id: String,
        val request: NetworkMonitorStartRequest,
        val dependencies: NetworkMonitorDependencies,
        val dataPlane: ForwardingDataPlane,
        var capabilities: CapabilitySnapshot,
        val startedAtMillis: Long,
        val tlsInspectionSession: TlsInspectionRouteSession?,
    ) {
        /** Bounded, process-local flow state exposed only while this session is active. */
        val flowRegistry = BoundedFlowRegistry()
        private val firewallDecisionLock = Any()
        private val firewallDecisions = LinkedHashMap<String, FirewallDecision>()
        lateinit var listener: ForwardingDataPlaneListener

        fun rememberFirewallDecision(decision: FirewallDecision) = synchronized(firewallDecisionLock) {
            firewallDecisions[decision.directiveId] = decision
            while (firewallDecisions.size > MAX_PENDING_FIREWALL_DECISIONS) {
                firewallDecisions.remove(firewallDecisions.entries.first().key)
            }
        }

        fun takeFirewallDecision(directiveId: String): FirewallDecision? = synchronized(firewallDecisionLock) {
            firewallDecisions.remove(directiveId)
        }

        @Volatile
        var lifecycleState: MonitorLifecycleState = MonitorLifecycleState.STARTING

        @Volatile
        var finishing: Boolean = false

        @Volatile
        var tunnelDescriptor: ParcelFileDescriptor? = null

        /** Event-store behavior stays unchanged; durable history receives only its sanitized projection. */
        fun record(event: NetworkEvent) {
            dependencies.eventStore.append(event)
            dependencies.durableHistory?.offer(event)
        }
    }

    private class FailedForwardingDataPlane(
        detail: String,
    ) : ForwardingDataPlane {
        override val capabilities: ForwardingDataPlaneCapabilities = ForwardingDataPlaneCapabilities(
            canForwardIpv4 = false,
            canForwardIpv6 = false,
            canEnforceFirewallRules = false,
            appAttributionAvailability = CapabilityAvailability.UNAVAILABLE,
            detail = detail,
            trafficForwardingAvailability = CapabilityAvailability.UNAVAILABLE,
        )

        override fun start(
            tunnel: ParcelFileDescriptor,
            configuration: TunnelConfiguration,
            socketProtector: TunnelSocketProtector,
            listener: ForwardingDataPlaneListener,
        ): ForwardingStartResult = ForwardingStartResult.Rejected(capabilities.detail)

        override fun stop() = Unit
    }

    companion object {
        private const val CAPTURE_FLUSH_WAIT_MILLIS = 1_500L
        private const val HISTORY_FLUSH_WAIT_MILLIS = 1_500L
        private const val MAX_PENDING_FIREWALL_DECISIONS = 512
        const val ACTION_START = "app.apksentinel.networkmonitor.action.START"
        const val ACTION_STOP = "app.apksentinel.networkmonitor.action.STOP"
        const val ACTION_ATTACH_REMOTE_STREAM = "app.apksentinel.networkmonitor.action.ATTACH_REMOTE_STREAM"

        private const val EXTRA_DISCLOSURE_VERSION = "disclosure_version"
        private const val EXTRA_DISCLOSURE_ACKNOWLEDGED_AT = "disclosure_acknowledged_at"
        private const val EXTRA_DISCLOSURE_NONCE = "disclosure_nonce"
        private const val EXTRA_SESSION_NAME = "session_name"
        private const val EXTRA_MODE = "mode"
        private const val EXTRA_IPV4 = "ipv4"
        private const val EXTRA_IPV6 = "ipv6"
        private const val EXTRA_MTU = "mtu"
        private const val EXTRA_SELECTION_KIND = "selection_kind"
        private const val EXTRA_PACKAGE_NAMES = "package_names"
        private const val EXTRA_PROTOCOL_EVIDENCE_ENABLED = "protocol_evidence_enabled"
        private const val EXTRA_PROTOCOL_EVIDENCE_DISCLOSURE_VERSION = "protocol_evidence_disclosure_version"
        private const val EXTRA_PROTOCOL_EVIDENCE_ACKNOWLEDGED_AT = "protocol_evidence_acknowledged_at"
        private const val EXTRA_PROTOCOL_EVIDENCE_TLS_SNI = "protocol_evidence_tls_sni"
        private const val EXTRA_PROTOCOL_EVIDENCE_HTTP = "protocol_evidence_http"
        private const val EXTRA_PROTOCOL_EVIDENCE_MAX_FLOWS = "protocol_evidence_max_flows"
        private const val EXTRA_PROTOCOL_EVIDENCE_MAX_OBSERVATIONS = "protocol_evidence_max_observations"
        private const val EXTRA_PROTOCOL_EVIDENCE_MAX_PER_FLOW_DIRECTION = "protocol_evidence_max_per_flow_direction"
        private const val EXTRA_PAYLOAD_INSPECTION_ENABLED = "payload_inspection_enabled"
        private const val EXTRA_PAYLOAD_INSPECTION_DISCLOSURE_VERSION = "payload_inspection_disclosure_version"
        private const val EXTRA_PAYLOAD_INSPECTION_ACKNOWLEDGED_AT = "payload_inspection_acknowledged_at"
        private const val EXTRA_PAYLOAD_INSPECTION_MAX_SESSION_BYTES = "payload_inspection_max_session_bytes"
        private const val EXTRA_PAYLOAD_INSPECTION_MAX_FLOW_BYTES = "payload_inspection_max_flow_bytes"
        private const val EXTRA_PAYLOAD_INSPECTION_MAX_RECORDS = "payload_inspection_max_records"
        private const val EXTRA_PAYLOAD_INSPECTION_MAX_RECORD_BYTES = "payload_inspection_max_record_bytes"
        private const val EXTRA_PAYLOAD_INSPECTION_MAX_DURATION = "payload_inspection_max_duration"
        private const val EXTRA_PAYLOAD_INSPECTION_QUEUE_CAPACITY = "payload_inspection_queue_capacity"
        private const val EXTRA_TLS_ENABLED = "tls_inspection_enabled"
        private const val EXTRA_TLS_PACKAGES = "tls_inspection_packages"
        private const val EXTRA_TLS_CONSENT_VERSION = "tls_inspection_consent_version"
        private const val EXTRA_TLS_CONSENT_ACKNOWLEDGED_AT = "tls_inspection_consent_acknowledged_at"
        private const val EXTRA_TLS_CONSENT_NONCE = "tls_inspection_consent_nonce"
        private const val EXTRA_TLS_MAX_SESSION_BYTES = "tls_inspection_max_session_bytes"
        private const val EXTRA_TLS_MAX_FLOW_BYTES = "tls_inspection_max_flow_bytes"
        private const val EXTRA_TLS_MAX_DURATION = "tls_inspection_max_duration"
        private const val EXTRA_REMOTE_STREAM_ATTACHMENT_TOKEN = "remote_stream_attachment_token"
        private const val SELECTION_ALL_EXCEPT = "all_except"
        private const val SELECTION_ONLY_APPS = "only_apps"

        fun startIntent(context: Context, request: NetworkMonitorStartRequest): Intent = Intent(
            context,
            NetworkMonitorService::class.java,
        ).setAction(ACTION_START).apply {
            putExtra(EXTRA_DISCLOSURE_VERSION, request.disclosureAcknowledgement.disclosureVersion)
            putExtra(EXTRA_DISCLOSURE_ACKNOWLEDGED_AT, request.disclosureAcknowledgement.acknowledgedAtMillis)
            putExtra(EXTRA_DISCLOSURE_NONCE, request.disclosureAcknowledgement.nonce)
            putExtra(EXTRA_SESSION_NAME, request.tunnel.sessionName)
            putExtra(EXTRA_MODE, request.tunnel.mode.name)
            putExtra(EXTRA_IPV4, request.tunnel.enableIpv4)
            putExtra(EXTRA_IPV6, request.tunnel.enableIpv6)
            putExtra(EXTRA_MTU, request.tunnel.mtu)
            putExtra(EXTRA_PROTOCOL_EVIDENCE_ENABLED, request.tunnel.protocolEvidence.enabled)
            request.tunnel.protocolEvidence.consent?.let { consent ->
                putExtra(EXTRA_PROTOCOL_EVIDENCE_DISCLOSURE_VERSION, consent.disclosureVersion)
                putExtra(EXTRA_PROTOCOL_EVIDENCE_ACKNOWLEDGED_AT, consent.acknowledgedAtMillis)
            }
            putExtra(EXTRA_PROTOCOL_EVIDENCE_TLS_SNI, request.tunnel.protocolEvidence.inspectTlsClientHelloSni)
            putExtra(EXTRA_PROTOCOL_EVIDENCE_HTTP, request.tunnel.protocolEvidence.inspectCleartextHttp)
            putExtra(EXTRA_PROTOCOL_EVIDENCE_MAX_FLOWS, request.tunnel.protocolEvidence.maximumTrackedFlows)
            putExtra(EXTRA_PROTOCOL_EVIDENCE_MAX_OBSERVATIONS, request.tunnel.protocolEvidence.maximumObservations)
            putExtra(
                EXTRA_PROTOCOL_EVIDENCE_MAX_PER_FLOW_DIRECTION,
                request.tunnel.protocolEvidence.maximumObservationsPerFlowDirection,
            )
            val inspection = request.tunnel.payloadInspection
            putExtra(EXTRA_PAYLOAD_INSPECTION_ENABLED, inspection.enabled)
            inspection.consent?.let { consent ->
                putExtra(EXTRA_PAYLOAD_INSPECTION_DISCLOSURE_VERSION, consent.disclosureVersion)
                putExtra(EXTRA_PAYLOAD_INSPECTION_ACKNOWLEDGED_AT, consent.acknowledgedAtMillis)
            }
            putExtra(EXTRA_PAYLOAD_INSPECTION_MAX_SESSION_BYTES, inspection.maximumSessionBytes)
            putExtra(EXTRA_PAYLOAD_INSPECTION_MAX_FLOW_BYTES, inspection.maximumBytesPerFlow)
            putExtra(EXTRA_PAYLOAD_INSPECTION_MAX_RECORDS, inspection.maximumRecords)
            putExtra(EXTRA_PAYLOAD_INSPECTION_MAX_RECORD_BYTES, inspection.maximumBytesPerRecord)
            putExtra(EXTRA_PAYLOAD_INSPECTION_MAX_DURATION, inspection.maximumDurationMillis)
            putExtra(EXTRA_PAYLOAD_INSPECTION_QUEUE_CAPACITY, inspection.ingressQueueCapacity)
            val tls = request.tunnel.tlsInspection
            putExtra(EXTRA_TLS_ENABLED, tls.enabled)
            putStringArrayListExtra(EXTRA_TLS_PACKAGES, ArrayList(tls.selectedPackages))
            tls.sessionConsentVersion?.let { putExtra(EXTRA_TLS_CONSENT_VERSION, it) }
            tls.sessionConsentAcknowledgedAtMillis?.let { putExtra(EXTRA_TLS_CONSENT_ACKNOWLEDGED_AT, it) }
            tls.sessionConsentNonce?.let { putExtra(EXTRA_TLS_CONSENT_NONCE, it) }
            putExtra(EXTRA_TLS_MAX_SESSION_BYTES, tls.maximumSessionBytes)
            putExtra(EXTRA_TLS_MAX_FLOW_BYTES, tls.maximumBytesPerFlow)
            putExtra(EXTRA_TLS_MAX_DURATION, tls.maximumDurationMillis)
            request.remoteStreamAttachmentToken?.let { putExtra(EXTRA_REMOTE_STREAM_ATTACHMENT_TOKEN, it) }
            when (val selection = request.tunnel.appSelection) {
                is VpnAppSelection.AllAppsExcept -> {
                    putExtra(EXTRA_SELECTION_KIND, SELECTION_ALL_EXCEPT)
                    putStringArrayListExtra(EXTRA_PACKAGE_NAMES, ArrayList(selection.packageNames))
                }

                is VpnAppSelection.OnlyApps -> {
                    putExtra(EXTRA_SELECTION_KIND, SELECTION_ONLY_APPS)
                    putStringArrayListExtra(EXTRA_PACKAGE_NAMES, ArrayList(selection.packageNames))
                }
            }
        }

        fun stopIntent(context: Context): Intent = Intent(context, NetworkMonitorService::class.java)
            .setAction(ACTION_STOP)

        fun attachRemoteStreamIntent(context: Context, token: String): Intent = Intent(
            context,
            NetworkMonitorService::class.java,
        ).setAction(ACTION_ATTACH_REMOTE_STREAM).putExtra(EXTRA_REMOTE_STREAM_ATTACHMENT_TOKEN, token)

        private fun decodeStartRequest(intent: Intent): NetworkMonitorStartRequest? = runCatching {
            val selectionPackages = intent.getStringArrayListExtra(EXTRA_PACKAGE_NAMES)?.toSet().orEmpty()
            val selection = when (intent.getStringExtra(EXTRA_SELECTION_KIND)) {
                SELECTION_ALL_EXCEPT -> VpnAppSelection.AllAppsExcept(selectionPackages)
                SELECTION_ONLY_APPS -> VpnAppSelection.OnlyApps(selectionPackages)
                else -> error("Missing app selection.")
            }
            NetworkMonitorStartRequest(
                tunnel = TunnelConfiguration(
                    sessionName = intent.getStringExtra(EXTRA_SESSION_NAME) ?: error("Missing session name."),
                    mode = intent.getStringExtra(EXTRA_MODE)?.let(MonitoringMode::valueOf)
                        ?: error("Missing monitoring mode."),
                    enableIpv4 = intent.getBooleanExtra(EXTRA_IPV4, false),
                    enableIpv6 = intent.getBooleanExtra(EXTRA_IPV6, false),
                    appSelection = selection,
                    mtu = intent.getIntExtra(EXTRA_MTU, -1),
                    protocolEvidence = ProtocolEvidenceConfiguration(
                        enabled = intent.getBooleanExtra(EXTRA_PROTOCOL_EVIDENCE_ENABLED, false),
                        consent = decodeProtocolEvidenceConsent(intent),
                        inspectTlsClientHelloSni = intent.getBooleanExtra(EXTRA_PROTOCOL_EVIDENCE_TLS_SNI, false),
                        inspectCleartextHttp = intent.getBooleanExtra(EXTRA_PROTOCOL_EVIDENCE_HTTP, false),
                        maximumTrackedFlows = intent.getIntExtra(
                            EXTRA_PROTOCOL_EVIDENCE_MAX_FLOWS,
                            ProtocolEvidenceConfiguration().maximumTrackedFlows,
                        ),
                        maximumObservations = intent.getIntExtra(
                            EXTRA_PROTOCOL_EVIDENCE_MAX_OBSERVATIONS,
                            ProtocolEvidenceConfiguration().maximumObservations,
                        ),
                        maximumObservationsPerFlowDirection = intent.getIntExtra(
                            EXTRA_PROTOCOL_EVIDENCE_MAX_PER_FLOW_DIRECTION,
                            ProtocolEvidenceConfiguration().maximumObservationsPerFlowDirection,
                        ),
                    ),
                    payloadInspection = decodePayloadInspection(intent),
                    tlsInspection = decodeTlsInspection(intent),
                ),
                disclosureAcknowledgement = VpnDisclosureAcknowledgement(
                    disclosureVersion = intent.getStringExtra(EXTRA_DISCLOSURE_VERSION)
                        ?: error("Missing disclosure version."),
                    acknowledgedAtMillis = intent.getLongExtra(EXTRA_DISCLOSURE_ACKNOWLEDGED_AT, -1L),
                    nonce = intent.getStringExtra(EXTRA_DISCLOSURE_NONCE)
                        ?: error("Missing disclosure nonce."),
                ),
                remoteStreamAttachmentToken = intent.getStringExtra(EXTRA_REMOTE_STREAM_ATTACHMENT_TOKEN),
            )
        }.getOrNull()

        private fun decodeProtocolEvidenceConsent(intent: Intent): ProtocolEvidenceConsent? {
            if (!intent.getBooleanExtra(EXTRA_PROTOCOL_EVIDENCE_ENABLED, false)) return null
            return ProtocolEvidenceConsent(
                disclosureVersion = intent.getStringExtra(EXTRA_PROTOCOL_EVIDENCE_DISCLOSURE_VERSION)
                    ?: error("Missing protocol-evidence disclosure acknowledgement."),
                acknowledgedAtMillis = intent.getLongExtra(EXTRA_PROTOCOL_EVIDENCE_ACKNOWLEDGED_AT, -1L),
            )
        }

        private fun decodePayloadInspection(intent: Intent): PayloadInspectionConfiguration {
            val defaults = PayloadInspectionConfiguration()
            val enabled = intent.getBooleanExtra(EXTRA_PAYLOAD_INSPECTION_ENABLED, false)
            val consent = if (enabled) {
                PayloadInspectionConsent(
                    disclosureVersion = intent.getStringExtra(EXTRA_PAYLOAD_INSPECTION_DISCLOSURE_VERSION)
                        ?: error("Missing payload-inspection disclosure acknowledgement."),
                    acknowledgedAtMillis = intent.getLongExtra(EXTRA_PAYLOAD_INSPECTION_ACKNOWLEDGED_AT, -1L),
                )
            } else {
                null
            }
            return PayloadInspectionConfiguration(
                enabled = enabled,
                consent = consent,
                maximumSessionBytes = intent.getIntExtra(EXTRA_PAYLOAD_INSPECTION_MAX_SESSION_BYTES, defaults.maximumSessionBytes),
                maximumBytesPerFlow = intent.getIntExtra(EXTRA_PAYLOAD_INSPECTION_MAX_FLOW_BYTES, defaults.maximumBytesPerFlow),
                maximumRecords = intent.getIntExtra(EXTRA_PAYLOAD_INSPECTION_MAX_RECORDS, defaults.maximumRecords),
                maximumBytesPerRecord = intent.getIntExtra(EXTRA_PAYLOAD_INSPECTION_MAX_RECORD_BYTES, defaults.maximumBytesPerRecord),
                maximumDurationMillis = intent.getLongExtra(EXTRA_PAYLOAD_INSPECTION_MAX_DURATION, defaults.maximumDurationMillis),
                ingressQueueCapacity = intent.getIntExtra(EXTRA_PAYLOAD_INSPECTION_QUEUE_CAPACITY, defaults.ingressQueueCapacity),
            )
        }

        private fun decodeTlsInspection(intent: Intent): TlsInspectionTunnelConfiguration {
            val enabled = intent.getBooleanExtra(EXTRA_TLS_ENABLED, false)
            val packages = intent.getStringArrayListExtra(EXTRA_TLS_PACKAGES)?.toSet().orEmpty()
            return TlsInspectionTunnelConfiguration(
                enabled = enabled,
                selectedPackages = packages,
                sessionConsentVersion = intent.getStringExtra(EXTRA_TLS_CONSENT_VERSION),
                sessionConsentAcknowledgedAtMillis = intent.getLongExtra(EXTRA_TLS_CONSENT_ACKNOWLEDGED_AT, -1L)
                    .takeIf { it > 0L },
                sessionConsentNonce = intent.getStringExtra(EXTRA_TLS_CONSENT_NONCE),
                maximumSessionBytes = intent.getIntExtra(EXTRA_TLS_MAX_SESSION_BYTES, 128 * 1_024),
                maximumBytesPerFlow = intent.getIntExtra(EXTRA_TLS_MAX_FLOW_BYTES, 64 * 1_024),
                maximumDurationMillis = intent.getLongExtra(EXTRA_TLS_MAX_DURATION, 5 * 60 * 1_000L),
            )
        }
    }
}

sealed interface MonitoringStartRequestResult {
    object ConsentRequired : MonitoringStartRequestResult

    object StartRequested : MonitoringStartRequestResult
}

/** UI hook: obtain Android's intent after a separate app disclosure, then start only after success. */
object NetworkMonitorController {
    fun vpnConsentIntent(context: Context): Intent? = VpnService.prepare(context.applicationContext)

    fun startAfterUserConsent(
        context: Context,
        request: NetworkMonitorStartRequest,
    ): MonitoringStartRequestResult {
        if (VpnService.prepare(context.applicationContext) != null) {
            return MonitoringStartRequestResult.ConsentRequired
        }
        context.startForegroundService(NetworkMonitorService.startIntent(context, request))
        return MonitoringStartRequestResult.StartRequested
    }

    fun stop(context: Context) {
        context.startService(NetworkMonitorService.stopIntent(context))
    }
}
