package app.apksentinel.networkmonitor

import android.os.ParcelFileDescriptor
import java.net.DatagramSocket
import java.net.Socket
import java.util.UUID

/**
 * A forwarding implementation must explicitly report its real capabilities.
 * The built-in factory is intentionally narrow; a host may still install the
 * no-forwarder factory when it needs to disable route ownership altogether.
 */
data class ForwardingDataPlaneCapabilities(
    val canForwardIpv4: Boolean,
    val canForwardIpv6: Boolean,
    val canEnforceFirewallRules: Boolean,
    val appAttributionAvailability: CapabilityAvailability,
    val detail: String,
    /** True only when this data plane calls the module's non-blocking raw-IP capture hook. */
    val canOfferBoundedRawPcapngCapture: Boolean = false,
    /** A data plane must reject unsupported MTUs before the service establishes a full-route TUN. */
    val minimumMtu: Int = 576,
    /**
     * [LIMITED] means the forwarder can safely own the requested route only for
     * its documented protocol coverage. It must never be presented as complete
     * traffic coverage.
     */
    val trafficForwardingAvailability: CapabilityAvailability = CapabilityAvailability.AVAILABLE,
) {
    fun supports(configuration: TunnelConfiguration): Boolean =
        (!configuration.enableIpv4 || canForwardIpv4) &&
            (!configuration.enableIpv6 || canForwardIpv6) &&
            configuration.mtu >= minimumMtu &&
            trafficForwardingAvailability != CapabilityAvailability.UNAVAILABLE
}

/** Bounded operational counters only; this model never contains packet payloads or DNS names. */
data class ForwardingMetrics(
    val activeTcpFlows: Int = 0,
    val activeUdpFlows: Int = 0,
    val outboundPackets: Long = 0,
    val inboundPackets: Long = 0,
    val outboundPacketBytes: Long = 0,
    val inboundPacketBytes: Long = 0,
    val upstreamSentBytes: Long = 0,
    val upstreamReceivedBytes: Long = 0,
    val openedTcpFlows: Long = 0,
    val openedUdpFlows: Long = 0,
    val closedFlows: Long = 0,
    val blockedPackets: Long = 0,
    val unsupportedPackets: Long = 0,
    val malformedPackets: Long = 0,
    /**
     * Packets whose TCP/UDP checksum did not verify. These are still forwarded: a zero
     * UDP checksum is legal in IPv4, and checksum offload can leave the field unfinished,
     * so dropping on this would discard ordinary traffic. It is counted because IPv6 has
     * no header checksum at all, making this the only integrity signal available there.
     */
    val transportChecksumMismatches: Long = 0,
    val capacityRejections: Long = 0,
    val queueRejections: Long = 0,
    val packetTooLargeResponses: Long = 0,
)

data class ForwardedPacket(
    /**
     * Ephemeral input. Implementations must call the listener synchronously and
     * must not retain this array after it returns.
     */
    val bytes: ByteArray,
    val direction: PacketDirection,
    val observedAtMillis: Long,
    val attribution: AppAttribution = AppAttribution.Unknown(
        AttributionUnavailableReason.DATA_PLANE_DID_NOT_PROVIDE_UID,
    ),
)

data class PacketForwardingDirective(
    val shouldForward: Boolean,
    val firewallDecision: FirewallDecision? = null,
)

interface ForwardingDataPlaneListener {
    /** Called synchronously before a packet is forwarded or blocked. */
    fun onPacket(packet: ForwardedPacket): PacketForwardingDirective

    /** Required for a block/allow UI claim to become an enforcement claim. */
    fun onFirewallEnforcementResult(result: FirewallEnforcementResult)

    /** The data plane must surface unexpected termination rather than silently continuing. */
    fun onDataPlaneStopped(detail: String)
}

/** Lets a forwarder exempt its own upstream sockets from the local VPN loop. */
interface TunnelSocketProtector {
    fun protect(socket: Socket): Boolean

    fun protect(socket: DatagramSocket): Boolean

    fun protect(fileDescriptor: Int): Boolean
}

sealed interface ForwardingStartResult {
    object Started : ForwardingStartResult

    data class Rejected(val detail: String) : ForwardingStartResult
}

/**
 * Contract for a reviewed data plane. It owns packet I/O but not the supplied
 * descriptor's lifecycle; [NetworkMonitorService] closes it after [stop].
 *
 * A concrete implementation must fail before routing traffic when it cannot
 * forward the requested IP families/MTU. A header parser by itself is not a
 * data plane and must never be presented as one.
 */
interface ForwardingDataPlane {
    val capabilities: ForwardingDataPlaneCapabilities

    fun start(
        tunnel: ParcelFileDescriptor,
        configuration: TunnelConfiguration,
        socketProtector: TunnelSocketProtector,
        listener: ForwardingDataPlaneListener,
    ): ForwardingStartResult

    /** Optional process-local selected-app TLS route; no key material crosses this boundary. */
    fun start(
        tunnel: ParcelFileDescriptor,
        configuration: TunnelConfiguration,
        socketProtector: TunnelSocketProtector,
        listener: ForwardingDataPlaneListener,
        tlsInspectionSession: TlsInspectionRouteSession?,
    ): ForwardingStartResult = start(tunnel, configuration, socketProtector, listener)

    fun stop()

    /** Snapshot safe-to-display counters. Implementations may return zeros when not started. */
    fun metrics(): ForwardingMetrics = ForwardingMetrics()

    /**
     * Optional, ephemeral protocol-evidence snapshot. The default is disabled
     * and empty; it contains no raw bytes, bodies, headers, query values, or
     * credentials. Hosts must add their own disclosure and rendering policy
     * before making this visible outside the engine.
     */
    fun protocolEvidenceSnapshot(): ProtocolEvidenceSnapshot = ProtocolEvidenceSnapshot()

    /**
     * Optional, session-memory-only payload inspection. The default is
     * disabled. Returned records intentionally contain metadata only; hosts
     * need a second reveal acknowledgement and token before rendering redacted
     * text or hex. This is independent from metadata history and raw PCAPNG.
     */
    fun payloadInspectionSnapshot(): PayloadInspectionSnapshot = PayloadInspectionSnapshot()

    fun issuePayloadRevealToken(acknowledgement: PayloadRevealAcknowledgement): PayloadRevealToken? = null

    fun renderPayload(
        recordId: Long,
        token: PayloadRevealToken,
        format: PayloadRenderFormat,
    ): RenderedPayloadContent? = null

    /** Invalidates host reveal tokens while retaining the bounded session data. */
    fun revokePayloadRevealTokens() = Unit
}

fun interface ForwardingDataPlaneFactory {
    fun create(): ForwardingDataPlane
}

object NoForwardingDataPlaneFactory : ForwardingDataPlaneFactory {
    override fun create(): ForwardingDataPlane = NoForwardingDataPlane
}

private object NoForwardingDataPlane : ForwardingDataPlane {
    override val capabilities: ForwardingDataPlaneCapabilities = ForwardingDataPlaneCapabilities(
        canForwardIpv4 = false,
        canForwardIpv6 = false,
        canEnforceFirewallRules = false,
        appAttributionAvailability = CapabilityAvailability.UNAVAILABLE,
        detail = "No reviewed TUN forwarding data plane is installed. The module will not establish a traffic-capturing VPN route.",
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

fun interface EpochClock {
    fun nowMillis(): Long
}

object SystemEpochClock : EpochClock {
    override fun nowMillis(): Long = System.currentTimeMillis()
}

fun interface DnsNameHandlingFactory {
    fun forSession(sessionId: String): DnsNameHandling
}

/** Receives an exact forwarder result paired with its originating firewall decision. */
fun interface FirewallEnforcementObserver {
    fun onConfirmedOutcome(decision: FirewallDecision, result: FirewallEnforcementResult, atMillis: Long)
}

/** The privacy-preserving default: DNS name hashes are not stable across sessions. */
object HashDnsNamesByDefault : DnsNameHandlingFactory {
    override fun forSession(sessionId: String): DnsNameHandling =
        DnsNameHandling.HashPerSession("$sessionId:${UUID.randomUUID()}")
}

data class NetworkMonitorDependencies(
    val eventStore: NetworkEventStore = BoundedInMemoryNetworkEventStore(),
    /** Mutable, process-local rules let the default UI update the active policy without persistence. */
    val firewallRuleProvider: FirewallRuleProvider = InMemoryFirewallRuleProvider(),
    val forwardingDataPlaneFactory: ForwardingDataPlaneFactory = PureKotlinForwardingDataPlaneFactory,
    /** Created for each user-started service session; the built-in data plane calls it only while active. */
    val appAttributionProviderFactory: FlowAppAttributionProviderFactory = AndroidFlowAppAttributionProviderFactory,
    val dnsNameHandlingFactory: DnsNameHandlingFactory = HashDnsNamesByDefault,
    /**
     * Optional app-composed history sink. It is null by default, so the local
     * monitor remains process-local until a host explicitly composes history.
     */
    val durableHistory: DurableNetworkHistorySink? = null,
    /**
     * Optional, immutable offline country/ASN lookup supplied by the host.
     * It defaults to unavailable and is not consulted by the data plane,
     * storage, exports, or UI until a future reviewed composition opts in.
     */
    val offlineIpAttribution: OfflineIpAttributionLookup = OfflineIpAttributionLookup.unavailable(),
    /** Optional host observer. It receives only exact decision/result pairs from a forwarder. */
    val firewallEnforcementObserver: FirewallEnforcementObserver? = null,
    val clock: EpochClock = SystemEpochClock,
    /** Installed by the app only after CA setup, user consent, and public-CA verification. */
    val tlsInspectionRoute: TlsInspectionRoute? = null,
)

data class NetworkMonitorStatus(
    val sessionId: String? = null,
    val state: MonitorLifecycleState = MonitorLifecycleState.STOPPED,
    /** Diagnostic-only legacy text. UI must render [uiText], never this field. */
    val detail: String = "Monitoring is stopped.",
    val uiText: NetworkUiText = NetworkUiText.forLifecycle(state),
    val capabilities: CapabilitySnapshot? = null,
    val startedAtMillis: Long? = null,
    val endedAtMillis: Long? = null,
)

/**
 * Process-wide, payload-free UI surface. The default event store and firewall
 * rules are bounded and process-local. The store is capacity-evicted rather
 * than age-pruned, so it must not be described as a seven-day (or any other
 * time-window) history. Calling [install] while a session is active affects
 * only later sessions; reads continue to target the active session's dependency
 * snapshot until it stops.
 */
object NetworkMonitorRuntime {
    private const val DEFAULT_RECENT_EVENT_LIMIT = 128
    private val runtimeLock = Any()

    @Volatile
    private var dependencies: NetworkMonitorDependencies = NetworkMonitorDependencies()

    @Volatile
    private var status: NetworkMonitorStatus = NetworkMonitorStatus()

    /**
     * Domain-to-address bindings observed by the ACTIVE session only. Held here rather
     * than in the dependency snapshot because it is live session evidence, not
     * configuration, and it must disappear when the session does.
     */
    @Volatile
    private var domainBindings: DomainBindingRegistry? = null

    /**
     * The active session's DNS name handling. A caller outside the engine cannot derive a
     * lookup key without it, because the key is salted per session.
     */
    @Volatile
    private var domainNameHandling: DnsNameHandling? = null

    internal fun attachDomainBindings(value: DomainBindingRegistry, handling: DnsNameHandling) {
        domainBindings = value
        domainNameHandling = handling
    }

    internal fun detachDomainBindings() {
        domainBindings?.clear()
        domainBindings = null
        domainNameHandling = null
    }

    /** The active session's DNS name handling, or null when no session is running. */
    fun currentDnsNameHandling(): DnsNameHandling? = domainNameHandling

    /** The active session's observed bindings, or null when no session is running. */
    fun currentDomainBindings(): DomainBindingRegistry? = domainBindings

    fun install(value: NetworkMonitorDependencies) {
        synchronized(runtimeLock) {
            dependencies = value
        }
    }

    /**
     * Replaces only the optional durable-history sink for later sessions. An
     * active service retains its dependency snapshot, so a policy change cannot
     * redirect or close history halfway through an active VPN session.
     */
    fun installDurableHistoryForFutureSessions(value: DurableNetworkHistorySink?): NetworkMonitorDependencies =
        synchronized(runtimeLock) {
            dependencies = dependencies.copy(durableHistory = value)
            dependencies
        }

    /**
     * Adds a provider for later sessions without replacing process-local rules.
     * An active session keeps its immutable dependency snapshot.
     */
    fun addFirewallRuleProviderForFutureSessions(value: FirewallRuleProvider): NetworkMonitorDependencies =
        synchronized(runtimeLock) {
            dependencies = dependencies.copy(
                firewallRuleProvider = CompositeFirewallRuleProvider(dependencies.firewallRuleProvider, value),
            )
            dependencies
        }

    /** Installs a confirmed-outcome observer for later sessions only. */
    fun installFirewallEnforcementObserverForFutureSessions(value: FirewallEnforcementObserver?): NetworkMonitorDependencies =
        synchronized(runtimeLock) {
            dependencies = dependencies.copy(firewallEnforcementObserver = value)
            dependencies
        }

    /** Installs an immutable, already verified offline lookup for later sessions only. */
    fun installOfflineIpAttributionForFutureSessions(value: OfflineIpAttributionLookup): NetworkMonitorDependencies =
        synchronized(runtimeLock) {
            dependencies = dependencies.copy(offlineIpAttribution = value)
            dependencies
        }

    fun installTlsInspectionRouteForFutureSessions(value: TlsInspectionRoute?): NetworkMonitorDependencies =
        synchronized(runtimeLock) {
            dependencies = dependencies.copy(tlsInspectionRoute = value)
            dependencies
        }

    internal fun snapshot(): NetworkMonitorDependencies = dependencies

    fun currentStatus(): NetworkMonitorStatus = status

    /**
     * Returns an oldest-to-newest bounded snapshot. [NetworkEvent] never
     * contains raw packets or packet payloads; callers still choose whether to
     * render metadata such as addresses or consented DNS names.
     */
    fun recentEvents(limit: Int = DEFAULT_RECENT_EVENT_LIMIT): List<NetworkEvent> {
        require(limit >= 0) { "Recent-event limit must not be negative." }
        return resourcesForUi().eventStore.snapshot(limit)
    }

    /** Clears only retained in-memory events. It does not stop monitoring or alter firewall rules. */
    fun clearRecentEvents(): Int = resourcesForUi().eventStore.clear()

    /** Aggregate counters only; no packet contents, addresses, ports, or DNS names are exposed here. */
    fun forwardingMetrics(): ForwardingMetrics {
        val source = synchronized(runtimeLock) {
            ForwardingMetricsSource(activeResources?.dataPlane, latestForwardingMetrics)
        }
        return source.dataPlane?.let { dataPlane ->
            runCatching { dataPlane.metrics() }.getOrDefault(source.fallback)
        } ?: source.fallback
    }

    /**
     * Returns only the active session's bounded flow registry. The registry is
     * detached and discarded when monitoring stops; no flow snapshot is kept
     * as a post-session history.
     */
    fun flowRegistrySnapshot(): FlowRegistrySnapshot = resourcesForUi().flowRegistry.snapshotState()

    /**
     * Pass-through for the active forwarder's bounded protocol observations.
     * Protocol evidence is ephemeral and is intentionally empty after stop.
     */
    fun protocolEvidenceSnapshot(): ProtocolEvidenceSnapshot = synchronized(runtimeLock) {
        activeResources?.dataPlane?.let { dataPlane ->
            runCatching { dataPlane.protocolEvidenceSnapshot() }.getOrDefault(ProtocolEvidenceSnapshot())
        } ?: ProtocolEvidenceSnapshot()
    }

    /**
     * Metadata-only payload inspection state for the active session. This does
     * not expose content. A later host UI must surface the separate session
     * consent and request a second reveal acknowledgement before calling the
     * token/render methods below.
     */
    fun payloadInspectionSnapshot(): PayloadInspectionSnapshot = synchronized(runtimeLock) {
        activeResources?.dataPlane?.payloadInspectionSnapshot() ?: PayloadInspectionSnapshot()
    }

    fun issuePayloadRevealToken(acknowledgement: PayloadRevealAcknowledgement): PayloadRevealToken? =
        synchronized(runtimeLock) { activeResources?.dataPlane }
            ?.issuePayloadRevealToken(acknowledgement)

    fun renderPayload(
        recordId: Long,
        token: PayloadRevealToken,
        format: PayloadRenderFormat,
    ): RenderedPayloadContent? = synchronized(runtimeLock) { activeResources?.dataPlane }
        ?.renderPayload(recordId, token, format)

    fun revokePayloadRevealTokens() {
        synchronized(runtimeLock) { activeResources?.dataPlane }?.revokePayloadRevealTokens()
    }

    /**
     * Returns the active process-local rule set when the installed provider is
     * [InMemoryFirewallRuleProvider], or null when a host deliberately installs
     * a different provider. Its snapshot/mutation methods are synchronized.
     */
    fun inMemoryFirewallRules(): InMemoryFirewallRuleProvider? =
        resourcesForUi().firewallRuleProvider as? InMemoryFirewallRuleProvider

    internal fun updateStatus(value: NetworkMonitorStatus) {
        status = value
    }

    internal fun attachSessionResources(
        sessionId: String,
        eventStore: NetworkEventStore,
        firewallRuleProvider: FirewallRuleProvider,
        dataPlane: ForwardingDataPlane,
        flowRegistry: BoundedFlowRegistry = BoundedFlowRegistry(),
    ) {
        synchronized(runtimeLock) {
            activeResources = RuntimeSessionResources(
                sessionId = sessionId,
                eventStore = eventStore,
                firewallRuleProvider = firewallRuleProvider,
                dataPlane = dataPlane,
                flowRegistry = flowRegistry,
            )
        }
    }

    internal fun detachSessionResources(sessionId: String, dataPlane: ForwardingDataPlane) {
        val finalMetrics = runCatching { dataPlane.metrics() }.getOrNull()
        synchronized(runtimeLock) {
            val active = activeResources
            if (active?.sessionId == sessionId && active.dataPlane === dataPlane) {
                if (finalMetrics != null) latestForwardingMetrics = finalMetrics
                // Session evidence is not a post-session history surface. The
                // durable sink, when explicitly configured by the host, owns
                // its separate retention policy; process-local collectors and
                // reveal credentials must be empty after teardown.
                active.eventStore.clear()
                active.flowRegistry.clear()
                runCatching { dataPlane.revokePayloadRevealTokens() }
                activeResources = null
            }
        }
    }

    /** Intended for host tests only. */
    fun resetForTests() {
        synchronized(runtimeLock) {
            dependencies = NetworkMonitorDependencies()
            status = NetworkMonitorStatus()
            activeResources = null
            latestForwardingMetrics = ForwardingMetrics()
        }
    }

    private fun resourcesForUi(): RuntimeSessionResources = synchronized(runtimeLock) {
        activeResources ?: RuntimeSessionResources(
            sessionId = null,
            eventStore = dependencies.eventStore,
            firewallRuleProvider = dependencies.firewallRuleProvider,
            dataPlane = null,
            flowRegistry = BoundedFlowRegistry(capacity = 1),
        )
    }

    private data class RuntimeSessionResources(
        val sessionId: String?,
        val eventStore: NetworkEventStore,
        val firewallRuleProvider: FirewallRuleProvider,
        val dataPlane: ForwardingDataPlane?,
        val flowRegistry: BoundedFlowRegistry,
    )

    private data class ForwardingMetricsSource(
        val dataPlane: ForwardingDataPlane?,
        val fallback: ForwardingMetrics,
    )

    private var activeResources: RuntimeSessionResources? = null
    private var latestForwardingMetrics: ForwardingMetrics = ForwardingMetrics()
}

fun capabilitySnapshot(
    configuration: TunnelConfiguration,
    forwarder: ForwardingDataPlaneCapabilities,
    vpnConsentGranted: Boolean,
): CapabilitySnapshot {
    val forwardingAvailable = forwarder.supports(configuration)
    val forwardingAvailability = if (forwardingAvailable) {
        forwarder.trafficForwardingAvailability
    } else {
        CapabilityAvailability.UNAVAILABLE
    }
    val rawCaptureAvailability = if (forwardingAvailable && forwarder.canOfferBoundedRawPcapngCapture) {
        CapabilityAvailability.LIMITED
    } else {
        CapabilityAvailability.UNAVAILABLE
    }
    val firewallAvailability = when {
        configuration.mode != MonitoringMode.FIREWALL_ENFORCEMENT -> CapabilityAvailability.LIMITED
        !forwardingAvailable || !forwarder.canEnforceFirewallRules -> CapabilityAvailability.UNAVAILABLE
        forwardingAvailability == CapabilityAvailability.LIMITED -> CapabilityAvailability.LIMITED
        else -> CapabilityAvailability.AVAILABLE
    }
    return CapabilitySnapshot(
        reports = listOf(
            CapabilityReport(
                MonitoringCapabilityId.VPN_USER_CONSENT,
                if (vpnConsentGranted) CapabilityAvailability.AVAILABLE else CapabilityAvailability.REQUIRES_USER_CONSENT,
                if (vpnConsentGranted) "Android VPN consent is currently granted." else "Android VPN consent must be granted from the system-owned prompt.",
            ),
            familyCapability(
                MonitoringCapabilityId.IPV4_TUNNEL,
                configuration.enableIpv4,
                forwarder.canForwardIpv4,
                forwarder.trafficForwardingAvailability,
                "IPv4",
            ),
            familyCapability(
                MonitoringCapabilityId.IPV6_TUNNEL,
                configuration.enableIpv6,
                forwarder.canForwardIpv6,
                forwarder.trafficForwardingAvailability,
                "IPv6",
            ),
            CapabilityReport(
                MonitoringCapabilityId.TRAFFIC_FORWARDING,
                forwardingAvailability,
                when (forwardingAvailability) {
                    CapabilityAvailability.AVAILABLE ->
                        "The installed data plane declares support for the selected IP families and MTU."

                    CapabilityAvailability.LIMITED -> forwarder.detail
                    else ->
                        "${forwarder.detail} Requested MTU is ${configuration.mtu}; this data plane requires at least ${forwarder.minimumMtu}."
                },
            ),
            CapabilityReport(
                MonitoringCapabilityId.APP_ATTRIBUTION,
                forwarder.appAttributionAvailability,
                when (forwarder.appAttributionAvailability) {
                    CapabilityAvailability.LIMITED ->
                        "Per-app ownership uses Android's active-VPN TCP/UDP connection lookup on API 29 or later. " +
                            "It can be unavailable, has no result for some flows, and shared-UID or multi-package owners stay unknown."

                    CapabilityAvailability.AVAILABLE ->
                        "App attribution is supplied by the forwarding data plane; unknown and shared ownership remain explicit."

                    else -> "The installed data plane does not provide app ownership for these flows."
                },
            ),
            CapabilityReport(
                MonitoringCapabilityId.FIREWALL_ENFORCEMENT,
                firewallAvailability,
                when (firewallAvailability) {
                    CapabilityAvailability.AVAILABLE ->
                        "A forwarder must still confirm each block result before it is shown as enforced."

                    CapabilityAvailability.LIMITED -> if (configuration.mode == MonitoringMode.FIREWALL_ENFORCEMENT) {
                        "Firewall blocks are limited to the installed data plane's documented packet coverage."
                    } else {
                        "Firewall enforcement mode was not selected for this session."
                    }

                    else -> "The installed data plane does not confirm firewall enforcement."
                },
            ),
            CapabilityReport(
                MonitoringCapabilityId.DNS_METADATA,
                CapabilityAvailability.LIMITED,
                "Only bounded cleartext DNS over TCP or UDP port 53 is recognized; names are hashed per session by default.",
            ),
            CapabilityReport(
                MonitoringCapabilityId.PACKET_PAYLOAD_COLLECTION,
                rawCaptureAvailability,
                if (rawCaptureAvailability == CapabilityAvailability.LIMITED) {
                    "Payloads are never parsed or shown. An explicit, bounded local PCAPNG evidence session can temporarily write raw IPv4/IPv6 packets to a caller-selected stream."
                } else {
                    "The installed data plane does not provide a raw-IP capture hook, so packet payloads are not collected."
                },
            ),
            CapabilityReport(
                MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT,
                rawCaptureAvailability,
                if (rawCaptureAvailability == CapabilityAvailability.LIMITED) {
                    "User-started PCAPNG export writes bounded raw IPv4/IPv6 packets (DLT_RAW) to a caller-selected local stream. It has no TLS decryption, payload UI, remote streaming, UID attribution, or full-PCAPdroid coverage."
                } else {
                    "The installed data plane does not provide raw packet hooks, so PCAPNG export is unavailable."
                },
            ),
            CapabilityReport(
                MonitoringCapabilityId.METADATA_CAPTURE_EXPORT,
                CapabilityAvailability.LIMITED,
                "A bounded metadata-only JSON Lines export is available. It excludes raw packet bytes, endpoint addresses, ports, and DNS names; it is not packet capture.",
            ),
            CapabilityReport(
                MonitoringCapabilityId.TLS_DECRYPTION,
                CapabilityAvailability.UNAVAILABLE,
                "TLS decryption and MITM are intentionally not implemented.",
            ),
            CapabilityReport(
                MonitoringCapabilityId.ROOT_ESCALATION,
                CapabilityAvailability.UNAVAILABLE,
                "Root escalation is intentionally not implemented.",
            ),
            CapabilityReport(
                MonitoringCapabilityId.REMOTE_TRAFFIC_RELAY,
                CapabilityAvailability.UNAVAILABLE,
                "Traffic is not relayed to a remote VPN server by this module.",
            ),
        ),
    )
}

private fun familyCapability(
    capability: MonitoringCapabilityId,
    selected: Boolean,
    supportedByForwarder: Boolean,
    trafficForwardingAvailability: CapabilityAvailability,
    name: String,
): CapabilityReport = when {
    !selected -> CapabilityReport(capability, CapabilityAvailability.LIMITED, "$name was not selected for this session.")
    !supportedByForwarder || trafficForwardingAvailability == CapabilityAvailability.UNAVAILABLE ->
        CapabilityReport(capability, CapabilityAvailability.UNAVAILABLE, "$name is requested but unavailable in the installed data plane.")

    trafficForwardingAvailability == CapabilityAvailability.LIMITED ->
        CapabilityReport(capability, CapabilityAvailability.LIMITED, "$name is routed only for the installed data plane's documented protocol coverage.")

    supportedByForwarder -> CapabilityReport(capability, CapabilityAvailability.AVAILABLE, "$name is supported by the installed data plane.")
    else -> CapabilityReport(capability, CapabilityAvailability.UNAVAILABLE, "$name is requested but unavailable in the installed data plane.")
}

fun CapabilitySnapshot.limitations(): List<EngineLimitation> = reports.mapNotNull { report ->
    val code = when {
        report.capability == MonitoringCapabilityId.TRAFFIC_FORWARDING &&
            report.availability == CapabilityAvailability.LIMITED ->
            EngineLimitationCode.FORWARDING_DATA_PLANE_LIMITED_PROTOCOL_COVERAGE

        report.capability == MonitoringCapabilityId.TRAFFIC_FORWARDING ->
            EngineLimitationCode.FORWARDING_DATA_PLANE_UNAVAILABLE_FOR_CONFIGURATION

        else -> when (report.capability) {
        MonitoringCapabilityId.APP_ATTRIBUTION -> EngineLimitationCode.APP_ATTRIBUTION_NOT_AVAILABLE
        MonitoringCapabilityId.FIREWALL_ENFORCEMENT -> EngineLimitationCode.FIREWALL_ENFORCEMENT_NOT_SUPPORTED_BY_DATA_PLANE
        MonitoringCapabilityId.DNS_METADATA -> EngineLimitationCode.DNS_NAMES_HASHED_BY_DEFAULT
        MonitoringCapabilityId.PACKET_PAYLOAD_COLLECTION -> if (report.availability == CapabilityAvailability.LIMITED) {
            EngineLimitationCode.PACKET_PAYLOADS_NOT_PARSED_OR_REVEALED
        } else {
            EngineLimitationCode.PACKET_PAYLOADS_ARE_NOT_COLLECTED
        }
        MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT -> if (report.availability == CapabilityAvailability.LIMITED) {
            EngineLimitationCode.PCAPNG_RAW_PACKET_EXPORT_LIMITED
        } else {
            EngineLimitationCode.PCAPNG_RAW_PACKET_EXPORT_NOT_AVAILABLE
        }
        MonitoringCapabilityId.METADATA_CAPTURE_EXPORT -> EngineLimitationCode.METADATA_CAPTURE_EXPORT_IS_NOT_PACKET_CAPTURE
        MonitoringCapabilityId.TLS_DECRYPTION -> EngineLimitationCode.TLS_DECRYPTION_AND_MITM_NOT_IMPLEMENTED
        MonitoringCapabilityId.ROOT_ESCALATION -> EngineLimitationCode.ROOT_ESCALATION_NOT_IMPLEMENTED
        MonitoringCapabilityId.REMOTE_TRAFFIC_RELAY -> EngineLimitationCode.REMOTE_RELAY_NOT_IMPLEMENTED
        else -> null
        }
    }
    val isActualLimitation = when (report.capability) {
        MonitoringCapabilityId.FIREWALL_ENFORCEMENT -> report.availability == CapabilityAvailability.UNAVAILABLE
        else -> report.availability != CapabilityAvailability.AVAILABLE
    }
    if (code != null && isActualLimitation) EngineLimitation(code, report.detail) else null
}
