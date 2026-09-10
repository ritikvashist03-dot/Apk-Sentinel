package app.apksentinel.networkmonitor

import android.os.ParcelFileDescriptor
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

private fun InetAddress.literalHostAddress(): String = requireNotNull(hostAddress)

/** Factory for the built-in limited forwarder; hosts may install a different reviewed forwarder. */
object PureKotlinForwardingDataPlaneFactory : ForwardingDataPlaneFactory {
    override fun create(): ForwardingDataPlane = PureKotlinForwardingDataPlane()
}

/**
 * A no-root, local user-space TCP/UDP proxy for packets delivered by
 * [android.net.VpnService]. Every upstream socket is protected before it is
 * connected so it uses Android's underlying network rather than looping into
 * the TUN interface.
 *
 * This implementation intentionally has a narrow, visible contract: it
 * forwards unfragmented TCP and UDP for IPv4/IPv6, synthesizes TCP handshakes
 * and terminal errors, and bounds all retained in-flight buffers. It does not
 * decrypt TLS, retain packet payloads after forwarding, reassemble fragments,
 * implement TCP options/SACK/window scaling, proxy ICMP or IPsec, interpret
 * QUIC, or handle IPv6 extension-header traffic. QUIC is treated only as
 * opaque UDP when it fits the normal UDP forwarding path. Unsupported traffic
 * receives a local error whenever a valid IP header is available; malformed
 * input is recorded by the supplied listener and cannot safely be answered.
 */
class PureKotlinForwardingDataPlane(
    private val maximumFlows: Int = DEFAULT_MAXIMUM_FLOWS,
    private val maximumQueuedBytesPerFlow: Int = DEFAULT_MAXIMUM_QUEUED_BYTES_PER_FLOW,
    private val tcpIdleTimeoutMillis: Long = DEFAULT_TCP_IDLE_TIMEOUT_MILLIS,
    private val udpIdleTimeoutMillis: Long = DEFAULT_UDP_IDLE_TIMEOUT_MILLIS,
    private val clock: EpochClock = SystemEpochClock,
) : ForwardingDataPlane {
    init {
        require(maximumFlows in 1..4_096) { "Maximum flows must be between 1 and 4096." }
        require(maximumQueuedBytesPerFlow in 1_024..4 * 1_024 * 1_024) {
            "Maximum queued bytes per flow must be between 1024 and 4194304."
        }
        require(tcpIdleTimeoutMillis in 5_000L..30 * 60 * 1_000L) { "TCP idle timeout is outside the supported range." }
        require(udpIdleTimeoutMillis in 5_000L..30 * 60 * 1_000L) { "UDP idle timeout is outside the supported range." }
    }

    override val capabilities: ForwardingDataPlaneCapabilities = ForwardingDataPlaneCapabilities(
        canForwardIpv4 = true,
        canForwardIpv6 = true,
        canEnforceFirewallRules = true,
        canOfferBoundedRawPcapngCapture = true,
        appAttributionAvailability = CapabilityAvailability.LIMITED,
        minimumMtu = MINIMUM_SUPPORTED_MTU,
        trafficForwardingAvailability = CapabilityAvailability.LIMITED,
        detail = "Built-in local data plane forwards bounded, unfragmented IPv4/IPv6 TCP and UDP only. " +
            "It protects every upstream socket, enforces matching firewall blocks, and reports unsupported traffic explicitly. " +
            "Per-app ownership is limited to Android API 29+ active-VPN TCP/UDP connection lookup; unavailable, missing, and shared-UID/multi-package results remain unknown. " +
            "It does not proxy ICMP or IPsec, reassemble fragments, or inspect encrypted content; QUIC is opaque UDP only.",
    )

    private val stateLock = Any()
    private var activeState: RuntimeState? = null

    @Volatile
    private var appAttributionProvider: FlowAppAttributionProvider = NoFlowAppAttributionProvider

    @Volatile
    private var latestMetrics: ForwardingMetrics = ForwardingMetrics()

    @Volatile
    private var latestProtocolEvidence: ProtocolEvidenceSnapshot = ProtocolEvidenceSnapshot()

    @Volatile
    private var latestPayloadInspection: PayloadInspectionSnapshot = PayloadInspectionSnapshot()

    override fun start(
        tunnel: ParcelFileDescriptor,
        configuration: TunnelConfiguration,
        socketProtector: TunnelSocketProtector,
        listener: ForwardingDataPlaneListener,
    ): ForwardingStartResult = start(tunnel, configuration, socketProtector, listener, null)

    override fun start(
        tunnel: ParcelFileDescriptor,
        configuration: TunnelConfiguration,
        socketProtector: TunnelSocketProtector,
        listener: ForwardingDataPlaneListener,
        tlsInspectionSession: TlsInspectionRouteSession?,
    ): ForwardingStartResult {
        if (!capabilities.supports(configuration)) {
            return ForwardingStartResult.Rejected(
                "The built-in data plane requires a selected supported IP family and an MTU of at least $MINIMUM_SUPPORTED_MTU bytes.",
            )
        }

        val runtime = synchronized(stateLock) {
            if (activeState != null) return ForwardingStartResult.Rejected("A local forwarding data plane is already running.")
            val input = runCatching {
                ParcelFileDescriptor.AutoCloseInputStream(ParcelFileDescriptor.dup(tunnel.fileDescriptor))
            }.getOrElse { exception ->
                return ForwardingStartResult.Rejected("The TUN input descriptor could not be duplicated.")
            }
            val output = runCatching {
                ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(tunnel.fileDescriptor))
            }.getOrElse { exception ->
                runCatching { input.close() }
                return ForwardingStartResult.Rejected("The TUN output descriptor could not be duplicated.")
            }
            val selector = runCatching { Selector.open() }.getOrElse { exception ->
                runCatching { input.close() }
                runCatching { output.close() }
                return ForwardingStartResult.Rejected("The upstream socket selector could not be opened.")
            }
            RuntimeState(
                configuration = configuration,
                input = input,
                output = output,
                selector = selector,
                socketProtector = socketProtector,
                listener = listener,
                appAttributionProvider = appAttributionProvider,
                capacity = ForwardingFlowCapacity(maximumFlows),
                maximumQueuedBytesPerFlow = maximumQueuedBytesPerFlow,
                metrics = ForwardingMetricsCounter(),
                protocolEvidence = BoundedProtocolEvidenceCollector(configuration.protocolEvidence),
                payloadInspection = BoundedPayloadInspectionCollector(configuration.payloadInspection, clock),
                tlsInspectionSession = tlsInspectionSession,
            ).also { activeState = it }
        }

        try {
            runtime.readerThread = thread(
                start = true,
                isDaemon = true,
                name = "apk-sentinel-tun-reader",
            ) { readerLoop(runtime) }
            runtime.selectorThread = thread(
                start = true,
                isDaemon = true,
                name = "apk-sentinel-upstream-selector",
            ) { selectorLoop(runtime) }
        } catch (exception: RuntimeException) {
            closeRuntime(runtime, ownerRequested = true, detail = "Forwarding workers could not be started.")
            return ForwardingStartResult.Rejected("Forwarding workers could not be started.")
        }
        return ForwardingStartResult.Started
    }

    override fun stop() {
        val runtime = synchronized(stateLock) { activeState } ?: return
        closeRuntime(runtime, ownerRequested = true, detail = "Stopped by the owning VPN service.")
    }

    override fun metrics(): ForwardingMetrics = synchronized(stateLock) {
        activeState?.snapshotMetrics() ?: latestMetrics
    }

    override fun protocolEvidenceSnapshot(): ProtocolEvidenceSnapshot = synchronized(stateLock) {
        activeState?.protocolEvidence?.snapshot() ?: latestProtocolEvidence
    }

    override fun payloadInspectionSnapshot(): PayloadInspectionSnapshot = synchronized(stateLock) {
        activeState?.payloadInspection?.snapshot() ?: latestPayloadInspection
    }

    override fun issuePayloadRevealToken(acknowledgement: PayloadRevealAcknowledgement): PayloadRevealToken? = synchronized(stateLock) {
        activeState?.payloadInspection?.issueRevealToken(acknowledgement)
    }

    override fun renderPayload(
        recordId: Long,
        token: PayloadRevealToken,
        format: PayloadRenderFormat,
    ): RenderedPayloadContent? = synchronized(stateLock) {
        activeState?.payloadInspection?.render(recordId, token, format)
    }

    override fun revokePayloadRevealTokens() {
        synchronized(stateLock) { activeState?.payloadInspection }?.revokeRevealTokens()
    }

    internal fun installAppAttributionProvider(provider: FlowAppAttributionProvider) {
        synchronized(stateLock) {
            check(activeState == null) { "App attribution may only be installed before forwarding starts." }
            appAttributionProvider = provider
        }
    }

    private fun readerLoop(runtime: RuntimeState) {
        try {
            val buffer = ByteArray(runtime.configuration.mtu)
            while (runtime.running.get()) {
                val read = runtime.input.read(buffer)
                when {
                    read < 0 -> {
                        if (runtime.running.get()) closeRuntime(runtime, ownerRequested = false, detail = "Android closed the TUN input stream.")
                        return
                    }

                    read == 0 -> continue
                    else -> handleOutboundPacket(runtime, buffer.copyOf(read))
                }
            }
        } catch (exception: IOException) {
            if (runtime.running.get()) {
                closeRuntime(runtime, ownerRequested = false, detail = "TUN input failed.")
            }
        } catch (exception: RuntimeException) {
            if (runtime.running.get()) {
                closeRuntime(runtime, ownerRequested = false, detail = "TUN reader stopped unexpectedly.")
            }
        }
    }

    private fun handleOutboundPacket(runtime: RuntimeState, bytes: ByteArray) {
        if (!runtime.running.get()) return
        runtime.metrics.outboundPackets.incrementAndGet()
        runtime.metrics.outboundPacketBytes.addAndGet(bytes.size.toLong())
        // This is a non-blocking offer into a separately user-started bounded
        // session. A slow local document stream only increments capture drops;
        // it cannot delay forwarding or firewall evaluation.
        RawPcapngCaptureRuntime.offerRawIpPacket(bytes, clock.nowMillis())

        when (val parsed = TunPacketCodec.parse(bytes)) {
            is TunPacketParseResult.Parsed -> {
                // The IPv4 header checksum is mandatory and covers the header this plane
                // reads addresses and ports out of. If it does not verify, the fields the
                // firewall and attribution decisions rest on cannot be trusted, so the
                // packet is treated exactly like a malformed one: counted, not forwarded.
                //
                // The transport (TCP/UDP) checksum is deliberately NOT enforced here. A
                // zero UDP checksum is legal in IPv4 and simply means "not computed", and
                // checksum offload legitimately leaves the field unfinished on some paths.
                // Dropping on that would discard ordinary traffic - DNS above all.
                if (parsed.packet.version == IpVersion.IPV4 && !TunPacketCodec.verifyIpv4HeaderChecksum(bytes)) {
                    val checksumDirective = requestDirective(
                        runtime = runtime,
                        packet = ForwardedPacket(
                            bytes = bytes,
                            direction = PacketDirection.OUTBOUND,
                            observedAtMillis = clock.nowMillis(),
                        ),
                    ) ?: return
                    runtime.metrics.malformedPackets.incrementAndGet()
                    reportFirewallOutcome(
                        runtime,
                        checksumDirective,
                        FirewallEnforcementOutcome.FAILED,
                        "Malformed packet was not forwarded: IPv4 header checksum did not verify.",
                    )
                    return
                }
                // Observed, never enforced - see transportChecksumMismatches for why.
                if (!TunPacketCodec.verifyTransportChecksum(bytes)) {
                    runtime.metrics.transportChecksumMismatches.incrementAndGet()
                }
                val directive = requestDirective(
                    runtime = runtime,
                    packet = ForwardedPacket(
                        bytes = bytes,
                        direction = PacketDirection.OUTBOUND,
                        observedAtMillis = clock.nowMillis(),
                        attribution = attributionFor(runtime, parsed.packet, PacketDirection.OUTBOUND),
                    ),
                ) ?: return
                if (!directive.shouldForward) {
                    blockPacket(runtime, parsed.packet, directive)
                    return
                }
                observePayloadEvidence(runtime, parsed.packet, PacketDirection.OUTBOUND, clock.nowMillis())
                val attribution = attributionFor(runtime, parsed.packet, PacketDirection.OUTBOUND)
                when (val outcome = forwardPacket(runtime, parsed.packet, attribution)) {
                    is ForwardingAttempt.Accepted -> reportFirewallOutcome(
                        runtime,
                        directive,
                        FirewallEnforcementOutcome.ALLOWED,
                        outcome.detail,
                    )

                    is ForwardingAttempt.Rejected -> reportFirewallOutcome(
                        runtime,
                        directive,
                        FirewallEnforcementOutcome.FAILED,
                        outcome.detail,
                    )
                }
            }

            is TunPacketParseResult.Unsupported -> {
                val directive = requestDirective(
                    runtime = runtime,
                    packet = ForwardedPacket(
                        bytes = bytes,
                        direction = PacketDirection.OUTBOUND,
                        observedAtMillis = clock.nowMillis(),
                    ),
                ) ?: return
                runtime.metrics.unsupportedPackets.incrementAndGet()
                if (!directive.shouldForward && parsed.packet != null) {
                    blockPacket(runtime, parsed.packet, directive)
                } else {
                    parsed.packet?.replyContext?.let { context ->
                        emitIcmpError(runtime, context, IcmpErrorReason.UNSUPPORTED_PROTOCOL)
                    }
                    reportFirewallOutcome(
                        runtime,
                        directive,
                        FirewallEnforcementOutcome.FAILED,
                        parsed.reason,
                    )
                }
            }

            is TunPacketParseResult.Malformed -> {
                val directive = requestDirective(
                    runtime = runtime,
                    packet = ForwardedPacket(
                        bytes = bytes,
                        direction = PacketDirection.OUTBOUND,
                        observedAtMillis = clock.nowMillis(),
                    ),
                ) ?: return
                runtime.metrics.malformedPackets.incrementAndGet()
                reportFirewallOutcome(
                    runtime,
                    directive,
                    FirewallEnforcementOutcome.FAILED,
                    "Malformed packet was not forwarded: ${parsed.reason}",
                )
            }
        }
    }

    private fun requestDirective(runtime: RuntimeState, packet: ForwardedPacket): PacketForwardingDirective? = try {
        runtime.listener.onPacket(packet)
    } catch (exception: RuntimeException) {
        closeRuntime(runtime, ownerRequested = false, detail = "The monitoring listener failed.")
        null
    }

    private fun forwardPacket(runtime: RuntimeState, packet: TunIpPacket, attribution: AppAttribution): ForwardingAttempt = when {
        packet.tcp != null -> forwardTcpPacket(runtime, packet, attribution)
        packet.udp != null -> forwardUdpPacket(runtime, packet, attribution)
        else -> {
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.UNSUPPORTED_PROTOCOL)
            ForwardingAttempt.Rejected("The packet does not contain TCP or UDP transport data.")
        }
    }

    private fun blockPacket(
        runtime: RuntimeState,
        packet: TunIpPacket,
        directive: PacketForwardingDirective,
    ) {
        runtime.metrics.blockedPackets.incrementAndGet()
        val terminal = TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)
            ?: TunPacketCodec.icmpErrorFor(packet.replyContext, IcmpErrorReason.ADMINISTRATIVELY_PROHIBITED, runtime.configuration.mtu)
        if (terminal != null) emitInboundPacket(runtime, terminal)
        reportFirewallOutcome(
            runtime,
            directive,
            FirewallEnforcementOutcome.BLOCKED,
            "Blocked by an active local firewall rule before an upstream socket was used.",
        )
    }

    private fun forwardTcpPacket(runtime: RuntimeState, packet: TunIpPacket, attribution: AppAttribution): ForwardingAttempt {
        val tcp = requireNotNull(packet.tcp)
        val key = TransportFlowKey.from(packet, tcp.sourcePort, tcp.destinationPort)
        val existing = runtime.tcpFlows[key]
        if (existing != null) return handleExistingTcpPacket(runtime, existing, tcp)

        if ((tcp.flags and TunPacketCodec.TCP_FLAG_SYN) == 0 || (tcp.flags and TunPacketCodec.TCP_FLAG_ACK) != 0) {
            TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
            return ForwardingAttempt.Rejected("A new TCP flow must start with a SYN without ACK.")
        }
        if (
            tcp.payload.isNotEmpty() ||
            (tcp.flags and (TunPacketCodec.TCP_FLAG_FIN or TunPacketCodec.TCP_FLAG_RST)) != 0
        ) {
            TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
            return ForwardingAttempt.Rejected("TCP Fast Open data and terminal flags on an initial SYN are not supported.")
        }
        if (!runtime.capacity.tryAcquire()) {
            runtime.metrics.capacityRejections.incrementAndGet()
            TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
            return ForwardingAttempt.Rejected("The bounded local TCP/UDP flow limit was reached.")
        }

        val channel = try {
            SocketChannel.open().apply { configureBlocking(false) }
        } catch (exception: IOException) {
            runtime.capacity.release()
            TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
            return ForwardingAttempt.Rejected("The upstream TCP socket could not be opened.")
        }
        if (!runCatching { runtime.socketProtector.protect(channel.socket()) }.getOrDefault(false)) {
            runCatching { channel.close() }
            runtime.capacity.release()
            TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
            return ForwardingAttempt.Rejected("Android did not protect the upstream TCP socket, so the flow was not routed.")
        }

        val tlsDecision = if (tcp.destinationPort == TLS_PORT) {
            runtime.tlsInspectionSession?.openTcpFlow(attribution, tcp.destinationPort)
        } else null
        if (tlsDecision is TlsInspectionFlowDecision.Reject) {
            runCatching { channel.close() }
            runtime.capacity.release()
            TunPacketCodec.tcpResetFor(packet, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
            return ForwardingAttempt.Rejected("Selected TLS flow rejected: ${tlsDecision.reason.name}.")
        }
        val flow = TcpFlow(
            key = key,
            channel = channel,
            version = packet.version,
            clientAddress = packet.source,
            remoteAddress = packet.destination,
            clientPort = tcp.sourcePort,
            remotePort = tcp.destinationPort,
            clientNextSequence = tcp.nextSequence(),
            serverInitialSequence = nextInitialTcpSequence(),
            maximumPacketBytes = runtime.configuration.mtu,
            maximumPayloadBytes = maximumTcpPayload(packet.version, runtime.configuration.mtu),
            maximumQueuedBytes = runtime.maximumQueuedBytesPerFlow,
            lastSeenAtMillis = clock.nowMillis(),
            tlsFlow = (tlsDecision as? TlsInspectionFlowDecision.Intercept)?.flow,
        )
        if (runtime.tcpFlows.putIfAbsent(key, flow) != null) {
            runCatching { channel.close() }
            runtime.capacity.release()
            return runtime.tcpFlows[key]?.let { handleExistingTcpPacket(runtime, it, tcp) }
                ?: ForwardingAttempt.Rejected("The TCP flow changed while it was being created.")
        }

        val connected = try {
            channel.connect(InetSocketAddress(packet.destination, tcp.destinationPort))
        } catch (exception: IOException) {
            sendTcpReset(runtime, flow)
            closeTcpFlow(runtime, flow)
            return ForwardingAttempt.Rejected("The upstream TCP connection was rejected.")
        }
        flow.connectCompletedBeforeRegistration = connected
        runtime.registrations.add(SelectorRegistration.Tcp(flow))
        runtime.selector.wakeup()
        runtime.metrics.openedTcpFlows.incrementAndGet()
        return ForwardingAttempt.Accepted("TCP connection is being established through a protected upstream socket.")
    }

    private fun handleExistingTcpPacket(
        runtime: RuntimeState,
        flow: TcpFlow,
        tcp: TunTcpSegment,
    ): ForwardingAttempt {
        var sendSynAck = false
        var sendAck = false
        var sendReset = false
        var updateInterest = false
        var shutdownAfterWrites = false
        var rejection: String? = null
        var clientDidReset = false
        synchronized(flow.lock) {
            if (flow.closed.get()) return ForwardingAttempt.Rejected("The TCP flow has already closed.")
            flow.lastSeenAtMillis = clock.nowMillis()
            if ((tcp.flags and TunPacketCodec.TCP_FLAG_RST) != 0) {
                flow.clientReset = true
                clientDidReset = true
            } else if ((tcp.flags and TunPacketCodec.TCP_FLAG_SYN) != 0 && (tcp.flags and TunPacketCodec.TCP_FLAG_ACK) == 0) {
                sendSynAck = flow.proxyState != TcpProxyState.CONNECTING
            } else when (flow.proxyState) {
                TcpProxyState.CONNECTING -> {
                    // The app's TCP stack retransmits SYN while a non-blocking upstream connect is pending.
                }

                TcpProxyState.SYN_ACK_SENT -> {
                    if ((tcp.flags and TunPacketCodec.TCP_FLAG_ACK) != 0 && tcp.acknowledgement == flow.serverNextSequence) {
                        flow.proxyState = TcpProxyState.ESTABLISHED
                        flow.clientAcknowledgedServerSequence = flow.serverNextSequence
                        updateInterest = true
                    }
                    if (flow.proxyState == TcpProxyState.ESTABLISHED) {
                        updateInterest = updateInterest || acknowledgeRemoteDataLocked(flow, tcp)
                        val result = acceptTcpPayloadLocked(flow, tcp)
                        sendAck = result.sendAck
                        sendReset = result.sendReset
                        rejection = result.rejection
                        updateInterest = updateInterest || result.updateInterest
                        shutdownAfterWrites = result.shutdownAfterWrites
                    }
                }

                TcpProxyState.ESTABLISHED,
                TcpProxyState.REMOTE_FIN_SENT -> {
                    updateInterest = acknowledgeRemoteDataLocked(flow, tcp)
                    val result = acceptTcpPayloadLocked(flow, tcp)
                    sendAck = result.sendAck
                    sendReset = result.sendReset
                    rejection = result.rejection
                    updateInterest = updateInterest || result.updateInterest
                    shutdownAfterWrites = result.shutdownAfterWrites
                }

                TcpProxyState.CLOSED -> Unit
            }
        }
        if (clientDidReset) {
            closeTcpFlow(runtime, flow)
            return ForwardingAttempt.Accepted("The app reset its TCP connection.")
        }
        if (sendSynAck) emitTcpSynAck(runtime, flow)
        if (sendReset) {
            sendTcpReset(runtime, flow)
            closeTcpFlow(runtime, flow)
            return ForwardingAttempt.Rejected(rejection ?: "TCP buffering limits were reached.")
        }
        if (sendAck) emitTcpAck(runtime, flow)
        if (flow.tlsFlow != null) flushTlsClient(runtime, flow)
        if (shutdownAfterWrites) synchronized(flow.lock) { flow.closeOutputAfterPendingWrites = true }
        if (updateInterest) requestInterestUpdate(runtime, flow)
        return ForwardingAttempt.Accepted("TCP packet accepted by the bounded local flow state.")
    }

    private fun acceptTcpPayloadLocked(flow: TcpFlow, tcp: TunTcpSegment): TcpInboundResult {
        if (tcp.sequence != flow.clientNextSequence) {
            // Out-of-order and duplicate data are not buffered. An ACK of the next expected
            // sequence asks the kernel TCP stack to retransmit without silently consuming data.
            return TcpInboundResult(sendAck = true)
        }
        if (tcp.payload.isNotEmpty()) {
            if (flow.tlsFlow != null) {
                val result = flow.tlsFlow.onClientCiphertext(tcp.payload.copyOf())
                if (result.state == TlsInspectionFlowState.FAILED) {
                    flow.tlsFailure = result.failure
                    return TcpInboundResult(sendReset = true, rejection = "TLS inspection rejected the selected flow.")
                }
                if (!queueTlsOutputLocked(flow, result.toUpstream, upstream = true) ||
                    !queueTlsOutputLocked(flow, result.toClient, upstream = false)
                ) {
                    flow.tlsFailure = TlsInspectionRouteFailure.BUFFER_LIMIT
                    return TcpInboundResult(sendReset = true, rejection = "TLS inspection buffers reached their bound.")
                }
            } else {
                if (flow.queuedBytes + tcp.payload.size > flow.maximumQueuedBytes) {
                    return TcpInboundResult(
                        sendReset = true,
                        rejection = "The per-flow upstream TCP queue reached its safe limit.",
                    )
                }
                flow.pendingWrites.addLast(ByteBuffer.wrap(tcp.payload.copyOf()))
                flow.queuedBytes += tcp.payload.size
            }
            flow.clientNextSequence = incrementSequence(flow.clientNextSequence, tcp.payload.size)
        }
        val fin = (tcp.flags and TunPacketCodec.TCP_FLAG_FIN) != 0
        if (fin) {
            if (flow.tlsFlow != null) {
                val result = flow.tlsFlow.onClientClosed()
                if (result.state == TlsInspectionFlowState.FAILED ||
                    !queueTlsOutputLocked(flow, result.toUpstream, upstream = true)
                ) {
                    flow.tlsFailure = result.failure ?: TlsInspectionRouteFailure.BUFFER_LIMIT
                    return TcpInboundResult(sendReset = true, rejection = "TLS close_notify could not be forwarded.")
                }
            }
            flow.clientNextSequence = incrementSequence(flow.clientNextSequence, 1)
            flow.clientFinReceived = true
        }
        return TcpInboundResult(
            sendAck = tcp.payload.isNotEmpty() || fin || (tcp.flags and TunPacketCodec.TCP_FLAG_ACK) != 0,
            updateInterest = tcp.payload.isNotEmpty(),
            shutdownAfterWrites = fin,
        )
    }

    private fun queueTlsOutputLocked(flow: TcpFlow, bytes: ByteArray, upstream: Boolean): Boolean {
        if (bytes.isEmpty() || bytes.size > TlsInspectionFlowResult.MAX_OUTPUT_BYTES) return bytes.isEmpty()
        val current = if (upstream) flow.queuedBytes else flow.queuedClientBytes
        if (current + bytes.size > flow.maximumQueuedBytes) return false
        (if (upstream) flow.pendingWrites else flow.pendingClientWrites).addLast(ByteBuffer.wrap(bytes.copyOf()))
        if (upstream) flow.queuedBytes += bytes.size else flow.queuedClientBytes += bytes.size
        return true
    }

    /**
     * Keeps remote-to-app data bounded even though this compact proxy does not
     * implement full TCP retransmission. Invalid or out-of-window ACKs never
     * increase the receive window.
     */
    private fun acknowledgeRemoteDataLocked(flow: TcpFlow, tcp: TunTcpSegment): Boolean {
        if ((tcp.flags and TunPacketCodec.TCP_FLAG_ACK) == 0) return false
        val acknowledged = sequenceDistance(flow.clientAcknowledgedServerSequence, tcp.acknowledgement)
        if (acknowledged <= 0L || acknowledged > flow.outstandingInboundBytes) return false
        flow.clientAcknowledgedServerSequence = tcp.acknowledgement
        flow.outstandingInboundBytes -= acknowledged
        return true
    }

    private fun forwardUdpPacket(runtime: RuntimeState, packet: TunIpPacket, attribution: AppAttribution): ForwardingAttempt {
        val udp = requireNotNull(packet.udp)
        if (udp.destinationPort == TLS_PORT && runtime.tlsInspectionSession?.rejectUdpFlow(attribution, udp.destinationPort) == true) {
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.ADMINISTRATIVELY_PROHIBITED)
            return ForwardingAttempt.Rejected("Selected UDP/443 flow rejected; QUIC is not TLS-inspected.")
        }
        val key = TransportFlowKey.from(packet, udp.sourcePort, udp.destinationPort)
        val flow = runtime.udpFlows[key] ?: createUdpFlow(runtime, packet, key)
            ?: return ForwardingAttempt.Rejected("The protected upstream UDP socket could not be established.")

        val queued = synchronized(flow.lock) {
            flow.lastSeenAtMillis = clock.nowMillis()
            flow.latestReplyContext = packet.replyContext
            if (flow.queuedBytes + udp.payload.size > flow.maximumQueuedBytes) {
                false
            } else {
                flow.pendingWrites.addLast(ByteBuffer.wrap(udp.payload.copyOf()))
                flow.queuedBytes += udp.payload.size
                true
            }
        }
        if (!queued) {
            runtime.metrics.queueRejections.incrementAndGet()
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
            return ForwardingAttempt.Rejected("The per-flow upstream UDP queue reached its safe limit.")
        }
        requestInterestUpdate(runtime, flow)
        return ForwardingAttempt.Accepted("UDP datagram accepted by a protected upstream socket.")
    }

    private fun createUdpFlow(
        runtime: RuntimeState,
        packet: TunIpPacket,
        key: TransportFlowKey,
    ): UdpFlow? {
        if (!runtime.capacity.tryAcquire()) {
            runtime.metrics.capacityRejections.incrementAndGet()
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
            return null
        }
        val udp = requireNotNull(packet.udp)
        val channel = try {
            DatagramChannel.open().apply { configureBlocking(false) }
        } catch (_: IOException) {
            runtime.capacity.release()
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
            return null
        }
        if (!runCatching { runtime.socketProtector.protect(channel.socket()) }.getOrDefault(false)) {
            runCatching { channel.close() }
            runtime.capacity.release()
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
            return null
        }
        val flow = UdpFlow(
            key = key,
            channel = channel,
            version = packet.version,
            clientAddress = packet.source,
            remoteAddress = packet.destination,
            clientPort = udp.sourcePort,
            remotePort = udp.destinationPort,
            maximumPacketBytes = runtime.configuration.mtu,
            maximumQueuedBytes = runtime.maximumQueuedBytesPerFlow,
            lastSeenAtMillis = clock.nowMillis(),
            latestReplyContext = packet.replyContext,
        )
        try {
            channel.connect(InetSocketAddress(packet.destination, udp.destinationPort))
        } catch (_: IOException) {
            runCatching { channel.close() }
            runtime.capacity.release()
            emitIcmpError(runtime, packet.replyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
            return null
        }
        val existing = runtime.udpFlows.putIfAbsent(key, flow)
        if (existing != null) {
            runCatching { channel.close() }
            runtime.capacity.release()
            return existing
        }
        runtime.registrations.add(SelectorRegistration.Udp(flow))
        runtime.selector.wakeup()
        runtime.metrics.openedUdpFlows.incrementAndGet()
        return flow
    }

    private fun selectorLoop(runtime: RuntimeState) {
        try {
            while (runtime.running.get()) {
                drainSelectorCommands(runtime)
                runtime.selector.select(SELECTOR_WAIT_MILLIS)
                drainSelectorCommands(runtime)
                val selected = runtime.selector.selectedKeys().iterator()
                while (selected.hasNext()) {
                    val key = selected.next()
                    selected.remove()
                    if (!key.isValid) continue
                    when (val attachment = key.attachment()) {
                        is TcpFlow -> serviceTcpKey(runtime, key, attachment)
                        is UdpFlow -> serviceUdpKey(runtime, key, attachment)
                        else -> Unit
                    }
                }
                evictIdleFlows(runtime)
            }
        } catch (exception: IOException) {
            if (runtime.running.get()) {
                closeRuntime(runtime, ownerRequested = false, detail = "The upstream socket selector failed.")
            }
        } catch (exception: RuntimeException) {
            if (runtime.running.get()) {
                closeRuntime(runtime, ownerRequested = false, detail = "The upstream socket selector stopped unexpectedly.")
            }
        }
    }

    private fun drainSelectorCommands(runtime: RuntimeState) {
        while (true) {
            when (val command = runtime.registrations.poll() ?: break) {
                is SelectorRegistration.Tcp -> registerTcp(runtime, command.flow)
                is SelectorRegistration.Udp -> registerUdp(runtime, command.flow)
            }
        }
        while (true) {
            when (val flow = runtime.interestUpdates.poll() ?: break) {
                is TcpFlow -> updateTcpInterest(runtime, flow)
                is UdpFlow -> updateUdpInterest(runtime, flow)
                else -> Unit
            }
        }
    }

    private fun registerTcp(runtime: RuntimeState, flow: TcpFlow) {
        if (flow.closed.get()) return
        try {
            val ops = if (flow.connectCompletedBeforeRegistration || flow.channel.isConnected) 0 else SelectionKey.OP_CONNECT
            flow.channel.register(runtime.selector, ops, flow)
            if (flow.channel.isConnected) onTcpConnected(runtime, flow)
        } catch (exception: IOException) {
            sendTcpReset(runtime, flow)
            closeTcpFlow(runtime, flow)
        }
    }

    private fun registerUdp(runtime: RuntimeState, flow: UdpFlow) {
        if (flow.closed.get()) return
        try {
            flow.channel.register(runtime.selector, udpInterestOps(flow), flow)
        } catch (_: IOException) {
            emitIcmpError(runtime, flow.latestReplyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
            closeUdpFlow(runtime, flow)
        }
    }

    private fun serviceTcpKey(runtime: RuntimeState, key: SelectionKey, flow: TcpFlow) {
        if (flow.closed.get()) return
        if (key.isConnectable) onTcpConnectable(runtime, flow)
        if (key.isValid && key.isWritable) writePendingTcp(runtime, flow)
        if (key.isValid && key.isReadable) readTcp(runtime, flow)
    }

    private fun serviceUdpKey(runtime: RuntimeState, key: SelectionKey, flow: UdpFlow) {
        if (flow.closed.get()) return
        if (key.isWritable) writePendingUdp(runtime, flow)
        if (key.isValid && key.isReadable) readUdp(runtime, flow)
    }

    private fun onTcpConnectable(runtime: RuntimeState, flow: TcpFlow) {
        try {
            if (flow.channel.finishConnect()) onTcpConnected(runtime, flow)
        } catch (_: IOException) {
            sendTcpReset(runtime, flow)
            closeTcpFlow(runtime, flow)
        }
    }

    private fun onTcpConnected(runtime: RuntimeState, flow: TcpFlow) {
        val shouldSend = synchronized(flow.lock) {
            if (flow.closed.get() || flow.proxyState != TcpProxyState.CONNECTING) false else {
                flow.proxyState = TcpProxyState.SYN_ACK_SENT
                flow.serverNextSequence = incrementSequence(flow.serverInitialSequence, 1)
                flow.lastSeenAtMillis = clock.nowMillis()
                true
            }
        }
        if (shouldSend) emitTcpSynAck(runtime, flow)
        requestInterestUpdate(runtime, flow)
    }

    private fun readTcp(runtime: RuntimeState, flow: TcpFlow) {
        val state = synchronized(flow.lock) { flow.proxyState }
        if (state != TcpProxyState.ESTABLISHED) return
        while (runtime.running.get() && !flow.closed.get()) {
            if (synchronized(flow.lock) { flow.outstandingInboundBytes >= MAXIMUM_UNACKNOWLEDGED_INBOUND_BYTES }) {
                requestInterestUpdate(runtime, flow)
                return
            }
            val buffer = flow.remoteReadBuffer
            buffer.clear()
            val read = try {
                flow.channel.read(buffer)
            } catch (_: IOException) {
                sendTcpReset(runtime, flow)
                closeTcpFlow(runtime, flow)
                return
            }
            when {
                read < 0 -> {
                    if (flow.tlsFlow != null) {
                        val result = flow.tlsFlow.onUpstreamClosed()
                        val queued = synchronized(flow.lock) {
                            result.state != TlsInspectionFlowState.FAILED &&
                                queueTlsOutputLocked(flow, result.toClient, upstream = false)
                        }
                        if (!queued) {
                            sendTcpReset(runtime, flow)
                            closeTcpFlow(runtime, flow)
                            return
                        }
                        flushTlsClient(runtime, flow)
                    }
                    sendTcpFin(runtime, flow)
                    requestInterestUpdate(runtime, flow)
                    return
                }

                read == 0 -> return
                else -> {
                    buffer.flip()
                    val payload = ByteArray(read)
                    buffer.get(payload)
                    if (flow.tlsFlow != null) {
                        val result = flow.tlsFlow.onUpstreamCiphertext(payload.copyOf())
                        if (result.state == TlsInspectionFlowState.FAILED) {
                            sendTcpReset(runtime, flow)
                            closeTcpFlow(runtime, flow)
                            return
                        }
                        val queued = synchronized(flow.lock) {
                            queueTlsOutputLocked(flow, result.toUpstream, upstream = true) &&
                                queueTlsOutputLocked(flow, result.toClient, upstream = false)
                        }
                        if (!queued) {
                            sendTcpReset(runtime, flow)
                            closeTcpFlow(runtime, flow)
                            return
                        }
                        flushTlsClient(runtime, flow)
                        runtime.metrics.upstreamReceivedBytes.addAndGet(payload.size.toLong())
                        continue
                    }
                    val outbound = synchronized(flow.lock) {
                        if (flow.closed.get()) {
                            null
                        } else {
                            val packet = TunPacketCodec.tcpPacket(
                                version = flow.version,
                                source = flow.remoteAddress,
                                destination = flow.clientAddress,
                                sourcePort = flow.remotePort,
                                destinationPort = flow.clientPort,
                                sequence = flow.serverNextSequence,
                                acknowledgement = flow.clientNextSequence,
                                flags = TunPacketCodec.TCP_FLAG_ACK or TunPacketCodec.TCP_FLAG_PSH,
                                payload = payload,
                                maximumPacketBytes = flow.maximumPacketBytes,
                            )
                            // Advance the synthetic receive state before exposing the
                            // packet to the TUN. The app can ACK immediately on the
                            // reader thread, so doing this afterward loses that ACK.
                            flow.serverNextSequence = incrementSequence(flow.serverNextSequence, payload.size)
                            flow.outstandingInboundBytes += payload.size.toLong()
                            flow.lastSeenAtMillis = clock.nowMillis()
                            packet
                        }
                    } ?: return
                    if (!emitInboundPacket(runtime, outbound)) return
                    runtime.metrics.upstreamReceivedBytes.addAndGet(payload.size.toLong())
                }
            }
        }
    }

    private fun writePendingTcp(runtime: RuntimeState, flow: TcpFlow) {
        while (!flow.closed.get()) {
            val buffer = synchronized(flow.lock) { flow.pendingWrites.firstOrNull() } ?: break
            if (!buffer.hasRemaining()) {
                synchronized(flow.lock) {
                    if (flow.pendingWrites.firstOrNull() === buffer) flow.pendingWrites.removeFirst()
                }
                continue
            }
            val written = try {
                flow.channel.write(buffer)
            } catch (_: IOException) {
                sendTcpReset(runtime, flow)
                closeTcpFlow(runtime, flow)
                return
            }
            if (written <= 0) break
            synchronized(flow.lock) {
                flow.queuedBytes -= written
                if (!buffer.hasRemaining()) flow.pendingWrites.removeFirst()
                flow.lastSeenAtMillis = clock.nowMillis()
            }
            runtime.metrics.upstreamSentBytes.addAndGet(written.toLong())
        }
        val shouldShutdownOutput = synchronized(flow.lock) {
            flow.closeOutputAfterPendingWrites && flow.pendingWrites.isEmpty() && !flow.outputShutdown
        }
        if (shouldShutdownOutput) {
            try {
                flow.channel.socket().shutdownOutput()
                synchronized(flow.lock) { flow.outputShutdown = true }
            } catch (_: IOException) {
                sendTcpReset(runtime, flow)
                closeTcpFlow(runtime, flow)
                return
            }
        }
        requestInterestUpdate(runtime, flow)
    }

    private fun flushTlsClient(runtime: RuntimeState, flow: TcpFlow) {
        while (!flow.closed.get()) {
            val packet = synchronized(flow.lock) {
                if (flow.outstandingInboundBytes >= MAXIMUM_UNACKNOWLEDGED_INBOUND_BYTES) return
                val buffer = flow.pendingClientWrites.firstOrNull() ?: return
                if (!buffer.hasRemaining()) {
                    flow.pendingClientWrites.removeFirst()
                    return@synchronized null
                }
                val size = minOf(buffer.remaining(), flow.maximumPayloadBytes)
                val chunk = ByteArray(size)
                buffer.get(chunk)
                flow.queuedClientBytes -= size
                if (!buffer.hasRemaining()) flow.pendingClientWrites.removeFirst()
                val value = TunPacketCodec.tcpPacket(
                    version = flow.version,
                    source = flow.remoteAddress,
                    destination = flow.clientAddress,
                    sourcePort = flow.remotePort,
                    destinationPort = flow.clientPort,
                    sequence = flow.serverNextSequence,
                    acknowledgement = flow.clientNextSequence,
                    flags = TunPacketCodec.TCP_FLAG_ACK or TunPacketCodec.TCP_FLAG_PSH,
                    payload = chunk,
                    maximumPacketBytes = flow.maximumPacketBytes,
                )
                flow.serverNextSequence = incrementSequence(flow.serverNextSequence, chunk.size)
                flow.outstandingInboundBytes += chunk.size.toLong()
                value
            }
            if (packet != null && !emitInboundPacket(runtime, packet)) return
            if (packet == null) continue
        }
    }

    private fun readUdp(runtime: RuntimeState, flow: UdpFlow) {
        while (runtime.running.get() && !flow.closed.get()) {
            val buffer = runtime.udpReceiveBuffer
            buffer.clear()
            val source = try {
                flow.channel.receive(buffer)
            } catch (_: IOException) {
                closeUdpFlow(runtime, flow)
                return
            } ?: return
            if (source !is InetSocketAddress) return
            buffer.flip()
            val payload = ByteArray(buffer.remaining())
            buffer.get(payload)
            val replyContext = synchronized(flow.lock) { flow.latestReplyContext }
            val response = runCatching {
                TunPacketCodec.udpPacket(
                    version = flow.version,
                    source = flow.remoteAddress,
                    destination = flow.clientAddress,
                    sourcePort = flow.remotePort,
                    destinationPort = flow.clientPort,
                    payload = payload,
                    maximumPacketBytes = flow.maximumPacketBytes,
                )
            }.getOrNull()
            if (response == null) {
                runtime.metrics.packetTooLargeResponses.incrementAndGet()
                emitIcmpError(runtime, replyContext, IcmpErrorReason.PACKET_TOO_LARGE)
                closeUdpFlow(runtime, flow)
                return
            }
            if (!emitInboundPacket(runtime, response)) return
            synchronized(flow.lock) { flow.lastSeenAtMillis = clock.nowMillis() }
            runtime.metrics.upstreamReceivedBytes.addAndGet(payload.size.toLong())
        }
    }

    private fun writePendingUdp(runtime: RuntimeState, flow: UdpFlow) {
        while (!flow.closed.get()) {
            val buffer = synchronized(flow.lock) { flow.pendingWrites.firstOrNull() } ?: break
            if (!buffer.hasRemaining()) {
                // A zero-length UDP datagram is valid. DatagramChannel reports zero
                // bytes for it, so attempt the send once and then remove the queued
                // datagram rather than spinning forever on its byte count.
                try {
                    flow.channel.write(buffer)
                } catch (_: IOException) {
                    emitIcmpError(runtime, flow.latestReplyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
                    closeUdpFlow(runtime, flow)
                    return
                }
                synchronized(flow.lock) { if (flow.pendingWrites.firstOrNull() === buffer) flow.pendingWrites.removeFirst() }
                continue
            }
            val written = try {
                flow.channel.write(buffer)
            } catch (_: IOException) {
                emitIcmpError(runtime, flow.latestReplyContext, IcmpErrorReason.RESOURCE_UNAVAILABLE)
                closeUdpFlow(runtime, flow)
                return
            }
            if (written <= 0) break
            synchronized(flow.lock) {
                flow.queuedBytes -= written
                if (!buffer.hasRemaining()) flow.pendingWrites.removeFirst()
                flow.lastSeenAtMillis = clock.nowMillis()
            }
            runtime.metrics.upstreamSentBytes.addAndGet(written.toLong())
        }
        requestInterestUpdate(runtime, flow)
    }

    private fun emitTcpSynAck(runtime: RuntimeState, flow: TcpFlow) {
        val packet = synchronized(flow.lock) {
            if (flow.closed.get()) null else TunPacketCodec.tcpPacket(
                version = flow.version,
                source = flow.remoteAddress,
                destination = flow.clientAddress,
                sourcePort = flow.remotePort,
                destinationPort = flow.clientPort,
                sequence = flow.serverInitialSequence,
                acknowledgement = flow.clientNextSequence,
                flags = TunPacketCodec.TCP_FLAG_SYN or TunPacketCodec.TCP_FLAG_ACK,
                maximumPacketBytes = flow.maximumPacketBytes,
            )
        }
        if (packet != null) emitInboundPacket(runtime, packet)
    }

    private fun emitTcpAck(runtime: RuntimeState, flow: TcpFlow) {
        val packet = synchronized(flow.lock) {
            if (flow.closed.get()) null else TunPacketCodec.tcpPacket(
                version = flow.version,
                source = flow.remoteAddress,
                destination = flow.clientAddress,
                sourcePort = flow.remotePort,
                destinationPort = flow.clientPort,
                sequence = flow.serverNextSequence,
                acknowledgement = flow.clientNextSequence,
                flags = TunPacketCodec.TCP_FLAG_ACK,
                maximumPacketBytes = flow.maximumPacketBytes,
            )
        }
        if (packet != null) emitInboundPacket(runtime, packet)
    }

    private fun sendTcpFin(runtime: RuntimeState, flow: TcpFlow) {
        val packet = synchronized(flow.lock) {
            if (flow.closed.get() || flow.proxyState == TcpProxyState.REMOTE_FIN_SENT) null else {
                val value = TunPacketCodec.tcpPacket(
                    version = flow.version,
                    source = flow.remoteAddress,
                    destination = flow.clientAddress,
                    sourcePort = flow.remotePort,
                    destinationPort = flow.clientPort,
                    sequence = flow.serverNextSequence,
                    acknowledgement = flow.clientNextSequence,
                    flags = TunPacketCodec.TCP_FLAG_FIN or TunPacketCodec.TCP_FLAG_ACK,
                    maximumPacketBytes = flow.maximumPacketBytes,
                )
                flow.serverNextSequence = incrementSequence(flow.serverNextSequence, 1)
                flow.outstandingInboundBytes += 1L
                flow.proxyState = TcpProxyState.REMOTE_FIN_SENT
                value
            }
        }
        if (packet != null) emitInboundPacket(runtime, packet)
    }

    private fun sendTcpReset(runtime: RuntimeState, flow: TcpFlow) {
        val packet = synchronized(flow.lock) {
            if (flow.closed.get()) null else TunPacketCodec.tcpPacket(
                version = flow.version,
                source = flow.remoteAddress,
                destination = flow.clientAddress,
                sourcePort = flow.remotePort,
                destinationPort = flow.clientPort,
                // A refused upstream connect is a reset of the app's original SYN;
                // RFC-style SYN-SENT resets use sequence zero and acknowledge the
                // app's next sequence. Established flows use the synthetic server
                // sequence currently visible to the app.
                sequence = if (flow.proxyState == TcpProxyState.CONNECTING) 0L else flow.serverNextSequence,
                acknowledgement = flow.clientNextSequence,
                flags = TunPacketCodec.TCP_FLAG_RST or TunPacketCodec.TCP_FLAG_ACK,
                maximumPacketBytes = flow.maximumPacketBytes,
            )
        }
        if (packet != null) emitInboundPacket(runtime, packet)
    }

    private fun emitIcmpError(runtime: RuntimeState, context: TunReplyContext, reason: IcmpErrorReason) {
        TunPacketCodec.icmpErrorFor(context, reason, runtime.configuration.mtu)?.let { emitInboundPacket(runtime, it) }
    }

    /** Records inbound metadata before injecting the packet; inbound rules do not suppress a response for an allowed flow. */
    private fun emitInboundPacket(runtime: RuntimeState, packet: ByteArray): Boolean {
        if (!runtime.running.get()) return false
        RawPcapngCaptureRuntime.offerRawIpPacket(packet, clock.nowMillis())
        val parsedPacket = (TunPacketCodec.parse(packet) as? TunPacketParseResult.Parsed)?.packet
        parsedPacket?.let { observePayloadEvidence(runtime, it, PacketDirection.INBOUND, clock.nowMillis()) }
        val attribution = parsedPacket
            ?.let { attributionFor(runtime, it, PacketDirection.INBOUND) }
            ?: AppAttribution.Unknown(AttributionUnavailableReason.NOT_ATTEMPTED)
        if (requestDirective(
                runtime,
                ForwardedPacket(
                    bytes = packet,
                    direction = PacketDirection.INBOUND,
                    observedAtMillis = clock.nowMillis(),
                    attribution = attribution,
                ),
            ) == null
        ) return false
        return try {
            synchronized(runtime.tunWriteLock) {
                runtime.output.write(packet)
                runtime.output.flush()
            }
            runtime.metrics.inboundPackets.incrementAndGet()
            runtime.metrics.inboundPacketBytes.addAndGet(packet.size.toLong())
            true
        } catch (exception: IOException) {
            if (runtime.running.get()) {
                closeRuntime(runtime, ownerRequested = false, detail = "TUN output failed.")
            }
            false
        }
    }

    /**
     * This runs synchronously against one already-parsed TCP packet only. It
     * does not buffer/reassemble bytes, open traffic, alter the forwarding
     * decision, or retain packet data after the parser returns.
     */
    private fun observePayloadEvidence(
        runtime: RuntimeState,
        packet: TunIpPacket,
        direction: PacketDirection,
        observedAtMillis: Long,
    ) {
        val tcp = packet.tcp
        if (tcp != null && tcp.payload.isNotEmpty()) {
            val flow = ProtocolEvidenceFlowKey(
                sourceAddress = packet.source.literalHostAddress(),
                sourcePort = tcp.sourcePort,
                destinationAddress = packet.destination.literalHostAddress(),
                destinationPort = tcp.destinationPort,
            )
            runtime.protocolEvidence.observeTcpPayload(
                flow = flow,
                direction = direction,
                payload = tcp.payload,
                observedAtMillis = observedAtMillis.coerceAtLeast(0L),
            )
            runtime.payloadInspection.offer(
                flow = PayloadFlowKey(flow.sourceAddress, flow.sourcePort, flow.destinationAddress, flow.destinationPort, PayloadInspectionTransport.TCP),
                direction = direction,
                transport = PayloadInspectionTransport.TCP,
                payload = tcp.payload,
                observedAtMillis = observedAtMillis.coerceAtLeast(0L),
            )
        }
        val udp = packet.udp
        if (udp != null && udp.payload.isNotEmpty()) {
            runtime.payloadInspection.offer(
                flow = PayloadFlowKey(
                    packet.source.literalHostAddress(),
                    udp.sourcePort,
                    packet.destination.literalHostAddress(),
                    udp.destinationPort,
                    PayloadInspectionTransport.UDP,
                ),
                direction = direction,
                transport = PayloadInspectionTransport.UDP,
                payload = udp.payload,
                observedAtMillis = observedAtMillis.coerceAtLeast(0L),
            )
        }
    }

    /** Never invoke Android's owner API for a non-TCP/UDP packet. */
    private fun attributionFor(
        runtime: RuntimeState,
        packet: TunIpPacket,
        direction: PacketDirection,
    ): AppAttribution = if (packet.tcp != null || packet.udp != null) {
        runtime.appAttributionProvider.attributionForSafely(
            requireNotNull(packet.toConnectionOwnerFlow(direction)),
        )
    } else {
        AppAttribution.Unknown(AttributionUnavailableReason.UNSUPPORTED_PROTOCOL)
    }

    private fun reportFirewallOutcome(
        runtime: RuntimeState,
        directive: PacketForwardingDirective,
        outcome: FirewallEnforcementOutcome,
        detail: String,
    ) {
        val decision = directive.firewallDecision ?: return
        // An allow rule only selects the normal forwarding path. It is not proof
        // that bytes reached the upstream peer, so never promote it to a
        // CONFIRMED_ALLOWED enforcement claim.
        if (decision.requestedAction != FirewallAction.BLOCK) return
        try {
            runtime.listener.onFirewallEnforcementResult(
                FirewallEnforcementResult(decision.directiveId, outcome, detail),
            )
        } catch (exception: RuntimeException) {
            closeRuntime(runtime, ownerRequested = false, detail = "The firewall-result listener failed.")
        }
    }

    private fun requestInterestUpdate(runtime: RuntimeState, flow: Any) {
        runtime.interestUpdates.add(flow)
        runtime.selector.wakeup()
    }

    private fun updateTcpInterest(runtime: RuntimeState, flow: TcpFlow) {
        if (flow.closed.get()) return
        val key = flow.channel.keyFor(runtime.selector) ?: return
        if (!key.isValid) return
        key.interestOps(tcpInterestOps(flow))
    }

    private fun updateUdpInterest(runtime: RuntimeState, flow: UdpFlow) {
        if (flow.closed.get()) return
        val key = flow.channel.keyFor(runtime.selector) ?: return
        if (!key.isValid) return
        key.interestOps(udpInterestOps(flow))
    }

    private fun tcpInterestOps(flow: TcpFlow): Int = synchronized(flow.lock) {
        when (flow.proxyState) {
            TcpProxyState.CONNECTING -> SelectionKey.OP_CONNECT
            TcpProxyState.SYN_ACK_SENT -> 0
            TcpProxyState.ESTABLISHED -> {
                val read = if (flow.outstandingInboundBytes < MAXIMUM_UNACKNOWLEDGED_INBOUND_BYTES) {
                    SelectionKey.OP_READ
                } else {
                    0
                }
                val write = if (flow.pendingWrites.isNotEmpty()) SelectionKey.OP_WRITE else 0
                read or write
            }

            TcpProxyState.REMOTE_FIN_SENT -> if (flow.pendingWrites.isNotEmpty()) SelectionKey.OP_WRITE else 0
            TcpProxyState.CLOSED -> 0
        }
    }

    private fun udpInterestOps(flow: UdpFlow): Int = synchronized(flow.lock) {
        SelectionKey.OP_READ or if (flow.pendingWrites.isNotEmpty()) SelectionKey.OP_WRITE else 0
    }

    private fun evictIdleFlows(runtime: RuntimeState) {
        val now = clock.nowMillis()
        runtime.tcpFlows.values.forEach { flow ->
            if (now - flow.lastSeenAtMillis >= tcpIdleTimeoutMillis) {
                sendTcpReset(runtime, flow)
                closeTcpFlow(runtime, flow)
            }
        }
        runtime.udpFlows.values.forEach { flow ->
            if (now - flow.lastSeenAtMillis >= udpIdleTimeoutMillis) closeUdpFlow(runtime, flow)
        }
    }

    private fun closeTcpFlow(runtime: RuntimeState, flow: TcpFlow) {
        if (!flow.closed.compareAndSet(false, true)) return
        synchronized(flow.lock) {
            flow.proxyState = TcpProxyState.CLOSED
            flow.pendingWrites.clear()
            flow.pendingClientWrites.clear()
            flow.queuedBytes = 0
            flow.queuedClientBytes = 0
        }
        runCatching { flow.tlsFlow?.close() }
        runtime.tcpFlows.remove(flow.key, flow)
        runCatching { flow.channel.close() }
        runtime.capacity.release()
        runtime.metrics.closedFlows.incrementAndGet()
        runtime.selector.wakeup()
    }

    private fun closeUdpFlow(runtime: RuntimeState, flow: UdpFlow) {
        if (!flow.closed.compareAndSet(false, true)) return
        synchronized(flow.lock) {
            flow.pendingWrites.clear()
            flow.queuedBytes = 0
        }
        runtime.udpFlows.remove(flow.key, flow)
        runCatching { flow.channel.close() }
        runtime.capacity.release()
        runtime.metrics.closedFlows.incrementAndGet()
        runtime.selector.wakeup()
    }

    private fun closeRuntime(runtime: RuntimeState, ownerRequested: Boolean, detail: String) {
        if (ownerRequested) runtime.ownerRequestedStop.set(true)
        if (!runtime.running.compareAndSet(true, false)) return
        runtime.tcpFlows.values.toList().forEach { closeTcpFlow(runtime, it) }
        runtime.udpFlows.values.toList().forEach { closeUdpFlow(runtime, it) }
        runCatching { runtime.tlsInspectionSession?.stop() }
        runCatching { runtime.input.close() }
        runCatching { runtime.output.close() }
        runCatching { runtime.selector.wakeup() }
        runCatching { runtime.selector.close() }
        latestMetrics = runtime.snapshotMetrics()
        // Protocol evidence is session-memory only. Do not leave even its
        // metadata snapshot available after the user stops the local VPN.
        runtime.protocolEvidence.clear()
        latestProtocolEvidence = ProtocolEvidenceSnapshot()
        runtime.payloadInspection.stopAndClear()
        latestPayloadInspection = PayloadInspectionSnapshot()
        synchronized(stateLock) {
            if (activeState === runtime) activeState = null
        }
        if (!runtime.ownerRequestedStop.get() && runtime.stopCallbackSent.compareAndSet(false, true)) {
            runCatching { runtime.listener.onDataPlaneStopped(detail) }
        }
    }

    private sealed interface ForwardingAttempt {
        data class Accepted(val detail: String) : ForwardingAttempt

        data class Rejected(val detail: String) : ForwardingAttempt
    }

    private sealed interface SelectorRegistration {
        data class Tcp(val flow: TcpFlow) : SelectorRegistration

        data class Udp(val flow: UdpFlow) : SelectorRegistration
    }

    private enum class TcpProxyState {
        CONNECTING,
        SYN_ACK_SENT,
        ESTABLISHED,
        REMOTE_FIN_SENT,
        CLOSED,
    }

    private data class TcpInboundResult(
        val sendAck: Boolean = false,
        val sendReset: Boolean = false,
        val updateInterest: Boolean = false,
        val shutdownAfterWrites: Boolean = false,
        val rejection: String? = null,
    )

    private data class TransportFlowKey(
        val version: IpVersion,
        val clientAddress: String,
        val clientPort: Int,
        val remoteAddress: String,
        val remotePort: Int,
    ) {
        companion object {
            fun from(packet: TunIpPacket, clientPort: Int, remotePort: Int): TransportFlowKey = TransportFlowKey(
                version = packet.version,
                clientAddress = packet.source.literalHostAddress(),
                clientPort = clientPort,
                remoteAddress = packet.destination.literalHostAddress(),
                remotePort = remotePort,
            )
        }
    }

    private class TcpFlow(
        val key: TransportFlowKey,
        val channel: SocketChannel,
        val version: IpVersion,
        val clientAddress: InetAddress,
        val remoteAddress: InetAddress,
        val clientPort: Int,
        val remotePort: Int,
        var clientNextSequence: Long,
        val serverInitialSequence: Long,
        val maximumPacketBytes: Int,
        val maximumPayloadBytes: Int,
        val maximumQueuedBytes: Int,
        lastSeenAtMillis: Long,
        val tlsFlow: TlsInspectionFlow? = null,
    ) {
        // Written by the reader/worker threads, but read WITHOUT the flow lock by the
        // selector thread in evictIdleFlows(). Non-volatile it has no visibility
        // guarantee (and a 64-bit write is not required to be atomic), so the sweep can
        // observe a stale timestamp and tear down a connection that is actively in use.
        @Volatile var lastSeenAtMillis: Long = lastSeenAtMillis
        val lock = Any()
        val closed = AtomicBoolean(false)
        val pendingWrites = ArrayDeque<ByteBuffer>()
        val pendingClientWrites = ArrayDeque<ByteBuffer>()
        val remoteReadBuffer: ByteBuffer = ByteBuffer.allocate(maximumPayloadBytes)
        var proxyState: TcpProxyState = TcpProxyState.CONNECTING
        var serverNextSequence: Long = serverInitialSequence
        var clientAcknowledgedServerSequence: Long = serverInitialSequence
        var outstandingInboundBytes: Long = 0
        var queuedBytes: Int = 0
        var queuedClientBytes: Int = 0
        @Volatile var tlsFailure: TlsInspectionRouteFailure? = null
        var clientFinReceived: Boolean = false
        var closeOutputAfterPendingWrites: Boolean = false
        var outputShutdown: Boolean = false
        var clientReset: Boolean = false
        var connectCompletedBeforeRegistration: Boolean = false
    }

    private class UdpFlow(
        val key: TransportFlowKey,
        val channel: DatagramChannel,
        val version: IpVersion,
        val clientAddress: InetAddress,
        val remoteAddress: InetAddress,
        val clientPort: Int,
        val remotePort: Int,
        val maximumPacketBytes: Int,
        val maximumQueuedBytes: Int,
        lastSeenAtMillis: Long,
        var latestReplyContext: TunReplyContext,
    ) {
        // See TcpFlow.lastSeenAtMillis: same unlocked cross-thread read in evictIdleFlows().
        @Volatile var lastSeenAtMillis: Long = lastSeenAtMillis
        val lock = Any()
        val closed = AtomicBoolean(false)
        val pendingWrites = ArrayDeque<ByteBuffer>()
        var queuedBytes: Int = 0
    }

    private class RuntimeState(
        val configuration: TunnelConfiguration,
        val input: InputStream,
        val output: OutputStream,
        val selector: Selector,
        val socketProtector: TunnelSocketProtector,
        val listener: ForwardingDataPlaneListener,
        val appAttributionProvider: FlowAppAttributionProvider,
        val capacity: ForwardingFlowCapacity,
        val maximumQueuedBytesPerFlow: Int,
        val metrics: ForwardingMetricsCounter,
        val protocolEvidence: BoundedProtocolEvidenceCollector,
        val payloadInspection: BoundedPayloadInspectionCollector,
        val tlsInspectionSession: TlsInspectionRouteSession?,
    ) {
        val running = AtomicBoolean(true)
        val ownerRequestedStop = AtomicBoolean(false)
        val stopCallbackSent = AtomicBoolean(false)
        val tunWriteLock = Any()
        val tcpFlows = ConcurrentHashMap<TransportFlowKey, TcpFlow>()
        val udpFlows = ConcurrentHashMap<TransportFlowKey, UdpFlow>()
        val registrations = ConcurrentLinkedQueue<SelectorRegistration>()
        val interestUpdates = ConcurrentLinkedQueue<Any>()
        val udpReceiveBuffer: ByteBuffer = ByteBuffer.allocate(MAXIMUM_UDP_PAYLOAD_BYTES)

        @Volatile
        var readerThread: Thread? = null

        @Volatile
        var selectorThread: Thread? = null

        fun snapshotMetrics(): ForwardingMetrics = metrics.snapshot(
            activeTcpFlows = tcpFlows.size,
            activeUdpFlows = udpFlows.size,
        )
    }

    private class ForwardingMetricsCounter {
        val outboundPackets = AtomicLong(0)
        val inboundPackets = AtomicLong(0)
        val outboundPacketBytes = AtomicLong(0)
        val inboundPacketBytes = AtomicLong(0)
        val upstreamSentBytes = AtomicLong(0)
        val upstreamReceivedBytes = AtomicLong(0)
        val openedTcpFlows = AtomicLong(0)
        val openedUdpFlows = AtomicLong(0)
        val closedFlows = AtomicLong(0)
        val blockedPackets = AtomicLong(0)
        val unsupportedPackets = AtomicLong(0)
        val malformedPackets = AtomicLong(0)
        val transportChecksumMismatches = AtomicLong(0)
        val capacityRejections = AtomicLong(0)
        val queueRejections = AtomicLong(0)
        val packetTooLargeResponses = AtomicLong(0)

        fun snapshot(activeTcpFlows: Int, activeUdpFlows: Int): ForwardingMetrics = ForwardingMetrics(
            activeTcpFlows = activeTcpFlows,
            activeUdpFlows = activeUdpFlows,
            outboundPackets = outboundPackets.get(),
            inboundPackets = inboundPackets.get(),
            outboundPacketBytes = outboundPacketBytes.get(),
            inboundPacketBytes = inboundPacketBytes.get(),
            upstreamSentBytes = upstreamSentBytes.get(),
            upstreamReceivedBytes = upstreamReceivedBytes.get(),
            openedTcpFlows = openedTcpFlows.get(),
            openedUdpFlows = openedUdpFlows.get(),
            closedFlows = closedFlows.get(),
            blockedPackets = blockedPackets.get(),
            unsupportedPackets = unsupportedPackets.get(),
            malformedPackets = malformedPackets.get(),
            transportChecksumMismatches = transportChecksumMismatches.get(),
            capacityRejections = capacityRejections.get(),
            queueRejections = queueRejections.get(),
            packetTooLargeResponses = packetTooLargeResponses.get(),
        )
    }

    private fun maximumTcpPayload(version: IpVersion, mtu: Int): Int = (mtu - when (version) {
        IpVersion.IPV4 -> 40
        IpVersion.IPV6 -> 60
    }).coerceAtLeast(1)

    private fun nextInitialTcpSequence(): Long = secureRandom.nextInt().toLong() and 0xffff_ffffL

    private fun incrementSequence(value: Long, increment: Int): Long = (value + increment) and 0xffff_ffffL

    private fun sequenceDistance(from: Long, to: Long): Long = (to - from) and 0xffff_ffffL

    private companion object {
        const val TLS_PORT = 443
        const val MINIMUM_SUPPORTED_MTU = 1_280
        const val DEFAULT_MAXIMUM_FLOWS = 256
        const val DEFAULT_MAXIMUM_QUEUED_BYTES_PER_FLOW = 256 * 1_024
        const val DEFAULT_TCP_IDLE_TIMEOUT_MILLIS = 2 * 60 * 1_000L
        const val DEFAULT_UDP_IDLE_TIMEOUT_MILLIS = 60 * 1_000L
        const val SELECTOR_WAIT_MILLIS = 250L
        const val MAXIMUM_UDP_PAYLOAD_BYTES = 65_535
        const val MAXIMUM_UNACKNOWLEDGED_INBOUND_BYTES = 64 * 1_024L
        val secureRandom = SecureRandom()
    }
}

/** Internal service bridge; third-party data planes retain their own attribution contract. */
internal fun ForwardingDataPlane.installBuiltInAppAttributionProvider(provider: FlowAppAttributionProvider) {
    (this as? PureKotlinForwardingDataPlane)?.installAppAttributionProvider(provider)
}
