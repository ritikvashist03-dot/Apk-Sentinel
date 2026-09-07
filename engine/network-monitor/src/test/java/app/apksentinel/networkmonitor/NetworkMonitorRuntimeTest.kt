package app.apksentinel.networkmonitor

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import android.os.ParcelFileDescriptor

class NetworkMonitorRuntimeTest {
    @After
    fun resetRuntime() {
        NetworkMonitorRuntime.resetForTests()
        VpnDisclosureAcknowledgementGate.resetForTests()
    }

    @Test
    fun vpnDisclosureIsExactFreshAndOneTimeAtTheServiceBoundary() {
        val now = 1_000_000L
        val acknowledgement = VpnDisclosureAcknowledgement(
            disclosureVersion = VpnDisclosurePolicy.CURRENT_VERSION,
            acknowledgedAtMillis = now,
        )

        assertTrue(VpnDisclosurePolicy.isFreshAndExact(acknowledgement, now + 1_000L))
        assertTrue(VpnDisclosureAcknowledgementGate.consume(acknowledgement, now + 1_000L))
        assertFalse(VpnDisclosureAcknowledgementGate.consume(acknowledgement, now + 2_000L))
        assertFalse(
            VpnDisclosurePolicy.isFreshAndExact(
                acknowledgement.copy(disclosureVersion = "vpn-local-metadata-old"),
                now + 1_000L,
            ),
        )
        assertFalse(
            VpnDisclosurePolicy.isFreshAndExact(
                acknowledgement.copy(acknowledgedAtMillis = now - VpnDisclosurePolicy.MAX_AGE_MILLIS - 1),
                now,
            ),
        )
    }

    @Test
    fun sessionCollectionOptionsAreLockedForAnActiveAttempt() {
        assertTrue(isSessionConfigurationLocked(MonitorLifecycleState.STARTING))
        assertTrue(isSessionConfigurationLocked(MonitorLifecycleState.ACTIVE))
        assertTrue(isSessionConfigurationLocked(MonitorLifecycleState.STOPPING))
        assertFalse(isSessionConfigurationLocked(MonitorLifecycleState.STOPPED))
        assertFalse(isSessionConfigurationLocked(MonitorLifecycleState.CONSENT_REQUIRED))
    }

    @Test
    fun runtimeSurfaceReadsAndClearsBoundedEventsAndMutatesInstalledMemoryRules() {
        val store = BoundedInMemoryNetworkEventStore(capacity = 2)
        val rules = InMemoryFirewallRuleProvider()
        NetworkMonitorRuntime.install(
            NetworkMonitorDependencies(
                eventStore = store,
                firewallRuleProvider = rules,
            ),
        )
        store.append(stateEvent(1L))
        store.append(stateEvent(2L))

        assertEquals(listOf(1L, 2L), NetworkMonitorRuntime.recentEvents().map { it.atMillis })
        assertEquals(2, NetworkMonitorRuntime.clearRecentEvents())
        assertTrue(NetworkMonitorRuntime.recentEvents().isEmpty())
        assertEquals(0L, NetworkMonitorRuntime.forwardingMetrics().outboundPackets)

        val exposedRules = requireNotNull(NetworkMonitorRuntime.inMemoryFirewallRules())
        val rule = FirewallRule(id = "block-tcp", action = FirewallAction.BLOCK)
        exposedRules.upsert(rule)
        assertEquals(listOf("block-tcp"), exposedRules.snapshot().map(FirewallRule::id))
        assertTrue(exposedRules.remove("block-tcp"))
        assertEquals(0, exposedRules.clear())
    }

    @Test
    fun defaultDependenciesExposeAnEmptyMutableInMemoryRuleSet() {
        NetworkMonitorRuntime.resetForTests()

        val rules = requireNotNull(NetworkMonitorRuntime.inMemoryFirewallRules())
        assertTrue(rules.snapshot().isEmpty())
        rules.upsert(FirewallRule(id = "default-rule", action = FirewallAction.BLOCK))

        assertEquals(listOf("default-rule"), rules.snapshot().map(FirewallRule::id))
    }

    @Test
    fun runtimePassesProtocolEvidenceAndFlowSnapshotOnlyWhileSessionIsAttached() {
        val evidence = ProtocolEvidenceSnapshot(
            enabledForSession = true,
            sessionLimitations = emptySet(),
            observations = listOf(
                ProtocolEvidenceObservation(
                    source = ProtocolEvidenceSource.TLS_CLIENT_HELLO_SNI,
                    direction = PacketDirection.OUTBOUND,
                    observedAtMillis = 10L,
                    confidence = ProtocolEvidenceConfidence.HIGH,
                    value = ProtocolEvidenceValue.TlsServerName("api.example.test"),
                    limitations = emptySet(),
                ),
            ),
        )
        val flowRegistry = BoundedFlowRegistry(capacity = 2)
        flowRegistry.observe(
            metadata = PacketMetadata(
                ipVersion = IpVersion.IPV4,
                ipProtocolNumber = 6,
                transportProtocol = TransportProtocol.TCP,
                source = NetworkEndpoint("10.0.0.2", 45_000),
                destination = NetworkEndpoint("203.0.113.7", 443),
                declaredIpPacketBytes = 40,
                capturedPacketBytes = 40,
            ),
            attribution = AppAttribution.Unknown(AttributionUnavailableReason.NOT_ATTEMPTED),
            direction = PacketDirection.OUTBOUND,
            atMillis = 10L,
        )
        val plane = SnapshotDataPlane(evidence)
        NetworkMonitorRuntime.attachSessionResources(
            sessionId = "session",
            eventStore = BoundedInMemoryNetworkEventStore(),
            firewallRuleProvider = InMemoryFirewallRuleProvider(),
            dataPlane = plane,
            flowRegistry = flowRegistry,
        )

        assertEquals(1, NetworkMonitorRuntime.flowRegistrySnapshot().flows.size)
        assertEquals(evidence, NetworkMonitorRuntime.protocolEvidenceSnapshot())

        NetworkMonitorRuntime.detachSessionResources("session", plane)

        assertTrue(NetworkMonitorRuntime.flowRegistrySnapshot().flows.isEmpty())
        assertFalse(NetworkMonitorRuntime.protocolEvidenceSnapshot().enabledForSession)
        assertTrue(NetworkMonitorRuntime.protocolEvidenceSnapshot().observations.isEmpty())
    }

    @Test
    fun detachingSessionClearsRetainedEventEvidenceAndRevealTokens() {
        val store = BoundedInMemoryNetworkEventStore()
        val plane = SnapshotDataPlane(ProtocolEvidenceSnapshot())
        NetworkMonitorRuntime.install(NetworkMonitorDependencies(eventStore = store))
        NetworkMonitorRuntime.attachSessionResources(
            sessionId = "session",
            eventStore = store,
            firewallRuleProvider = InMemoryFirewallRuleProvider(),
            dataPlane = plane,
        )
        store.append(stateEvent(1L))

        assertTrue(NetworkMonitorRuntime.recentEvents().isNotEmpty())
        NetworkMonitorRuntime.detachSessionResources("session", plane)

        assertTrue(NetworkMonitorRuntime.recentEvents().isEmpty())
        assertTrue(NetworkMonitorRuntime.flowRegistrySnapshot().flows.isEmpty())
    }

    private fun stateEvent(atMillis: Long): MonitorStateEvent = MonitorStateEvent(
        sessionId = "session",
        atMillis = atMillis,
        state = MonitorLifecycleState.ACTIVE,
        detail = "test",
    )

    private class SnapshotDataPlane(
        private val snapshot: ProtocolEvidenceSnapshot,
    ) : ForwardingDataPlane {
        override val capabilities = ForwardingDataPlaneCapabilities(
            canForwardIpv4 = true,
            canForwardIpv6 = true,
            canEnforceFirewallRules = false,
            appAttributionAvailability = CapabilityAvailability.UNAVAILABLE,
            detail = "test",
        )

        override fun start(
            tunnel: ParcelFileDescriptor,
            configuration: TunnelConfiguration,
            socketProtector: TunnelSocketProtector,
            listener: ForwardingDataPlaneListener,
        ): ForwardingStartResult = ForwardingStartResult.Rejected("test")

        override fun stop() = Unit

        override fun protocolEvidenceSnapshot(): ProtocolEvidenceSnapshot = snapshot
    }
}
