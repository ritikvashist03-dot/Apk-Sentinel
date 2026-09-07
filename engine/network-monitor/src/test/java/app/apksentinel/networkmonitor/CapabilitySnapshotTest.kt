package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CapabilitySnapshotTest {
    @Test
    fun unavailableForwarderDoesNotClaimTrafficOrFirewallCoverage() {
        val snapshot = capabilitySnapshot(
            configuration = TunnelConfiguration(mode = MonitoringMode.FIREWALL_ENFORCEMENT),
            forwarder = ForwardingDataPlaneCapabilities(
                canForwardIpv4 = false,
                canForwardIpv6 = false,
                canEnforceFirewallRules = false,
                appAttributionAvailability = CapabilityAvailability.UNAVAILABLE,
                detail = "No forwarder installed.",
            ),
            vpnConsentGranted = true,
        )

        assertEquals(
            CapabilityAvailability.UNAVAILABLE,
            snapshot.reportFor(MonitoringCapabilityId.TRAFFIC_FORWARDING)?.availability,
        )
        assertEquals(
            CapabilityAvailability.UNAVAILABLE,
            snapshot.reportFor(MonitoringCapabilityId.FIREWALL_ENFORCEMENT)?.availability,
        )
        assertEquals(
            CapabilityAvailability.UNAVAILABLE,
            snapshot.reportFor(MonitoringCapabilityId.PACKET_PAYLOAD_COLLECTION)?.availability,
        )
        assertEquals(
            CapabilityAvailability.UNAVAILABLE,
            snapshot.reportFor(MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT)?.availability,
        )
        assertEquals(
            CapabilityAvailability.LIMITED,
            snapshot.reportFor(MonitoringCapabilityId.METADATA_CAPTURE_EXPORT)?.availability,
        )
        assertTrue(snapshot.limitations().any { it.code == EngineLimitationCode.PACKET_PAYLOADS_ARE_NOT_COLLECTED })
        assertTrue(snapshot.limitations().any { it.code == EngineLimitationCode.PCAPNG_RAW_PACKET_EXPORT_NOT_AVAILABLE })
        assertTrue(snapshot.limitations().any { it.code == EngineLimitationCode.METADATA_CAPTURE_EXPORT_IS_NOT_PACKET_CAPTURE })
    }

    @Test
    fun limitedForwarderDoesNotClaimCompleteTrafficCoverage() {
        val snapshot = capabilitySnapshot(
            configuration = TunnelConfiguration(mode = MonitoringMode.FIREWALL_ENFORCEMENT),
            forwarder = ForwardingDataPlaneCapabilities(
                canForwardIpv4 = true,
                canForwardIpv6 = true,
                canEnforceFirewallRules = true,
                appAttributionAvailability = CapabilityAvailability.UNAVAILABLE,
                detail = "TCP and UDP only.",
                trafficForwardingAvailability = CapabilityAvailability.LIMITED,
            ),
            vpnConsentGranted = true,
        )

        assertEquals(
            CapabilityAvailability.LIMITED,
            snapshot.reportFor(MonitoringCapabilityId.TRAFFIC_FORWARDING)?.availability,
        )
        assertEquals(
            CapabilityAvailability.LIMITED,
            snapshot.reportFor(MonitoringCapabilityId.FIREWALL_ENFORCEMENT)?.availability,
        )
        assertTrue(
            snapshot.limitations().any {
                it.code == EngineLimitationCode.FORWARDING_DATA_PLANE_LIMITED_PROTOCOL_COVERAGE
            },
        )
    }

    @Test
    fun rawPcapngIsLimitedOnlyWhenForwarderProvidesItsCaptureHook() {
        val snapshot = capabilitySnapshot(
            configuration = TunnelConfiguration(),
            forwarder = PureKotlinForwardingDataPlane().capabilities,
            vpnConsentGranted = true,
        )

        assertEquals(
            CapabilityAvailability.LIMITED,
            snapshot.reportFor(MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT)?.availability,
        )
        assertTrue(snapshot.limitations().any { it.code == EngineLimitationCode.PCAPNG_RAW_PACKET_EXPORT_LIMITED })
    }
}
