package app.apksentinel.networkmonitor

import java.net.InetAddress
import java.net.InetSocketAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppConnectionAttributionTest {
    @Test
    fun outboundAndInboundPacketsUseTheSameLiteralLocalRemoteTuple() {
        val outbound = tcpPacket(
            source = byteArrayOf(10, 0, 0, 2),
            destination = byteArrayOf(1, 1, 1, 1),
            sourcePort = 48_000,
            destinationPort = 443,
        )
        val inbound = tcpPacket(
            source = byteArrayOf(1, 1, 1, 1),
            destination = byteArrayOf(10, 0, 0, 2),
            sourcePort = 443,
            destinationPort = 48_000,
        )

        val outboundFlow = requireNotNull(outbound.toConnectionOwnerFlow(PacketDirection.OUTBOUND))
        val inboundFlow = requireNotNull(inbound.toConnectionOwnerFlow(PacketDirection.INBOUND))

        assertEquals(outboundFlow, inboundFlow)
        assertFalse(outboundFlow.local.isUnresolved)
        assertFalse(outboundFlow.remote.isUnresolved)
        assertEquals("10.0.0.2", outboundFlow.local.address.hostAddress)
        assertEquals("1.1.1.1", outboundFlow.remote.address.hostAddress)
    }

    @Test
    fun knownSinglePackageIsCachedByExactFlow() {
        var ownerCalls = 0
        val provider = CachedFlowAppAttributionProvider(
            ownerLookup = ConnectionOwnerUidLookup {
                ownerCalls += 1
                ConnectionOwnerUidResult.Found(12_345)
            },
            packageLookup = UidPackageLookup { listOf("com.example.browser") },
        )
        val packet = tcpPacket()

        val flow = requireNotNull(packet.toConnectionOwnerFlow(PacketDirection.OUTBOUND))
        val first = provider.attributionFor(flow)
        val second = provider.attributionFor(flow)

        assertEquals(
            AppAttribution.Known("com.example.browser", 12_345, AttributionConfidence.HIGH),
            first,
        )
        assertEquals(first, second)
        assertEquals(1, ownerCalls)
    }

    @Test
    fun sharedUidAndNoOwnerStayExplicitlyUnknown() {
        val packet = tcpPacket()
        val shared = CachedFlowAppAttributionProvider(
            ownerLookup = ConnectionOwnerUidLookup { ConnectionOwnerUidResult.Found(4321) },
            packageLookup = UidPackageLookup { listOf("com.example.one", "com.example.two") },
        ).attributionFor(requireNotNull(packet.toConnectionOwnerFlow(PacketDirection.OUTBOUND)))
        val missing = CachedFlowAppAttributionProvider(
            ownerLookup = ConnectionOwnerUidLookup { ConnectionOwnerUidResult.NoOwner },
            packageLookup = UidPackageLookup { error("No package lookup is valid for no owner") },
        ).attributionFor(requireNotNull(packet.toConnectionOwnerFlow(PacketDirection.OUTBOUND)))
        val unavailable = CachedFlowAppAttributionProvider(
            ownerLookup = ConnectionOwnerUidLookup { ConnectionOwnerUidResult.Unavailable },
            packageLookup = UidPackageLookup { error("No package lookup is valid when the platform is unavailable") },
        ).attributionFor(requireNotNull(packet.toConnectionOwnerFlow(PacketDirection.OUTBOUND)))

        assertEquals(
            AppAttribution.Unknown(AttributionUnavailableReason.SHARED_UID_OR_AMBIGUOUS_OWNER),
            shared,
        )
        assertEquals(
            AppAttribution.Unknown(AttributionUnavailableReason.CONNECTION_OWNER_NOT_FOUND),
            missing,
        )
        assertEquals(
            AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE),
            unavailable,
        )
    }

    @Test
    fun unsupportedTransportNeverCallsPlatformOwnerLookup() {
        var calls = 0
        val provider = CachedFlowAppAttributionProvider(
            ownerLookup = ConnectionOwnerUidLookup {
                calls += 1
                ConnectionOwnerUidResult.Found(12)
            },
            packageLookup = UidPackageLookup { listOf("com.example.never") },
        )
        val icmp = TunIpPacket(
            version = IpVersion.IPV4,
            protocol = 1,
            source = InetAddress.getByAddress(byteArrayOf(10, 0, 0, 2)),
            destination = InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)),
            replyContext = TunReplyContext(
                IpVersion.IPV4,
                InetAddress.getByAddress(byteArrayOf(10, 0, 0, 2)),
                InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)),
                byteArrayOf(),
            ),
        )

        assertTrue(icmp.toConnectionOwnerFlow(PacketDirection.OUTBOUND) == null)
        assertEquals(
            AppAttribution.Unknown(AttributionUnavailableReason.UNSUPPORTED_PROTOCOL),
            provider.attributionFor(
                ConnectionOwnerFlow(
                    TransportProtocol.ICMPV4,
                    InetSocketAddress(InetAddress.getByAddress(byteArrayOf(10, 0, 0, 2)), 0),
                    InetSocketAddress(InetAddress.getByAddress(byteArrayOf(8, 8, 8, 8)), 0),
                ),
            ),
        )
        assertEquals(0, calls)
    }

    @Test
    fun providerAndClockFailuresRemainExplicitUnknownsInsteadOfEscaping() {
        val flow = requireNotNull(tcpPacket().toConnectionOwnerFlow(PacketDirection.OUTBOUND))
        val throwingProvider = FlowAppAttributionProvider { error("provider detail must not escape") }
        assertEquals(
            AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE),
            throwingProvider.attributionForSafely(flow),
        )

        val clockFailure = CachedFlowAppAttributionProvider(
            ownerLookup = ConnectionOwnerUidLookup { error("owner lookup must not run") },
            packageLookup = UidPackageLookup { error("package lookup must not run") },
            nowMillis = { error("clock detail must not escape") },
        ).attributionFor(flow)
        assertEquals(
            AppAttribution.Unknown(AttributionUnavailableReason.PLATFORM_MAPPING_UNAVAILABLE),
            clockFailure,
        )
    }

    @Test
    fun capabilityAdvertisesOnlyLimitedApiBoundAttribution() {
        val snapshot = capabilitySnapshot(
            configuration = TunnelConfiguration(),
            forwarder = PureKotlinForwardingDataPlane().capabilities,
            vpnConsentGranted = true,
        )

        val report = requireNotNull(snapshot.reportFor(MonitoringCapabilityId.APP_ATTRIBUTION))
        assertEquals(CapabilityAvailability.LIMITED, report.availability)
        assertTrue(report.detail.contains("TCP/UDP"))
        assertTrue(report.detail.contains("API 29"))
        assertTrue(report.detail.contains("shared-UID"))
    }

    private fun tcpPacket(
        source: ByteArray = byteArrayOf(10, 0, 0, 2),
        destination: ByteArray = byteArrayOf(1, 1, 1, 1),
        sourcePort: Int = 48_000,
        destinationPort: Int = 443,
    ): TunIpPacket {
        val sourceAddress = InetAddress.getByAddress(source)
        val destinationAddress = InetAddress.getByAddress(destination)
        return TunIpPacket(
            version = IpVersion.IPV4,
            protocol = 6,
            source = sourceAddress,
            destination = destinationAddress,
            replyContext = TunReplyContext(IpVersion.IPV4, sourceAddress, destinationAddress, byteArrayOf()),
            tcp = TunTcpSegment(
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                sequence = 0,
                acknowledgement = 0,
                flags = TunPacketCodec.TCP_FLAG_SYN,
                window = 65_535,
                payload = byteArrayOf(),
            ),
        )
    }
}
