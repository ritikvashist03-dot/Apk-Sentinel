package app.apksentinel.networkmonitor

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunPacketCodecTest {
    @Test
    fun ipv4TcpPacketRoundTripsWithValidChecksums() {
        val client = InetAddress.getByName("10.77.0.2")
        val remote = InetAddress.getByName("203.0.113.8")
        val packet = TunPacketCodec.tcpPacket(
            version = IpVersion.IPV4,
            source = client,
            destination = remote,
            sourcePort = 43_210,
            destinationPort = 443,
            sequence = 0x1020_3040L,
            acknowledgement = 0,
            flags = TunPacketCodec.TCP_FLAG_SYN,
            maximumPacketBytes = 1_500,
        )

        val parsed = (TunPacketCodec.parse(packet) as TunPacketParseResult.Parsed).packet
        val tcp = requireNotNull(parsed.tcp)
        assertEquals(IpVersion.IPV4, parsed.version)
        assertEquals("10.77.0.2", parsed.source.hostAddress)
        assertEquals("203.0.113.8", parsed.destination.hostAddress)
        assertEquals(43_210, tcp.sourcePort)
        assertEquals(443, tcp.destinationPort)
        assertEquals(0x1020_3040L, tcp.sequence)
        assertTrue(tcp.flags and TunPacketCodec.TCP_FLAG_SYN != 0)
        assertTrue(TunPacketCodec.verifyIpv4HeaderChecksum(packet))
        assertTrue(TunPacketCodec.verifyTransportChecksum(packet))
    }

    @Test
    fun aCorruptedIpv4HeaderFailsVerificationSoTheDataPlaneCanDropIt() {
        val packet = TunPacketCodec.tcpPacket(
            version = IpVersion.IPV4,
            source = InetAddress.getByName("10.77.0.2"),
            destination = InetAddress.getByName("203.0.113.8"),
            sourcePort = 43_210,
            destinationPort = 443,
            sequence = 1L,
            acknowledgement = 0,
            flags = TunPacketCodec.TCP_FLAG_SYN,
            maximumPacketBytes = 1_500,
        )
        assertTrue(TunPacketCodec.verifyIpv4HeaderChecksum(packet))

        // Flip a bit in the destination address, inside the checksummed header. The forwarding
        // plane reads addresses and ports out of this header to make firewall and attribution
        // decisions, so a header that does not verify must not be forwarded.
        val corrupted = packet.copyOf()
        corrupted[16] = (corrupted[16].toInt() xor 0x01).toByte()

        assertFalse(TunPacketCodec.verifyIpv4HeaderChecksum(corrupted))
    }

    @Test
    fun aLegalZeroChecksumUdpPacketKeepsAValidIpv4Header() {
        // A zero UDP checksum is legal in IPv4 and simply means "not computed". The transport
        // checksum is deliberately NOT a forwarding gate for exactly this reason - enforcing
        // it would discard ordinary traffic, DNS above all. The IPv4 header checksum, which
        // IS enforced, must stay valid regardless.
        val packet = TunPacketCodec.udpPacket(
            version = IpVersion.IPV4,
            source = InetAddress.getByName("10.77.0.2"),
            destination = InetAddress.getByName("203.0.113.53"),
            sourcePort = 51_000,
            destinationPort = 53,
            payload = byteArrayOf(0x12, 0x34, 0x01, 0x00),
            maximumPacketBytes = 1_500,
        )
        val headerBytes = (packet[0].toInt() and 0x0f) * 4
        val zeroed = packet.copyOf()
        zeroed[headerBytes + 6] = 0
        zeroed[headerBytes + 7] = 0

        assertTrue(
            "Zeroing the UDP checksum must not disturb the IPv4 header checksum",
            TunPacketCodec.verifyIpv4HeaderChecksum(zeroed),
        )
    }

    @Test
    fun ipv6UdpPacketRoundTripsWithValidChecksum() {
        val client = InetAddress.getByName("fd77:6170:6b73:656e::2")
        val remote = InetAddress.getByName("2001:db8::53")
        val payload = byteArrayOf(0x12, 0x34, 0x01, 0x00)
        val packet = TunPacketCodec.udpPacket(
            version = IpVersion.IPV6,
            source = client,
            destination = remote,
            sourcePort = 52_000,
            destinationPort = 53,
            payload = payload,
            maximumPacketBytes = 1_500,
        )

        val parsed = (TunPacketCodec.parse(packet) as TunPacketParseResult.Parsed).packet
        val udp = requireNotNull(parsed.udp)
        assertEquals(IpVersion.IPV6, parsed.version)
        assertEquals(53, udp.destinationPort)
        assertTrue(udp.payload.contentEquals(payload))
        assertTrue(TunPacketCodec.verifyTransportChecksum(packet))
    }

    @Test
    fun tcpResetAcknowledgesUnacknowledgedSyn() {
        val client = InetAddress.getByName("10.77.0.2")
        val remote = InetAddress.getByName("198.51.100.9")
        val syn = TunPacketCodec.tcpPacket(
            version = IpVersion.IPV4,
            source = client,
            destination = remote,
            sourcePort = 40_000,
            destinationPort = 443,
            sequence = 99,
            acknowledgement = 0,
            flags = TunPacketCodec.TCP_FLAG_SYN,
            maximumPacketBytes = 1_500,
        )
        val request = (TunPacketCodec.parse(syn) as TunPacketParseResult.Parsed).packet
        val reset = requireNotNull(TunPacketCodec.tcpResetFor(request, maximumPacketBytes = 1_500))
        val response = (TunPacketCodec.parse(reset) as TunPacketParseResult.Parsed).packet
        val tcp = requireNotNull(response.tcp)

        assertEquals(remote.hostAddress, response.source.hostAddress)
        assertEquals(client.hostAddress, response.destination.hostAddress)
        assertEquals(100L, tcp.acknowledgement)
        assertTrue(tcp.flags and TunPacketCodec.TCP_FLAG_RST != 0)
        assertTrue(tcp.flags and TunPacketCodec.TCP_FLAG_ACK != 0)
    }

    @Test
    fun fragmentedIpv4IsExplicitlyUnsupported() {
        val client = InetAddress.getByName("10.77.0.2")
        val remote = InetAddress.getByName("198.51.100.10")
        val packet = TunPacketCodec.udpPacket(
            version = IpVersion.IPV4,
            source = client,
            destination = remote,
            sourcePort = 40_000,
            destinationPort = 53,
            payload = byteArrayOf(1),
            maximumPacketBytes = 1_500,
        )
        packet[6] = (packet[6].toInt() or 0x20).toByte() // More fragments.

        val result = TunPacketCodec.parse(packet)
        assertTrue(result is TunPacketParseResult.Unsupported)
        assertFalse(result is TunPacketParseResult.Malformed)
    }
}
