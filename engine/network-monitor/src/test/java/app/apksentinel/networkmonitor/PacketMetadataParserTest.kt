package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketMetadataParserTest {
    @Test
    fun parsesIpv4TcpHeadersWithoutReturningPayload() {
        val packet = ByteArray(40)
        packet[0] = 0x45
        write16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 6
        packet[12] = 192.toByte()
        packet[13] = 0
        packet[14] = 2
        packet[15] = 5
        packet[16] = 198.toByte()
        packet[17] = 51
        packet[18] = 100
        packet[19] = 10
        write16(packet, 20, 51_234)
        write16(packet, 22, 443)
        packet[32] = 0x50

        val metadata = (PacketMetadataParser(DnsNameHandling.HashPerSession("test-session"))
            .parse(packet) as PacketParseResult.Parsed).metadata

        assertEquals(IpVersion.IPV4, metadata.ipVersion)
        assertEquals(TransportProtocol.TCP, metadata.transportProtocol)
        assertEquals("192.0.2.5", metadata.source.address)
        assertEquals("198.51.100.10", metadata.destination.address)
        assertEquals(51_234, metadata.source.port)
        assertEquals(443, metadata.destination.port)
        assertNull(metadata.dns)
    }

    @Test
    fun parsesIpv6UdpDnsWithHashedNameByDefault() {
        val dns = dnsQuery("Example.COM")
        val udpLength = 8 + dns.size
        val packet = ByteArray(40 + udpLength)
        packet[0] = 0x60
        write16(packet, 4, udpLength)
        packet[6] = 17
        packet[7] = 64
        packet[8] = 0x20
        packet[9] = 0x01
        packet[10] = 0x0d
        packet[11] = 0xb8.toByte()
        packet[23] = 1
        packet[24] = 0x20
        packet[25] = 0x01
        packet[26] = 0x0d
        packet[27] = 0xb8.toByte()
        packet[39] = 0x35
        write16(packet, 40, 43_210)
        write16(packet, 42, 53)
        write16(packet, 44, udpLength)
        dns.copyInto(packet, destinationOffset = 48)

        val metadata = (PacketMetadataParser(DnsNameHandling.HashPerSession("deterministic-salt"))
            .parse(packet) as PacketParseResult.Parsed).metadata

        assertEquals(IpVersion.IPV6, metadata.ipVersion)
        assertEquals(TransportProtocol.UDP, metadata.transportProtocol)
        assertEquals(53, metadata.destination.port)
        val dnsMetadata = requireNotNull(metadata.dns)
        assertEquals(DnsParseStatus.PARSED, dnsMetadata.status)
        val name = dnsMetadata.questionName as SafeDnsName.Hashed
        assertEquals(2, name.labelCount)
        assertFalse(name.sha256Prefix.contains("example", ignoreCase = true))
    }

    @Test
    fun keepsNonInitialIpv6FragmentsMetadataOnly() {
        val packet = ByteArray(40 + 8 + 8)
        packet[0] = 0x60
        write16(packet, 4, 16)
        packet[6] = 44 // Fragment extension header.
        packet[40] = 17 // UDP follows the fragment header.
        packet[43] = 8 // Fragment offset = 1; ports must not be interpreted.
        write16(packet, 48, 12_345)
        write16(packet, 50, 53)

        val metadata = (PacketMetadataParser(DnsNameHandling.HashPerSession("test"))
            .parse(packet) as PacketParseResult.Parsed).metadata

        assertEquals(TransportProtocol.UDP, metadata.transportProtocol)
        assertNull(metadata.source.port)
        assertNull(metadata.destination.port)
        assertTrue(PacketParserNote.NON_INITIAL_FRAGMENT in metadata.notes)
    }

    @Test
    fun rejectsTruncatedIpHeaderInsteadOfReadingPastInput() {
        val result = PacketMetadataParser(DnsNameHandling.HashPerSession("test")).parse(byteArrayOf(0x45))

        assertTrue(result is PacketParseResult.Malformed)
    }

    @Test
    fun readsIpv4AnswerAddressAndTtlFromADnsResponse() {
        val dns = dnsResponse("example.com", type = 1, rdata = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34), ttl = 300)
        val metadata = (PacketMetadataParser(DnsNameHandling.HashPerSession("t"))
            .parse(ipv4UdpPacket(dns)) as PacketParseResult.Parsed).metadata

        val answers = requireNotNull(metadata.dns).answers
        assertEquals(1, answers.size)
        assertEquals("93.184.216.34", answers[0].address)
        assertEquals(300L, answers[0].ttlSeconds)
        assertFalse(answers[0].isIpv6)
    }

    @Test
    fun readsIpv6AnswerFromADnsResponse() {
        val rdata = ByteArray(16)
        rdata[0] = 0x20; rdata[1] = 0x01; rdata[2] = 0x0d; rdata[3] = 0xb8.toByte(); rdata[15] = 1
        val dns = dnsResponse("example.com", type = 28, rdata = rdata, ttl = 60)
        val metadata = (PacketMetadataParser(DnsNameHandling.HashPerSession("t"))
            .parse(ipv4UdpPacket(dns)) as PacketParseResult.Parsed).metadata

        val answers = requireNotNull(metadata.dns).answers
        assertEquals(1, answers.size)
        assertTrue(answers[0].isIpv6)
        assertEquals("2001:db8:0:0:0:0:0:1", answers[0].address)
    }

    @Test
    fun aQueryContributesNoAnswerBinding() {
        val metadata = (PacketMetadataParser(DnsNameHandling.HashPerSession("t"))
            .parse(ipv4UdpPacket(dnsQuery("example.com"))) as PacketParseResult.Parsed).metadata

        assertTrue(requireNotNull(metadata.dns).answers.isEmpty())
    }

    @Test
    fun aDishonestAnswerCountCannotReadPastTheMessage() {
        // Claims 40 answers but carries one truncated record. The parser must keep what it
        // could read safely and stop, rather than throwing or walking off the buffer.
        val dns = dnsResponse("example.com", type = 1, rdata = byteArrayOf(1, 2, 3, 4), ttl = 10)
        write16(dns, 6, 40)
        val truncated = dns.copyOf(dns.size - 2)
        val result = PacketMetadataParser(DnsNameHandling.HashPerSession("t")).parse(ipv4UdpPacket(truncated))

        val answers = ((result as PacketParseResult.Parsed).metadata.dns)?.answers.orEmpty()
        assertTrue(answers.isEmpty())
    }

    /** Wraps a DNS payload in a minimal IPv4/UDP packet destined for port 53. */
    private fun ipv4UdpPacket(dns: ByteArray): ByteArray {
        val packet = ByteArray(20 + 8 + dns.size)
        packet[0] = 0x45
        write16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17
        packet[12] = 192.toByte(); packet[13] = 0; packet[14] = 2; packet[15] = 5
        packet[16] = 198.toByte(); packet[17] = 51; packet[18] = 100; packet[19] = 10
        write16(packet, 20, 40_000)
        write16(packet, 22, 53)
        write16(packet, 24, 8 + dns.size)
        dns.copyInto(packet, destinationOffset = 28)
        return packet
    }

    /** A response whose single answer uses a compression pointer back to the question name. */
    private fun dnsResponse(name: String, type: Int, rdata: ByteArray, ttl: Long): ByteArray {
        val labels = (
            name.split('.').flatMap { label -> listOf(label.length.toByte()) + label.encodeToByteArray().toList() } +
                listOf(0.toByte())
            ).toByteArray()
        val questionEnd = 12 + labels.size + 4
        val result = ByteArray(questionEnd + 2 + 10 + rdata.size)
        write16(result, 0, 0x1234)
        write16(result, 2, 0x8180)
        write16(result, 4, 1)
        write16(result, 6, 1)
        labels.copyInto(result, destinationOffset = 12)
        write16(result, 12 + labels.size, type)
        write16(result, 12 + labels.size + 2, 1)
        write16(result, questionEnd, 0xC00C)
        write16(result, questionEnd + 2, type)
        write16(result, questionEnd + 4, 1)
        write16(result, questionEnd + 6, (ttl ushr 16).toInt())
        write16(result, questionEnd + 8, (ttl and 0xFFFF).toInt())
        write16(result, questionEnd + 10, rdata.size)
        rdata.copyInto(result, destinationOffset = questionEnd + 12)
        return result
    }

    private fun dnsQuery(name: String): ByteArray {
        val labels = name.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.encodeToByteArray().toList()
        } + listOf(0.toByte())
        val result = ByteArray(12 + labels.size + 4)
        write16(result, 0, 0x1234)
        write16(result, 2, 0x0100)
        write16(result, 4, 1)
        labels.toByteArray().copyInto(result, destinationOffset = 12)
        write16(result, 12 + labels.size, 1)
        write16(result, 12 + labels.size + 2, 1)
        return result
    }

    private fun write16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }
}
