package app.apksentinel.networkmonitor

import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * Minimal, deliberately bounded IP codec used only at the TUN boundary.
 *
 * It supports unfragmented IPv4 and IPv6 TCP/UDP packets. It does not try to
 * reassemble fragments, interpret IPv6 extension chains, retain payloads, or
 * bypass kernel protocol validation. Unsupported packets keep only a small
 * quote so the forwarder can return a visible ICMP error when possible.
 */
internal object TunPacketCodec {
    const val TCP_FLAG_FIN = 0x01
    const val TCP_FLAG_SYN = 0x02
    const val TCP_FLAG_RST = 0x04
    const val TCP_FLAG_PSH = 0x08
    const val TCP_FLAG_ACK = 0x10

    private const val IPV4_HEADER_BYTES = 20
    private const val IPV6_HEADER_BYTES = 40
    private const val TCP_HEADER_BYTES = 20
    private const val UDP_HEADER_BYTES = 8
    private const val ICMP_HEADER_BYTES = 8
    private const val IPV4_PROTOCOL_ICMP = 1
    private const val IPV6_PROTOCOL_ICMP = 58
    private const val PROTOCOL_TCP = 6
    private const val PROTOCOL_UDP = 17
    private const val MAX_ICMP_QUOTE_BYTES = 48
    private const val IPV4_FRAGMENT_MASK = 0x3fff
    private const val IPV4_DONT_FRAGMENT = 0x4000
    private const val DEFAULT_TTL = 64

    private val identification = AtomicInteger(1)

    fun parse(bytes: ByteArray): TunPacketParseResult {
        if (bytes.isEmpty()) return TunPacketParseResult.Malformed("TUN packet is empty.")
        return when (u8(bytes, 0) ushr 4) {
            4 -> parseIpv4(bytes)
            6 -> parseIpv6(bytes)
            else -> TunPacketParseResult.Unsupported(null, "Packet is neither IPv4 nor IPv6.")
        }
    }

    fun tcpPacket(
        version: IpVersion,
        source: InetAddress,
        destination: InetAddress,
        sourcePort: Int,
        destinationPort: Int,
        sequence: Long,
        acknowledgement: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
        maximumPacketBytes: Int,
    ): ByteArray {
        require(sourcePort in 0..65_535 && destinationPort in 0..65_535) { "TCP ports are invalid." }
        require(payload.size <= maximumPacketBytes) { "TCP payload exceeds the configured TUN packet bound." }
        val transportBytes = TCP_HEADER_BYTES + payload.size
        return when (version) {
            IpVersion.IPV4 -> {
                require(source.address.size == 4 && destination.address.size == 4) { "IPv4 packet requires IPv4 addresses." }
                val totalBytes = IPV4_HEADER_BYTES + transportBytes
                require(totalBytes <= maximumPacketBytes) { "TCP packet exceeds the configured TUN MTU." }
                val packet = ByteArray(totalBytes)
                writeIpv4Header(packet, source, destination, PROTOCOL_TCP, transportBytes)
                writeTcpHeader(
                    packet = packet,
                    offset = IPV4_HEADER_BYTES,
                    sourcePort = sourcePort,
                    destinationPort = destinationPort,
                    sequence = sequence,
                    acknowledgement = acknowledgement,
                    flags = flags,
                    payload = payload,
                )
                write16(packet, IPV4_HEADER_BYTES + 16, transportChecksum(packet, IPV4_HEADER_BYTES, transportBytes, source, destination, PROTOCOL_TCP))
                packet
            }

            IpVersion.IPV6 -> {
                require(source.address.size == 16 && destination.address.size == 16) { "IPv6 packet requires IPv6 addresses." }
                val totalBytes = IPV6_HEADER_BYTES + transportBytes
                require(totalBytes <= maximumPacketBytes) { "TCP packet exceeds the configured TUN MTU." }
                val packet = ByteArray(totalBytes)
                writeIpv6Header(packet, source, destination, PROTOCOL_TCP, transportBytes)
                writeTcpHeader(
                    packet = packet,
                    offset = IPV6_HEADER_BYTES,
                    sourcePort = sourcePort,
                    destinationPort = destinationPort,
                    sequence = sequence,
                    acknowledgement = acknowledgement,
                    flags = flags,
                    payload = payload,
                )
                write16(packet, IPV6_HEADER_BYTES + 16, transportChecksum(packet, IPV6_HEADER_BYTES, transportBytes, source, destination, PROTOCOL_TCP))
                packet
            }
        }
    }

    fun udpPacket(
        version: IpVersion,
        source: InetAddress,
        destination: InetAddress,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
        maximumPacketBytes: Int,
    ): ByteArray {
        require(sourcePort in 0..65_535 && destinationPort in 0..65_535) { "UDP ports are invalid." }
        val transportBytes = UDP_HEADER_BYTES + payload.size
        return when (version) {
            IpVersion.IPV4 -> {
                require(source.address.size == 4 && destination.address.size == 4) { "IPv4 packet requires IPv4 addresses." }
                val totalBytes = IPV4_HEADER_BYTES + transportBytes
                require(totalBytes <= maximumPacketBytes) { "UDP packet exceeds the configured TUN MTU." }
                val packet = ByteArray(totalBytes)
                writeIpv4Header(packet, source, destination, PROTOCOL_UDP, transportBytes)
                writeUdpHeader(packet, IPV4_HEADER_BYTES, sourcePort, destinationPort, payload)
                val checksum = transportChecksum(packet, IPV4_HEADER_BYTES, transportBytes, source, destination, PROTOCOL_UDP)
                write16(packet, IPV4_HEADER_BYTES + 6, if (checksum == 0) 0xffff else checksum)
                packet
            }

            IpVersion.IPV6 -> {
                require(source.address.size == 16 && destination.address.size == 16) { "IPv6 packet requires IPv6 addresses." }
                val totalBytes = IPV6_HEADER_BYTES + transportBytes
                require(totalBytes <= maximumPacketBytes) { "UDP packet exceeds the configured TUN MTU." }
                val packet = ByteArray(totalBytes)
                writeIpv6Header(packet, source, destination, PROTOCOL_UDP, transportBytes)
                writeUdpHeader(packet, IPV6_HEADER_BYTES, sourcePort, destinationPort, payload)
                val checksum = transportChecksum(packet, IPV6_HEADER_BYTES, transportBytes, source, destination, PROTOCOL_UDP)
                write16(packet, IPV6_HEADER_BYTES + 6, if (checksum == 0) 0xffff else checksum)
                packet
            }
        }
    }

    /** A synthetic reset tells the app a TCP flow was rejected; it never impersonates a remote response body. */
    fun tcpResetFor(packet: TunIpPacket, maximumPacketBytes: Int): ByteArray? {
        val tcp = packet.tcp ?: return null
        val acknowledgement = if ((tcp.flags and TCP_FLAG_ACK) != 0) 0L else tcp.nextSequence()
        val sequence = if ((tcp.flags and TCP_FLAG_ACK) != 0) tcp.acknowledgement else 0L
        val flags = if ((tcp.flags and TCP_FLAG_ACK) != 0) TCP_FLAG_RST else TCP_FLAG_RST or TCP_FLAG_ACK
        return tcpPacket(
            version = packet.version,
            source = packet.destination,
            destination = packet.source,
            sourcePort = tcp.destinationPort,
            destinationPort = tcp.sourcePort,
            sequence = sequence,
            acknowledgement = acknowledgement,
            flags = flags,
            maximumPacketBytes = maximumPacketBytes,
        )
    }

    /**
     * Sends an administratively-prohibited or protocol-unreachable ICMP error
     * back through the TUN. The quoted bytes are capped at one IP header plus
     * eight transport bytes and are never persisted.
     */
    fun icmpErrorFor(
        context: TunReplyContext,
        reason: IcmpErrorReason,
        maximumPacketBytes: Int,
    ): ByteArray? = when (context.version) {
        IpVersion.IPV4 -> ipv4IcmpError(context, reason, maximumPacketBytes)
        IpVersion.IPV6 -> ipv6IcmpError(context, reason, maximumPacketBytes)
    }

    fun verifyIpv4HeaderChecksum(packet: ByteArray): Boolean {
        if (packet.size < IPV4_HEADER_BYTES || (u8(packet, 0) ushr 4) != 4) return false
        val headerBytes = (u8(packet, 0) and 0x0f) * 4
        return headerBytes >= IPV4_HEADER_BYTES && headerBytes <= packet.size && checksum(packet, 0, headerBytes) == 0
    }

    fun verifyTransportChecksum(packet: ByteArray): Boolean {
        val parsed = parse(packet) as? TunPacketParseResult.Parsed ?: return false
        val protocol = when {
            parsed.packet.tcp != null -> PROTOCOL_TCP
            parsed.packet.udp != null -> PROTOCOL_UDP
            else -> return false
        }
        val headerBytes = if (parsed.packet.version == IpVersion.IPV4) {
            (u8(packet, 0) and 0x0f) * 4
        } else {
            IPV6_HEADER_BYTES
        }
        return transportChecksum(packet, headerBytes, packet.size - headerBytes, parsed.packet.source, parsed.packet.destination, protocol) == 0
    }

    private fun parseIpv4(bytes: ByteArray): TunPacketParseResult {
        if (bytes.size < IPV4_HEADER_BYTES) return TunPacketParseResult.Malformed("IPv4 header is truncated.")
        val headerBytes = (u8(bytes, 0) and 0x0f) * 4
        if (headerBytes < IPV4_HEADER_BYTES || headerBytes > bytes.size) {
            return TunPacketParseResult.Malformed("IPv4 header length is invalid.")
        }
        val totalBytes = u16(bytes, 2)
        if (totalBytes < headerBytes || totalBytes > bytes.size) {
            return TunPacketParseResult.Malformed("IPv4 total length is invalid or truncated.")
        }
        val source = InetAddress.getByAddress(bytes.copyOfRange(12, 16))
        val destination = InetAddress.getByAddress(bytes.copyOfRange(16, 20))
        val base = TunIpPacket(
            version = IpVersion.IPV4,
            protocol = u8(bytes, 9),
            source = source,
            destination = destination,
            replyContext = TunReplyContext(
                version = IpVersion.IPV4,
                source = source,
                destination = destination,
                quote = bytes.copyOfRange(0, minOf(totalBytes, headerBytes + 8, MAX_ICMP_QUOTE_BYTES)),
            ),
        )
        if ((u16(bytes, 6) and IPV4_FRAGMENT_MASK) != 0) {
            return TunPacketParseResult.Unsupported(base, "IPv4 fragmentation is not supported by the built-in forwarder.")
        }
        return parseTransport(base, bytes, headerBytes, totalBytes)
    }

    private fun parseIpv6(bytes: ByteArray): TunPacketParseResult {
        if (bytes.size < IPV6_HEADER_BYTES) return TunPacketParseResult.Malformed("IPv6 header is truncated.")
        val payloadBytes = u16(bytes, 4)
        val totalBytes = IPV6_HEADER_BYTES + payloadBytes
        if (totalBytes > bytes.size) return TunPacketParseResult.Malformed("IPv6 payload is truncated.")
        val source = InetAddress.getByAddress(bytes.copyOfRange(8, 24))
        val destination = InetAddress.getByAddress(bytes.copyOfRange(24, 40))
        val base = TunIpPacket(
            version = IpVersion.IPV6,
            protocol = u8(bytes, 6),
            source = source,
            destination = destination,
            replyContext = TunReplyContext(
                version = IpVersion.IPV6,
                source = source,
                destination = destination,
                quote = bytes.copyOfRange(0, minOf(totalBytes, MAX_ICMP_QUOTE_BYTES)),
            ),
        )
        return when (base.protocol) {
            PROTOCOL_TCP,
            PROTOCOL_UDP -> parseTransport(base, bytes, IPV6_HEADER_BYTES, totalBytes)

            else -> TunPacketParseResult.Unsupported(
                base,
                "IPv6 extension headers, fragments, and protocol ${base.protocol} are not supported by the built-in forwarder.",
            )
        }
    }

    private fun parseTransport(
        base: TunIpPacket,
        bytes: ByteArray,
        offset: Int,
        endExclusive: Int,
    ): TunPacketParseResult = when (base.protocol) {
        PROTOCOL_TCP -> parseTcp(base, bytes, offset, endExclusive)
        PROTOCOL_UDP -> parseUdp(base, bytes, offset, endExclusive)
        else -> TunPacketParseResult.Unsupported(base, "IP protocol ${base.protocol} is not supported by the built-in forwarder.")
    }

    private fun parseTcp(
        base: TunIpPacket,
        bytes: ByteArray,
        offset: Int,
        endExclusive: Int,
    ): TunPacketParseResult {
        if (offset + TCP_HEADER_BYTES > endExclusive) {
            return TunPacketParseResult.Malformed("TCP header is truncated.")
        }
        val headerBytes = ((u8(bytes, offset + 12) ushr 4) and 0x0f) * 4
        if (headerBytes < TCP_HEADER_BYTES || offset + headerBytes > endExclusive) {
            return TunPacketParseResult.Malformed("TCP header length is invalid.")
        }
        return TunPacketParseResult.Parsed(
            base.copy(
                tcp = TunTcpSegment(
                    sourcePort = u16(bytes, offset),
                    destinationPort = u16(bytes, offset + 2),
                    sequence = u32(bytes, offset + 4),
                    acknowledgement = u32(bytes, offset + 8),
                    flags = u8(bytes, offset + 13),
                    window = u16(bytes, offset + 14),
                    payload = bytes.copyOfRange(offset + headerBytes, endExclusive),
                ),
            ),
        )
    }

    private fun parseUdp(
        base: TunIpPacket,
        bytes: ByteArray,
        offset: Int,
        endExclusive: Int,
    ): TunPacketParseResult {
        if (offset + UDP_HEADER_BYTES > endExclusive) return TunPacketParseResult.Malformed("UDP header is truncated.")
        val declaredBytes = u16(bytes, offset + 4)
        val actualBytes = endExclusive - offset
        val payloadEnd = when {
            declaredBytes == 0 && base.version == IpVersion.IPV6 -> endExclusive
            declaredBytes < UDP_HEADER_BYTES -> return TunPacketParseResult.Malformed("UDP length is invalid.")
            declaredBytes > actualBytes -> return TunPacketParseResult.Malformed("UDP payload is truncated.")
            else -> offset + declaredBytes
        }
        return TunPacketParseResult.Parsed(
            base.copy(
                udp = TunUdpDatagram(
                    sourcePort = u16(bytes, offset),
                    destinationPort = u16(bytes, offset + 2),
                    payload = bytes.copyOfRange(offset + UDP_HEADER_BYTES, payloadEnd),
                ),
            ),
        )
    }

    private fun writeIpv4Header(
        packet: ByteArray,
        source: InetAddress,
        destination: InetAddress,
        protocol: Int,
        payloadBytes: Int,
    ) {
        packet[0] = 0x45
        write16(packet, 2, IPV4_HEADER_BYTES + payloadBytes)
        write16(packet, 4, identification.getAndIncrement() and 0xffff)
        write16(packet, 6, IPV4_DONT_FRAGMENT)
        packet[8] = DEFAULT_TTL.toByte()
        packet[9] = protocol.toByte()
        source.address.copyInto(packet, destinationOffset = 12)
        destination.address.copyInto(packet, destinationOffset = 16)
        write16(packet, 10, checksum(packet, 0, IPV4_HEADER_BYTES))
    }

    private fun writeIpv6Header(
        packet: ByteArray,
        source: InetAddress,
        destination: InetAddress,
        protocol: Int,
        payloadBytes: Int,
    ) {
        packet[0] = 0x60
        write16(packet, 4, payloadBytes)
        packet[6] = protocol.toByte()
        packet[7] = DEFAULT_TTL.toByte()
        source.address.copyInto(packet, destinationOffset = 8)
        destination.address.copyInto(packet, destinationOffset = 24)
    }

    private fun writeTcpHeader(
        packet: ByteArray,
        offset: Int,
        sourcePort: Int,
        destinationPort: Int,
        sequence: Long,
        acknowledgement: Long,
        flags: Int,
        payload: ByteArray,
    ) {
        write16(packet, offset, sourcePort)
        write16(packet, offset + 2, destinationPort)
        write32(packet, offset + 4, sequence)
        write32(packet, offset + 8, acknowledgement)
        packet[offset + 12] = (5 shl 4).toByte()
        packet[offset + 13] = flags.toByte()
        write16(packet, offset + 14, 65_535)
        payload.copyInto(packet, destinationOffset = offset + TCP_HEADER_BYTES)
    }

    private fun writeUdpHeader(
        packet: ByteArray,
        offset: Int,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
    ) {
        write16(packet, offset, sourcePort)
        write16(packet, offset + 2, destinationPort)
        write16(packet, offset + 4, UDP_HEADER_BYTES + payload.size)
        payload.copyInto(packet, destinationOffset = offset + UDP_HEADER_BYTES)
    }

    private fun ipv4IcmpError(
        context: TunReplyContext,
        reason: IcmpErrorReason,
        maximumPacketBytes: Int,
    ): ByteArray? {
        if (context.source.address.size != 4 || context.destination.address.size != 4) return null
        val icmpPayloadBytes = context.quote.size
        val totalBytes = IPV4_HEADER_BYTES + ICMP_HEADER_BYTES + icmpPayloadBytes
        if (totalBytes > maximumPacketBytes) return null
        val packet = ByteArray(totalBytes)
        writeIpv4Header(packet, context.destination, context.source, IPV4_PROTOCOL_ICMP, ICMP_HEADER_BYTES + icmpPayloadBytes)
        packet[IPV4_HEADER_BYTES] = 3 // Destination unreachable.
        packet[IPV4_HEADER_BYTES + 1] = when (reason) {
            IcmpErrorReason.ADMINISTRATIVELY_PROHIBITED -> 13
            IcmpErrorReason.UNSUPPORTED_PROTOCOL -> 2
            IcmpErrorReason.PACKET_TOO_LARGE -> 4
            IcmpErrorReason.RESOURCE_UNAVAILABLE -> 1
        }.toByte()
        if (reason == IcmpErrorReason.PACKET_TOO_LARGE) write16(packet, IPV4_HEADER_BYTES + 6, maximumPacketBytes)
        context.quote.copyInto(packet, destinationOffset = IPV4_HEADER_BYTES + ICMP_HEADER_BYTES)
        write16(packet, IPV4_HEADER_BYTES + 2, checksum(packet, IPV4_HEADER_BYTES, ICMP_HEADER_BYTES + icmpPayloadBytes))
        return packet
    }

    private fun ipv6IcmpError(
        context: TunReplyContext,
        reason: IcmpErrorReason,
        maximumPacketBytes: Int,
    ): ByteArray? {
        if (context.source.address.size != 16 || context.destination.address.size != 16) return null
        val icmpPayloadBytes = context.quote.size
        val transportBytes = ICMP_HEADER_BYTES + icmpPayloadBytes
        val totalBytes = IPV6_HEADER_BYTES + transportBytes
        if (totalBytes > maximumPacketBytes) return null
        val packet = ByteArray(totalBytes)
        writeIpv6Header(packet, context.destination, context.source, IPV6_PROTOCOL_ICMP, transportBytes)
        packet[IPV6_HEADER_BYTES] = when (reason) {
            IcmpErrorReason.PACKET_TOO_LARGE -> 2
            else -> 1 // Destination unreachable.
        }.toByte()
        packet[IPV6_HEADER_BYTES + 1] = when (reason) {
            IcmpErrorReason.ADMINISTRATIVELY_PROHIBITED -> 1
            IcmpErrorReason.UNSUPPORTED_PROTOCOL -> 4
            IcmpErrorReason.PACKET_TOO_LARGE -> 0
            IcmpErrorReason.RESOURCE_UNAVAILABLE -> 0
        }.toByte()
        if (reason == IcmpErrorReason.PACKET_TOO_LARGE) write32(packet, IPV6_HEADER_BYTES + 4, maximumPacketBytes.toLong())
        context.quote.copyInto(packet, destinationOffset = IPV6_HEADER_BYTES + ICMP_HEADER_BYTES)
        write16(packet, IPV6_HEADER_BYTES + 2, transportChecksum(packet, IPV6_HEADER_BYTES, transportBytes, context.destination, context.source, IPV6_PROTOCOL_ICMP))
        return packet
    }

    private fun transportChecksum(
        packet: ByteArray,
        transportOffset: Int,
        transportBytes: Int,
        source: InetAddress,
        destination: InetAddress,
        protocol: Int,
    ): Int {
        var sum = 0L
        sum = addBytes(sum, source.address)
        sum = addBytes(sum, destination.address)
        if (source.address.size == 4) {
            sum += protocol.toLong()
            sum += transportBytes.toLong()
        } else {
            sum += (transportBytes.toLong() ushr 16) and 0xffff
            sum += transportBytes.toLong() and 0xffff
            sum += protocol.toLong()
        }
        sum = addBytes(sum, packet, transportOffset, transportBytes)
        return finalizeChecksum(sum)
    }

    private fun checksum(packet: ByteArray, offset: Int, length: Int): Int =
        finalizeChecksum(addBytes(0L, packet, offset, length))

    private fun addBytes(initial: Long, bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): Long {
        var sum = initial
        var cursor = offset
        val end = offset + length
        while (cursor + 1 < end) {
            sum += ((u8(bytes, cursor) shl 8) or u8(bytes, cursor + 1)).toLong()
            cursor += 2
        }
        if (cursor < end) sum += (u8(bytes, cursor) shl 8).toLong()
        return sum
    }

    private fun finalizeChecksum(initial: Long): Int {
        var sum = initial
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return (sum.inv() and 0xffff).toInt()
    }

    private fun u8(source: ByteArray, offset: Int): Int = source[offset].toInt() and 0xff

    private fun u16(source: ByteArray, offset: Int): Int = (u8(source, offset) shl 8) or u8(source, offset + 1)

    private fun u32(source: ByteArray, offset: Int): Long =
        ((u8(source, offset).toLong() shl 24) or
            (u8(source, offset + 1).toLong() shl 16) or
            (u8(source, offset + 2).toLong() shl 8) or
            u8(source, offset + 3).toLong()) and 0xffff_ffffL

    private fun write16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private fun write32(target: ByteArray, offset: Int, value: Long) {
        target[offset] = (value ushr 24).toByte()
        target[offset + 1] = (value ushr 16).toByte()
        target[offset + 2] = (value ushr 8).toByte()
        target[offset + 3] = value.toByte()
    }
}

internal data class TunIpPacket(
    val version: IpVersion,
    val protocol: Int,
    val source: InetAddress,
    val destination: InetAddress,
    val replyContext: TunReplyContext,
    val tcp: TunTcpSegment? = null,
    val udp: TunUdpDatagram? = null,
)

/** Minimal, bounded information required to report a local IP error. */
internal data class TunReplyContext(
    val version: IpVersion,
    val source: InetAddress,
    val destination: InetAddress,
    val quote: ByteArray,
)

internal data class TunTcpSegment(
    val sourcePort: Int,
    val destinationPort: Int,
    val sequence: Long,
    val acknowledgement: Long,
    val flags: Int,
    val window: Int,
    val payload: ByteArray,
) {
    fun nextSequence(): Long {
        val controlBytes =
            (if ((flags and TunPacketCodec.TCP_FLAG_SYN) != 0) 1 else 0) +
                (if ((flags and TunPacketCodec.TCP_FLAG_FIN) != 0) 1 else 0)
        return (sequence + payload.size + controlBytes) and 0xffff_ffffL
    }
}

internal data class TunUdpDatagram(
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
)

internal sealed interface TunPacketParseResult {
    data class Parsed(val packet: TunIpPacket) : TunPacketParseResult

    data class Unsupported(val packet: TunIpPacket?, val reason: String) : TunPacketParseResult

    data class Malformed(val reason: String) : TunPacketParseResult
}

internal enum class IcmpErrorReason {
    ADMINISTRATIVELY_PROHIBITED,
    UNSUPPORTED_PROTOCOL,
    PACKET_TOO_LARGE,
    RESOURCE_UNAVAILABLE,
}
