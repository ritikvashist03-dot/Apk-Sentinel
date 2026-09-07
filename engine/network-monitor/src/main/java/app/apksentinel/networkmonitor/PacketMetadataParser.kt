package app.apksentinel.networkmonitor

import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/**
 * DNS names are never retained in their original form by default. The caller
 * must deliberately opt into [PlaintextAfterExplicitConsent] after its own
 * privacy disclosure; that choice is not made by this module automatically.
 */
sealed interface DnsNameHandling {
    object Omit : DnsNameHandling

    data class HashPerSession(val salt: String) : DnsNameHandling {
        init {
            require(salt.isNotBlank()) { "A per-session DNS hash salt is required." }
        }
    }

    object PlaintextAfterExplicitConsent : DnsNameHandling
}

/**
 * Parses only packet headers and a bounded cleartext DNS question. It never
 * returns a raw packet or transport payload, and it does not decrypt TLS,
 * DNS-over-TLS, DNS-over-HTTPS, QUIC, or IPsec payloads.
 */
class PacketMetadataParser(
    private val dnsNameHandling: DnsNameHandling,
) {
    fun parse(
        packet: ByteArray,
        offset: Int = 0,
        length: Int = packet.size,
    ): PacketParseResult {
        if (offset < 0 || length < 0 || offset > packet.size || length > packet.size - offset) {
            return PacketParseResult.Malformed("Packet offset/length is outside the supplied byte array.")
        }
        if (length == 0) return PacketParseResult.Malformed("Packet is empty.")

        val view = PacketView(packet, offset, offset + length)
        return when (view.u8(offset) ushr 4) {
            4 -> parseIpv4(view)
            6 -> parseIpv6(view)
            else -> PacketParseResult.Ignored("Packet does not start with an IPv4 or IPv6 version header.")
        }
    }

    private fun parseIpv4(view: PacketView): PacketParseResult {
        val start = view.start
        if (!view.has(start, IPV4_MIN_HEADER_BYTES)) {
            return PacketParseResult.Malformed("IPv4 header is shorter than 20 bytes.")
        }

        val headerBytes = (view.u8(start) and 0x0f) * 4
        if (headerBytes < IPV4_MIN_HEADER_BYTES || !view.has(start, headerBytes)) {
            return PacketParseResult.Malformed("IPv4 header length is invalid or truncated.")
        }

        val declaredPacketBytes = view.u16(start + 2)
        if (declaredPacketBytes < headerBytes) {
            return PacketParseResult.Malformed("IPv4 total length is smaller than its header.")
        }

        val expectedEnd = start.toLong() + declaredPacketBytes.toLong()
        val effectiveEnd = minOf(view.end.toLong(), expectedEnd).toInt()
        val notes = linkedSetOf<PacketParserNote>()
        if (view.end.toLong() < expectedEnd) notes += PacketParserNote.CAPTURE_TRUNCATED

        val protocolNumber = view.u8(start + 9)
        val fragmentField = view.u16(start + 6)
        val fragmentOffset = fragmentField and IPV4_FRAGMENT_OFFSET_MASK
        val transportStart = start + headerBytes
        val transport = if (fragmentOffset == 0) {
            parseTransport(view, transportStart, effectiveEnd, protocolNumber)
        } else {
            notes += PacketParserNote.NON_INITIAL_FRAGMENT
            TransportObservation.fromProtocolNumber(protocolNumber)
        }
        notes += transport.notes

        return PacketParseResult.Parsed(
            PacketMetadata(
                ipVersion = IpVersion.IPV4,
                ipProtocolNumber = protocolNumber,
                transportProtocol = transport.protocol,
                source = NetworkEndpoint(addressOf(view.bytes, start + 12, IPV4_ADDRESS_BYTES), transport.sourcePort),
                destination = NetworkEndpoint(addressOf(view.bytes, start + 16, IPV4_ADDRESS_BYTES), transport.destinationPort),
                icmpType = transport.icmpType,
                icmpCode = transport.icmpCode,
                declaredIpPacketBytes = declaredPacketBytes,
                capturedPacketBytes = effectiveEnd - start,
                dns = transport.dns,
                notes = notes,
            ),
        )
    }

    private fun parseIpv6(view: PacketView): PacketParseResult {
        val start = view.start
        if (!view.has(start, IPV6_HEADER_BYTES)) {
            return PacketParseResult.Malformed("IPv6 header is shorter than 40 bytes.")
        }

        val declaredPayloadBytes = view.u16(start + 4)
        val declaredPacketBytes = IPV6_HEADER_BYTES + declaredPayloadBytes
        val expectedEnd = start.toLong() + declaredPacketBytes.toLong()
        val effectiveEnd = minOf(view.end.toLong(), expectedEnd).toInt()
        val notes = linkedSetOf<PacketParserNote>()
        if (view.end.toLong() < expectedEnd) notes += PacketParserNote.CAPTURE_TRUNCATED

        var nextHeader = view.u8(start + 6)
        var cursor = start + IPV6_HEADER_BYTES
        var nonInitialFragment = false
        var extensionCount = 0
        var extensionParsingStopped = false

        while (nextHeader in IPV6_EXTENSION_HEADERS) {
            extensionCount += 1
            if (extensionCount > MAX_IPV6_EXTENSION_HEADERS) {
                notes += PacketParserNote.EXCESSIVE_IPV6_EXTENSION_HEADERS
                extensionParsingStopped = true
                break
            }

            when (nextHeader) {
                IPV6_FRAGMENT_HEADER -> {
                    if (cursor + IPV6_FRAGMENT_HEADER_BYTES > effectiveEnd) {
                        notes += PacketParserNote.TRANSPORT_HEADER_TRUNCATED
                        extensionParsingStopped = true
                        break
                    }
                    val fragmentNextHeader = view.u8(cursor)
                    val fragmentOffset = (view.u16(cursor + 2) ushr 3) and IPV6_FRAGMENT_OFFSET_MASK
                    if (fragmentOffset != 0) {
                        notes += PacketParserNote.NON_INITIAL_FRAGMENT
                        nonInitialFragment = true
                    }
                    nextHeader = fragmentNextHeader
                    cursor += IPV6_FRAGMENT_HEADER_BYTES
                }

                IPV6_AUTHENTICATION_HEADER -> {
                    if (cursor + 2 > effectiveEnd) {
                        notes += PacketParserNote.TRANSPORT_HEADER_TRUNCATED
                        extensionParsingStopped = true
                        break
                    }
                    val headerBytes = (view.u8(cursor + 1) + 2) * 4
                    if (headerBytes < 8 || cursor + headerBytes > effectiveEnd) {
                        notes += PacketParserNote.TRANSPORT_HEADER_TRUNCATED
                        extensionParsingStopped = true
                        break
                    }
                    nextHeader = view.u8(cursor)
                    cursor += headerBytes
                }

                else -> {
                    // Hop-by-hop, routing, and destination options use 8-octet units.
                    if (cursor + 2 > effectiveEnd) {
                        notes += PacketParserNote.TRANSPORT_HEADER_TRUNCATED
                        extensionParsingStopped = true
                        break
                    }
                    val headerBytes = (view.u8(cursor + 1) + 1) * 8
                    if (headerBytes < 8 || cursor + headerBytes > effectiveEnd) {
                        notes += PacketParserNote.TRANSPORT_HEADER_TRUNCATED
                        extensionParsingStopped = true
                        break
                    }
                    nextHeader = view.u8(cursor)
                    cursor += headerBytes
                }
            }
        }

        val transport = when {
            extensionParsingStopped || nonInitialFragment -> TransportObservation.fromProtocolNumber(nextHeader)
            nextHeader == IPV6_ESP_HEADER -> {
                notes += PacketParserNote.ENCRYPTED_OR_OPAQUE_IP_PAYLOAD
                TransportObservation.fromProtocolNumber(nextHeader)
            }

            nextHeader == IPV6_NO_NEXT_HEADER -> TransportObservation.fromProtocolNumber(nextHeader)
            else -> parseTransport(view, cursor, effectiveEnd, nextHeader)
        }
        notes += transport.notes

        return PacketParseResult.Parsed(
            PacketMetadata(
                ipVersion = IpVersion.IPV6,
                ipProtocolNumber = nextHeader,
                transportProtocol = transport.protocol,
                source = NetworkEndpoint(addressOf(view.bytes, start + 8, IPV6_ADDRESS_BYTES), transport.sourcePort),
                destination = NetworkEndpoint(addressOf(view.bytes, start + 24, IPV6_ADDRESS_BYTES), transport.destinationPort),
                icmpType = transport.icmpType,
                icmpCode = transport.icmpCode,
                declaredIpPacketBytes = declaredPacketBytes,
                capturedPacketBytes = effectiveEnd - start,
                dns = transport.dns,
                notes = notes,
            ),
        )
    }

    private fun parseTransport(
        view: PacketView,
        start: Int,
        end: Int,
        protocolNumber: Int,
    ): TransportObservation {
        val protocol = transportProtocol(protocolNumber)
        if (start >= end) {
            return TransportObservation(protocol = protocol, notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED))
        }

        return when (protocol) {
            TransportProtocol.TCP -> parseTcp(view, start, end)
            TransportProtocol.UDP -> parseUdp(view, start, end)
            TransportProtocol.ICMPV4,
            TransportProtocol.ICMPV6 -> parseIcmp(view, start, end, protocol)

            TransportProtocol.OTHER -> TransportObservation(protocol = TransportProtocol.OTHER)
        }
    }

    private fun parseTcp(view: PacketView, start: Int, end: Int): TransportObservation {
        if (start + 4 > end) {
            return TransportObservation(
                protocol = TransportProtocol.TCP,
                notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED),
            )
        }
        val sourcePort = view.u16(start)
        val destinationPort = view.u16(start + 2)
        if (start + TCP_MIN_HEADER_BYTES > end) {
            return TransportObservation(
                protocol = TransportProtocol.TCP,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED),
            )
        }
        val headerBytes = ((view.u8(start + 12) ushr 4) and 0x0f) * 4
        if (headerBytes < TCP_MIN_HEADER_BYTES || start + headerBytes > end) {
            return TransportObservation(
                protocol = TransportProtocol.TCP,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED),
            )
        }

        val dns = if (isDnsPort(sourcePort, destinationPort)) {
            parseDns(view, start + headerBytes, end, hasTcpLengthPrefix = true)
        } else {
            DnsObservation()
        }
        return TransportObservation(
            protocol = TransportProtocol.TCP,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dns = dns.metadata,
            notes = dns.notes,
        )
    }

    private fun parseUdp(view: PacketView, start: Int, end: Int): TransportObservation {
        if (start + UDP_HEADER_BYTES > end) {
            return TransportObservation(
                protocol = TransportProtocol.UDP,
                notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED),
            )
        }
        val sourcePort = view.u16(start)
        val destinationPort = view.u16(start + 2)
        val declaredUdpBytes = view.u16(start + 4)
        if (declaredUdpBytes in 1 until UDP_HEADER_BYTES) {
            return TransportObservation(
                protocol = TransportProtocol.UDP,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED),
            )
        }
        val payloadEnd = if (declaredUdpBytes == 0) {
            end // IPv6 UDP zero length is legal for a jumbogram; remain bounded by the capture.
        } else {
            minOf(end, start + declaredUdpBytes)
        }
        val dns = if (isDnsPort(sourcePort, destinationPort)) {
            parseDns(view, start + UDP_HEADER_BYTES, payloadEnd, hasTcpLengthPrefix = false)
        } else {
            DnsObservation()
        }
        return TransportObservation(
            protocol = TransportProtocol.UDP,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            dns = dns.metadata,
            notes = dns.notes,
        )
    }

    private fun parseIcmp(
        view: PacketView,
        start: Int,
        end: Int,
        protocol: TransportProtocol,
    ): TransportObservation {
        if (start + 2 > end) {
            return TransportObservation(protocol = protocol, notes = setOf(PacketParserNote.TRANSPORT_HEADER_TRUNCATED))
        }
        return TransportObservation(
            protocol = protocol,
            icmpType = view.u8(start),
            icmpCode = view.u8(start + 1),
        )
    }

    private fun parseDns(
        view: PacketView,
        payloadStart: Int,
        payloadEnd: Int,
        hasTcpLengthPrefix: Boolean,
    ): DnsObservation {
        if (dnsNameHandling is DnsNameHandling.Omit) return DnsObservation()
        if (payloadStart > payloadEnd) return DnsObservation(notes = setOf(PacketParserNote.DNS_MESSAGE_TRUNCATED))

        var messageStart = payloadStart
        var messageEnd = payloadEnd
        if (hasTcpLengthPrefix) {
            if (messageStart + DNS_TCP_LENGTH_PREFIX_BYTES > messageEnd) {
                return DnsObservation(notes = setOf(PacketParserNote.DNS_MESSAGE_TRUNCATED))
            }
            val declaredDnsBytes = view.u16(messageStart)
            messageStart += DNS_TCP_LENGTH_PREFIX_BYTES
            messageEnd = minOf(messageEnd, messageStart + declaredDnsBytes)
            if (declaredDnsBytes > payloadEnd - messageStart) {
                return DnsObservation(notes = setOf(PacketParserNote.DNS_MESSAGE_TRUNCATED))
            }
        }
        if (messageStart + DNS_HEADER_BYTES > messageEnd) {
            return DnsObservation(notes = setOf(PacketParserNote.DNS_MESSAGE_TRUNCATED))
        }

        val transactionId = view.u16(messageStart)
        val flags = view.u16(messageStart + 2)
        val questionCount = view.u16(messageStart + 4)
        val messageKind = if ((flags and DNS_RESPONSE_BIT) == 0) DnsMessageKind.QUERY else DnsMessageKind.RESPONSE
        val responseCode = if (messageKind == DnsMessageKind.RESPONSE) flags and DNS_RESPONSE_CODE_MASK else null

        if (questionCount == 0) {
            return DnsObservation(
                metadata = DnsMetadata(
                    messageKind = messageKind,
                    transactionId = transactionId,
                    questionCount = questionCount,
                    responseCode = responseCode,
                    questionName = SafeDnsName.NotCaptured,
                    questionType = null,
                    status = DnsParseStatus.HEADER_ONLY,
                ),
            )
        }

        val decodedName = readDnsName(view, messageStart + DNS_HEADER_BYTES, messageStart, messageEnd)
            ?: return DnsObservation(
                metadata = DnsMetadata(
                    messageKind = messageKind,
                    transactionId = transactionId,
                    questionCount = questionCount,
                    responseCode = responseCode,
                    questionName = SafeDnsName.NotCaptured,
                    questionType = null,
                    status = DnsParseStatus.MALFORMED,
                ),
                notes = setOf(PacketParserNote.DNS_MESSAGE_TRUNCATED),
            )
        if (decodedName.nextOffset + DNS_QUESTION_FIXED_BYTES > messageEnd) {
            return DnsObservation(
                metadata = DnsMetadata(
                    messageKind = messageKind,
                    transactionId = transactionId,
                    questionCount = questionCount,
                    responseCode = responseCode,
                    questionName = SafeDnsName.NotCaptured,
                    questionType = null,
                    status = DnsParseStatus.MALFORMED,
                ),
                notes = setOf(PacketParserNote.DNS_MESSAGE_TRUNCATED),
            )
        }

        val normalizedName = decodedName.name.lowercase(Locale.ROOT).trimEnd('.')
        val safeName = when (dnsNameHandling) {
            DnsNameHandling.Omit -> SafeDnsName.NotCaptured
            is DnsNameHandling.HashPerSession -> SafeDnsName.Hashed(
                sha256Prefix = hashDnsName(normalizedName, dnsNameHandling.salt),
                labelCount = decodedName.labelCount,
            )

            DnsNameHandling.PlaintextAfterExplicitConsent ->
                SafeDnsName.PlaintextAfterExplicitConsent(normalizedName)
        }
        // Answers are read only from a response, and only after the question section has
        // parsed cleanly, so a malformed message never contributes a destination binding.
        val answers = if (messageKind == DnsMessageKind.RESPONSE) {
            readDnsAnswers(
                view = view,
                startOffset = decodedName.nextOffset + DNS_QUESTION_FIXED_BYTES,
                messageStart = messageStart,
                messageEnd = messageEnd,
                answerCount = view.u16(messageStart + 6),
            )
        } else {
            emptyList()
        }
        return DnsObservation(
            metadata = DnsMetadata(
                messageKind = messageKind,
                transactionId = transactionId,
                questionCount = questionCount,
                responseCode = responseCode,
                questionName = safeName,
                questionType = view.u16(decodedName.nextOffset),
                status = DnsParseStatus.PARSED,
                answers = answers,
            ),
        )
    }

    /**
     * Reads A and AAAA answers. Every step is bounded against [messageEnd] and the loop is
     * capped, because the response is attacker-controlled: a declared answer count, a
     * declared record length, and a compression pointer are all untrusted inputs. Any
     * inconsistency stops collection and returns what was safely read so far rather than
     * throwing.
     */
    private fun readDnsAnswers(
        view: PacketView,
        startOffset: Int,
        messageStart: Int,
        messageEnd: Int,
        answerCount: Int,
    ): List<DnsAnswerRecord> {
        if (answerCount <= 0) return emptyList()
        val records = ArrayList<DnsAnswerRecord>()
        var offset = startOffset
        val bounded = minOf(answerCount, MAX_DNS_ANSWER_RECORDS)
        for (index in 0 until bounded) {
            if (offset >= messageEnd) return records
            val owner = readDnsName(view, offset, messageStart, messageEnd) ?: return records
            offset = owner.nextOffset
            if (offset + DNS_RESOURCE_RECORD_FIXED_BYTES > messageEnd) return records
            val type = view.u16(offset)
            val ttl = ((view.u16(offset + 4).toLong() shl 16) or view.u16(offset + 6).toLong())
            val rdLength = view.u16(offset + 8)
            val rdStart = offset + DNS_RESOURCE_RECORD_FIXED_BYTES
            if (rdLength < 0 || rdStart + rdLength > messageEnd) return records
            when {
                type == DNS_TYPE_A && rdLength == DNS_RDATA_IPV4_BYTES ->
                    records.add(DnsAnswerRecord(readIpv4(view, rdStart), ttl, isIpv6 = false))
                type == DNS_TYPE_AAAA && rdLength == DNS_RDATA_IPV6_BYTES ->
                    records.add(DnsAnswerRecord(readIpv6(view, rdStart), ttl, isIpv6 = true))
            }
            offset = rdStart + rdLength
        }
        return records
    }

    private fun readIpv4(view: PacketView, offset: Int): String =
        "${view.u8(offset)}.${view.u8(offset + 1)}.${view.u8(offset + 2)}.${view.u8(offset + 3)}"

    /** Full (uncompressed) form. Unambiguous is worth more than short for a pin comparison. */
    private fun readIpv6(view: PacketView, offset: Int): String =
        (0 until 8).joinToString(":") { group ->
            Integer.toHexString(view.u16(offset + group * 2))
        }

    private fun readDnsName(
        view: PacketView,
        initialOffset: Int,
        messageStart: Int,
        messageEnd: Int,
    ): DnsNameRead? {
        var cursor = initialOffset
        var nextOffset = initialOffset
        var jumped = false
        var labelsRead = 0
        val visitedPointers = mutableSetOf<Int>()
        val labels = ArrayList<String>()

        while (true) {
            if (cursor >= messageEnd) return null
            val length = view.u8(cursor)
            when {
                length == 0 -> {
                    if (!jumped) nextOffset = cursor + 1
                    return DnsNameRead(labels.joinToString("."), nextOffset, labelsRead)
                }

                (length and DNS_POINTER_MASK) == DNS_POINTER_MASK -> {
                    if (cursor + 2 > messageEnd) return null
                    val pointer = ((length and DNS_POINTER_VALUE_MASK) shl 8) or view.u8(cursor + 1)
                    val pointerOffset = messageStart + pointer
                    if (pointerOffset !in messageStart until messageEnd || !visitedPointers.add(pointerOffset)) return null
                    if (!jumped) {
                        nextOffset = cursor + 2
                        jumped = true
                    }
                    cursor = pointerOffset
                }

                (length and DNS_POINTER_MASK) != 0 -> return null
                length > DNS_MAX_LABEL_BYTES || cursor + 1 + length > messageEnd -> return null
                else -> {
                    labelsRead += 1
                    if (labelsRead > DNS_MAX_LABELS) return null
                    labels += dnsLabel(view.bytes, cursor + 1, length)
                    cursor += 1 + length
                    if (!jumped) nextOffset = cursor
                }
            }
        }
    }

    // Delegates so the parser and DomainBindingRegistry can never disagree about a key.
    private fun hashDnsName(name: String, salt: String): String = DnsNameKey.hash(name, salt)

    private fun transportProtocol(protocolNumber: Int): TransportProtocol = when (protocolNumber) {
        IP_PROTOCOL_TCP -> TransportProtocol.TCP
        IP_PROTOCOL_UDP -> TransportProtocol.UDP
        IP_PROTOCOL_ICMPV4 -> TransportProtocol.ICMPV4
        IP_PROTOCOL_ICMPV6 -> TransportProtocol.ICMPV6
        else -> TransportProtocol.OTHER
    }

    private fun isDnsPort(sourcePort: Int, destinationPort: Int): Boolean =
        sourcePort == DNS_PORT || destinationPort == DNS_PORT

    private data class TransportObservation(
        val protocol: TransportProtocol,
        val sourcePort: Int? = null,
        val destinationPort: Int? = null,
        val icmpType: Int? = null,
        val icmpCode: Int? = null,
        val dns: DnsMetadata? = null,
        val notes: Set<PacketParserNote> = emptySet(),
    ) {
        companion object {
            fun fromProtocolNumber(protocolNumber: Int): TransportObservation =
                TransportObservation(protocol = when (protocolNumber) {
                    IP_PROTOCOL_TCP -> TransportProtocol.TCP
                    IP_PROTOCOL_UDP -> TransportProtocol.UDP
                    IP_PROTOCOL_ICMPV4 -> TransportProtocol.ICMPV4
                    IP_PROTOCOL_ICMPV6 -> TransportProtocol.ICMPV6
                    else -> TransportProtocol.OTHER
                })
        }
    }

    private data class DnsObservation(
        val metadata: DnsMetadata? = null,
        val notes: Set<PacketParserNote> = emptySet(),
    )

    private data class DnsNameRead(
        val name: String,
        val nextOffset: Int,
        val labelCount: Int,
    )

    private class PacketView(
        val bytes: ByteArray,
        val start: Int,
        val end: Int,
    ) {
        fun has(offset: Int, count: Int): Boolean = count >= 0 && offset >= start && offset <= end - count

        fun u8(offset: Int): Int = bytes[offset].toInt() and 0xff

        fun u16(offset: Int): Int = (u8(offset) shl 8) or u8(offset + 1)
    }

    private companion object {
        const val IPV4_MIN_HEADER_BYTES = 20
        const val IPV4_ADDRESS_BYTES = 4
        const val IPV4_FRAGMENT_OFFSET_MASK = 0x1fff
        const val IPV6_HEADER_BYTES = 40
        const val IPV6_ADDRESS_BYTES = 16
        const val IPV6_FRAGMENT_HEADER_BYTES = 8
        const val IPV6_FRAGMENT_OFFSET_MASK = 0x1fff
        const val MAX_IPV6_EXTENSION_HEADERS = 8
        const val TCP_MIN_HEADER_BYTES = 20
        const val UDP_HEADER_BYTES = 8
        const val IP_PROTOCOL_TCP = 6
        const val IP_PROTOCOL_UDP = 17
        const val IP_PROTOCOL_ICMPV4 = 1
        const val IP_PROTOCOL_ICMPV6 = 58
        const val IPV6_FRAGMENT_HEADER = 44
        const val IPV6_ESP_HEADER = 50
        const val IPV6_AUTHENTICATION_HEADER = 51
        const val IPV6_NO_NEXT_HEADER = 59
        val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 51, 60)
        const val DNS_PORT = 53
        const val DNS_TCP_LENGTH_PREFIX_BYTES = 2
        const val DNS_HEADER_BYTES = 12
        const val DNS_QUESTION_FIXED_BYTES = 4
        const val DNS_RESPONSE_BIT = 0x8000
        const val DNS_RESOURCE_RECORD_FIXED_BYTES = 10
        const val DNS_TYPE_A = 1
        const val DNS_TYPE_AAAA = 28
        const val DNS_RDATA_IPV4_BYTES = 4
        const val DNS_RDATA_IPV6_BYTES = 16
        // A hostile response can claim a very large answer count; retain a bounded prefix.
        const val MAX_DNS_ANSWER_RECORDS = 32
        const val DNS_RESPONSE_CODE_MASK = 0x000f
        const val DNS_POINTER_MASK = 0xc0
        const val DNS_POINTER_VALUE_MASK = 0x3f
        const val DNS_MAX_LABEL_BYTES = 63
        const val DNS_MAX_LABELS = 127
        const val DNS_HASH_PREFIX_HEX_CHARACTERS = 16

        fun addressOf(bytes: ByteArray, offset: Int, length: Int): String =
            requireNotNull(InetAddress.getByAddress(bytes.copyOfRange(offset, offset + length)).hostAddress)

        fun dnsLabel(bytes: ByteArray, offset: Int, length: Int): String = buildString(length) {
            repeat(length) { index ->
                val value = bytes[offset + index].toInt() and 0xff
                append(if (value in 0x21..0x7e && value != '.'.code) value.toChar() else '?')
            }
        }
    }
}
