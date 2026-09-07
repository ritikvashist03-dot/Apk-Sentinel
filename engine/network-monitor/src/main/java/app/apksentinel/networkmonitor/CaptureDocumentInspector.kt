package app.apksentinel.networkmonitor

import java.io.EOFException
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

enum class CaptureInspectionFormat { PCAP, PCAPNG }
enum class CaptureInspectionEncryption { NONE, ENCRYPTED_OR_OPAQUE, UNSUPPORTED }

data class CaptureInspectionLimits(
    val maximumBytes: Long = 128L * 1_024L * 1_024L,
    val maximumPackets: Long = 100_000L,
    val maximumBlockBytes: Int = 16 * 1_024 * 1_024,
    val maximumPacketBytes: Int = 1 * 1_024 * 1_024,
) {
    init {
        require(maximumBytes in 4_096L..512L * 1_024L * 1_024L)
        require(maximumPackets in 1L..1_000_000L)
        require(maximumBlockBytes in 64..64 * 1_024 * 1_024)
        require(maximumPacketBytes in 64..16 * 1_024 * 1_024)
    }
}

enum class CaptureInspectionFailure {
    EMPTY_INPUT, UNKNOWN_FORMAT, ENCRYPTED_OR_OPAQUE, UNSUPPORTED_VERSION,
    TRUNCATED_HEADER, INVALID_LENGTH, BLOCK_TOO_LARGE, PACKET_TOO_LARGE,
    PACKET_LIMIT_REACHED, BYTE_LIMIT_REACHED, INVALID_PCAPNG_SECTION,
    INVALID_PCAPNG_BLOCK, UNSUPPORTED_LINK_TYPE,
}

data class CaptureInspectionSummary(
    val format: CaptureInspectionFormat,
    val encryption: CaptureInspectionEncryption = CaptureInspectionEncryption.NONE,
    val packetCount: Long,
    val observedBytes: Long,
    val truncated: Boolean,
    val limitations: Set<CaptureInspectionFailure> = emptySet(),
) {
    init { require(packetCount >= 0L && observedBytes >= 0L) }
}

sealed interface CaptureInspectionResult {
    data class Opened(val summary: CaptureInspectionSummary) : CaptureInspectionResult
    data class Rejected(val failure: CaptureInspectionFailure) : CaptureInspectionResult
}

/**
 * Streaming, header/block-only capture inspector. It deliberately never
 * stores a packet body; packet bytes are consumed and discarded under caps.
 */
object CaptureDocumentInspector {
    fun inspect(input: InputStream, limits: CaptureInspectionLimits = CaptureInspectionLimits()): CaptureInspectionResult {
        val prefix = ByteArray(4)
        if (!readFully(input, prefix)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.EMPTY_INPUT)
        val magic = u32(prefix, ByteOrder.LITTLE_ENDIAN)
        return when (magic) {
            0xA1B2C3D4L, 0xA1B23C4DL, 0xD4C3B2A1L, 0x4D3CB2A1L -> inspectPcap(input, prefix, limits)
            0x0A0D0D0AL -> inspectPcapng(input, prefix, limits)
            else -> CaptureInspectionResult.Rejected(
                if (looksEncrypted(prefix)) CaptureInspectionFailure.ENCRYPTED_OR_OPAQUE
                else CaptureInspectionFailure.UNKNOWN_FORMAT,
            )
        }
    }

    private fun inspectPcap(input: InputStream, prefix: ByteArray, limits: CaptureInspectionLimits): CaptureInspectionResult {
        val little = u32(prefix, ByteOrder.LITTLE_ENDIAN) in setOf(0xA1B2C3D4L, 0xA1B23C4DL)
        val order = if (little) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val headerRest = ByteArray(20)
        if (!readFully(input, headerRest)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
        val header = ByteArray(24); prefix.copyInto(header); headerRest.copyInto(header, 4)
        val versionMajor = u16(header, 4, order); val versionMinor = u16(header, 6, order)
        val snaplen = u32(header, 16, order)
        if (versionMajor != 2 || versionMinor !in 0..4) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.UNSUPPORTED_VERSION)
        if (snaplen !in 1..limits.maximumPacketBytes.toLong()) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.PACKET_TOO_LARGE)
        var packets = 0L; var bytes = 24L; var truncated = false
        while (true) {
            if (bytes >= limits.maximumBytes || limits.maximumBytes - bytes < 16L) {
                return CaptureInspectionResult.Opened(
                    CaptureInspectionSummary(
                        CaptureInspectionFormat.PCAP,
                        packetCount = packets,
                        observedBytes = bytes,
                        truncated = true,
                        limitations = setOf(CaptureInspectionFailure.BYTE_LIMIT_REACHED),
                    ),
                )
            }
            val record = ByteArray(16)
            val first = input.read()
            if (first < 0) break
            record[0] = first.toByte()
            if (!readFully(input, record, 1, record.size - 1)) {
                return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
            }
            bytes += 16L
            val captured = u32(record, 8, order); val original = u32(record, 12, order)
            if (captured > limits.maximumPacketBytes) {
                return CaptureInspectionResult.Rejected(CaptureInspectionFailure.PACKET_TOO_LARGE)
            }
            if (captured > limits.maximumBytes - bytes) {
                return CaptureInspectionResult.Opened(
                    CaptureInspectionSummary(
                        CaptureInspectionFormat.PCAP,
                        packetCount = packets,
                        observedBytes = bytes,
                        truncated = true,
                        limitations = setOf(CaptureInspectionFailure.BYTE_LIMIT_REACHED),
                    ),
                )
            }
            if (original < captured) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_LENGTH)
            if (!skipFully(input, captured)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
            bytes += captured
            packets++
            truncated = truncated || original > captured
            if (packets >= limits.maximumPackets) {
                return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAP, packetCount = packets, observedBytes = bytes, truncated = truncated, limitations = setOf(CaptureInspectionFailure.PACKET_LIMIT_REACHED)))
            }
        }
        val limitation = emptySet<CaptureInspectionFailure>()
        return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAP, packetCount = packets, observedBytes = bytes, truncated = truncated, limitations = limitation))
    }

    private fun inspectPcapng(input: InputStream, prefix: ByteArray, limits: CaptureInspectionLimits): CaptureInspectionResult {
        var order: ByteOrder? = null
        var packets = 0L
        var bytes = 4L
        var truncated = false
        var sawSection = false
        var interfaceCount = 0
        var firstBlock = true
        while (true) {
            if (bytes >= limits.maximumBytes || limits.maximumBytes - bytes < 8L) {
                return CaptureInspectionResult.Opened(
                    CaptureInspectionSummary(
                        CaptureInspectionFormat.PCAPNG,
                        packetCount = packets,
                        observedBytes = bytes,
                        truncated = true,
                        limitations = setOf(CaptureInspectionFailure.BYTE_LIMIT_REACHED),
                    ),
                )
            }

            // The caller already consumed the initial four-byte SHB type. Read
            // its total length and BOM together: the length cannot be decoded
            // until the BOM establishes the section byte order.
            if (firstBlock) {
                val lengthAndBom = ByteArray(8)
                if (!readFully(input, lengthAndBom)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                bytes += 8L
                val candidate = pcapngOrder(lengthAndBom, 4) ?: return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_SECTION)
                val total = u32(lengthAndBom, 0, candidate)
                if (total !in 28L..limits.maximumBlockBytes.toLong()) {
                    return CaptureInspectionResult.Rejected(if (total > limits.maximumBlockBytes) CaptureInspectionFailure.BLOCK_TOO_LARGE else CaptureInspectionFailure.INVALID_LENGTH)
                }
                if (total > limits.maximumBytes - 4L) return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAPNG, packetCount = packets, observedBytes = bytes, truncated = true, limitations = setOf(CaptureInspectionFailure.BYTE_LIMIT_REACHED)))
                val fixed = ByteArray(12)
                if (!readFully(input, fixed)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_SECTION)
                bytes += 12L
                if (u16(fixed, 0, candidate) != 1) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.UNSUPPORTED_VERSION)
                val remaining = total - 28L
                if (!skipFully(input, remaining)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                bytes += remaining
                val trailer = ByteArray(4)
                if (!readFully(input, trailer)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                bytes += 4L
                if (u32(trailer, 0, candidate) != total) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                order = candidate
                interfaceCount = 0
                sawSection = true
                firstBlock = false
                continue
            }

            val header = ByteArray(8)
            val firstByte = input.read()
            if (firstByte < 0) break
            header[0] = firstByte.toByte()
            if (!readFully(input, header, 1, header.size - 1)) {
                return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAPNG, packetCount = packets, observedBytes = bytes + 1L, truncated = true, limitations = setOf(CaptureInspectionFailure.TRUNCATED_HEADER)))
            }
            bytes += 8L
            val currentOrder = order ?: return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_SECTION)
            val type = u32(header, 0, currentOrder)
            val candidate: ByteOrder
            val total: Long
            if (type == PCAPNG_SECTION_HEADER) {
                // A later section can use a different byte order. Read its BOM
                // before decoding the total length, just as for the first SHB.
                val bom = ByteArray(4)
                if (!readFully(input, bom)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_SECTION)
                bytes += 4L
                candidate = pcapngOrder(bom, 0) ?: return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_SECTION)
                total = u32(header, 4, candidate)
                if (total !in 28L..limits.maximumBlockBytes.toLong()) {
                    return CaptureInspectionResult.Rejected(if (total > limits.maximumBlockBytes) CaptureInspectionFailure.BLOCK_TOO_LARGE else CaptureInspectionFailure.INVALID_LENGTH)
                }
                if (total > limits.maximumBytes - (bytes - 12L)) return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAPNG, packetCount = packets, observedBytes = bytes, truncated = true, limitations = setOf(CaptureInspectionFailure.BYTE_LIMIT_REACHED)))
                val fixed = ByteArray(12)
                if (!readFully(input, fixed)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_SECTION)
                bytes += 12L
                if (u16(fixed, 0, candidate) != 1) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.UNSUPPORTED_VERSION)
                val remaining = total - 28L
                if (!skipFully(input, remaining)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                bytes += remaining
                val trailer = ByteArray(4)
                if (!readFully(input, trailer)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                bytes += 4L
                if (u32(trailer, 0, candidate) != total) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                order = candidate
                interfaceCount = 0
                continue
            } else {
                candidate = currentOrder
                total = u32(header, 4, candidate)
            }

            if (total !in 12L..limits.maximumBlockBytes.toLong()) {
                return CaptureInspectionResult.Rejected(if (total > limits.maximumBlockBytes) CaptureInspectionFailure.BLOCK_TOO_LARGE else CaptureInspectionFailure.INVALID_LENGTH)
            }
            if (total > limits.maximumBytes - (bytes - 8L)) {
                return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAPNG, packetCount = packets, observedBytes = bytes, truncated = true, limitations = setOf(CaptureInspectionFailure.BYTE_LIMIT_REACHED)))
            }
            val bodyLength = total - 12L
            when (type) {
                PCAPNG_INTERFACE_DESCRIPTION -> {
                    if (bodyLength < 8L) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    val idb = ByteArray(8)
                    if (!readFully(input, idb)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                    val linkType = u16(idb, 0, candidate)
                    val snaplen = u32(idb, 4, candidate)
                    if (linkType !in SUPPORTED_LINK_TYPES) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.UNSUPPORTED_LINK_TYPE)
                    if (snaplen !in 1L..limits.maximumPacketBytes.toLong()) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.PACKET_TOO_LARGE)
                    if (!skipFully(input, bodyLength - 8L)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                    interfaceCount++
                }
                PCAPNG_ENHANCED_PACKET -> {
                    if (bodyLength < 20L) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    val epb = ByteArray(20)
                    if (!readFully(input, epb)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                    val interfaceId = u32(epb, 0, candidate)
                    val captured = u32(epb, 12, candidate)
                    val original = u32(epb, 16, candidate)
                    if (interfaceId >= interfaceCount.toLong()) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    if (captured > limits.maximumPacketBytes || original < captured) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.PACKET_TOO_LARGE)
                    if (bodyLength - 20L < pad4(captured)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    if (!skipFully(input, bodyLength - 20L)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                    packets++
                    truncated = truncated || original > captured
                }
                PCAPNG_SIMPLE_PACKET -> {
                    if (bodyLength < 4L) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    val spb = ByteArray(4)
                    if (!readFully(input, spb)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                    val original = u32(spb, 0, candidate)
                    if (interfaceCount == 0) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    if (original > limits.maximumPacketBytes) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.PACKET_TOO_LARGE)
                    if (bodyLength - 4L < pad4(original)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
                    if (!skipFully(input, bodyLength - 4L)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
                    packets++
                }
                else -> if (!skipFully(input, bodyLength)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
            }
            val trailer = ByteArray(4)
            if (!readFully(input, trailer)) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.TRUNCATED_HEADER)
            // The eight-byte block header was already included above; only
            // account for the body and trailing length here.
            bytes += total - 8L
            if (u32(trailer, 0, candidate) != total) return CaptureInspectionResult.Rejected(CaptureInspectionFailure.INVALID_PCAPNG_BLOCK)
            if (packets >= limits.maximumPackets) return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAPNG, packetCount = packets, observedBytes = bytes, truncated = truncated, limitations = setOf(CaptureInspectionFailure.PACKET_LIMIT_REACHED)))
        }
        return CaptureInspectionResult.Opened(CaptureInspectionSummary(CaptureInspectionFormat.PCAPNG, packetCount = packets, observedBytes = bytes, truncated = truncated, limitations = emptySet()))
    }

    private fun looksEncrypted(prefix: ByteArray): Boolean = prefix.any { (it.toInt() and 0xff) == 0xA5 }
    private fun pad4(value: Long): Long = (4L - value.rem(4L)).rem(4L)
    private fun readFully(input: InputStream, target: ByteArray): Boolean = readFully(input, target, 0, target.size)
    private fun readFully(input: InputStream, target: ByteArray, offset: Int, length: Int): Boolean {
        var cursor = offset
        val end = offset + length
        while (cursor < end) {
            val read = input.read(target, cursor, end - cursor)
            if (read < 0) return false
            if (read == 0) {
                val one = input.read()
                if (one < 0) return false
                target[cursor++] = one.toByte()
            } else {
                cursor += read
            }
        }
        return true
    }
    private fun skipFully(input: InputStream, count: Long): Boolean {
        var remaining = count
        while (remaining > 0L) { val skipped = input.skip(remaining); if (skipped > 0L) remaining -= skipped else { if (input.read() < 0) return false; remaining-- } }
        return true
    }
    private fun u32(bytes: ByteArray, order: ByteOrder): Long = ByteBuffer.wrap(bytes).order(order).int.toLong() and 0xffff_ffffL
    private fun u32(bytes: ByteArray, offset: Int, order: ByteOrder): Long = ByteBuffer.wrap(bytes, offset, 4).order(order).int.toLong() and 0xffff_ffffL
    private fun u16(bytes: ByteArray, offset: Int, order: ByteOrder): Int = ByteBuffer.wrap(bytes, offset, 2).order(order).short.toInt() and 0xffff

    private fun pcapngOrder(bytes: ByteArray, offset: Int): ByteOrder? = when {
        u32(bytes, offset, ByteOrder.LITTLE_ENDIAN) == PCAPNG_BYTE_ORDER_MAGIC -> ByteOrder.LITTLE_ENDIAN
        u32(bytes, offset, ByteOrder.BIG_ENDIAN) == PCAPNG_BYTE_ORDER_MAGIC -> ByteOrder.BIG_ENDIAN
        else -> null
    }

    private const val PCAPNG_SECTION_HEADER = 0x0A0D0D0AL
    private const val PCAPNG_INTERFACE_DESCRIPTION = 1L
    private const val PCAPNG_SIMPLE_PACKET = 3L
    private const val PCAPNG_ENHANCED_PACKET = 6L
    private const val PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4DL
    private val SUPPORTED_LINK_TYPES = setOf(0, 1, 101, 113, 276)
}
