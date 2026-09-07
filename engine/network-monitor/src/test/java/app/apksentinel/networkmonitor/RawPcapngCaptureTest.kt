package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RawPcapngCaptureTest {
    @Test
    fun writesStandardsShbIdbAndRawIpv4Ipv6EnhancedPacketBlocks() {
        val clock = MutableClock(1_700_000_000_000L)
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(clock)

        assertTrue(capture.start(output) is RawPcapngCaptureStartResult.Started)
        capture.offerRawIpPacket(ipv4Packet(), clock.nowMillis())
        clock.advance(2)
        capture.offerRawIpPacket(ipv6Packet(), clock.nowMillis())
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))

        val bytes = output.toByteArray()
        assertEquals(0x0A0D0D0A, intLe(bytes, 0))
        assertEquals(28, intLe(bytes, 4))
        assertEquals(0x1A2B3C4D, intLe(bytes, 8))
        assertEquals(28, intLe(bytes, 24))
        assertEquals(1, intLe(bytes, 28))
        assertEquals(20, intLe(bytes, 32))
        assertEquals(101, shortLe(bytes, 36)) // DLT_RAW: raw IPv4/IPv6 datagrams.
        assertEquals(20, intLe(bytes, 44))

        val firstEpb = 48
        assertEquals(6, intLe(bytes, firstEpb))
        assertEquals(52, intLe(bytes, firstEpb + 4))
        assertEquals(20, intLe(bytes, firstEpb + 20))
        assertEquals(20, intLe(bytes, firstEpb + 24))
        assertEquals(4, bytes[firstEpb + 28].toInt() ushr 4)
        assertEquals(52, intLe(bytes, firstEpb + 48))

        val secondEpb = firstEpb + 52
        assertEquals(6, intLe(bytes, secondEpb))
        assertEquals(72, intLe(bytes, secondEpb + 4))
        assertEquals(40, intLe(bytes, secondEpb + 20))
        assertEquals(40, intLe(bytes, secondEpb + 24))
        assertEquals(6, bytes[secondEpb + 28].toInt() ushr 4)
        assertEquals(72, intLe(bytes, secondEpb + 68))
        assertEquals(RawPcapngCaptureState.STOPPED, capture.status().state)
    }

    @Test
    fun snaplenPreservesOriginalLengthAndPcapngPadding() {
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(output, RawPcapngCaptureLimits(perPacketSnaplen = 24, maximumCapturedBytes = 1_024L))
        val original = ipv4Packet() + ByteArray(17) { 7 }
        capture.offerRawIpPacket(original)
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))

        val epb = 48
        assertEquals(56, intLe(output.toByteArray(), epb + 4))
        assertEquals(24, intLe(output.toByteArray(), epb + 20))
        assertEquals(37, intLe(output.toByteArray(), epb + 24))
        assertEquals(56, intLe(output.toByteArray(), epb + 52))
        assertEquals(1L, capture.status().truncatedPackets)
    }

    @Test
    fun strictByteAndPacketBoundsStopNewOffersWithoutWritingExtraPackets() {
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(
            output,
            RawPcapngCaptureLimits(maximumPackets = 1L, maximumCapturedBytes = 1_024L),
        )
        capture.offerRawIpPacket(ipv4Packet())
        capture.offerRawIpPacket(ipv6Packet())
        assertTrue(capture.awaitStopped(2_000L))

        assertEquals(1L, capture.status().acceptedPackets)
        assertEquals(1L, capture.status().writtenPackets)
        assertTrue(capture.status().droppedByLimit >= 1L)
    }

    @Test
    fun strictCapturedByteAndDurationBoundsRejectLaterPackets() {
        val clock = MutableClock(1_700_000_000_000L)
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(clock)
        capture.start(
            output,
            RawPcapngCaptureLimits(
                maximumDurationMillis = 1_000L,
                maximumPackets = 10L,
                maximumCapturedBytes = 1_024L,
            ),
        )
        capture.offerRawIpPacket(ipv4Packet() + ByteArray(780))
        capture.offerRawIpPacket(ipv4Packet() + ByteArray(780)) // exceeds byte reservation
        assertTrue(capture.awaitStopped(2_000L))
        assertEquals(800L, capture.status().capturedBytes)
        assertTrue(capture.status().droppedByLimit >= 1L)

        val durationCapture = RawPcapngCaptureManager(clock)
        durationCapture.start(ByteArrayOutputStream(), RawPcapngCaptureLimits(maximumDurationMillis = 1_000L))
        clock.advance(1_000L)
        durationCapture.offerRawIpPacket(ipv4Packet())
        assertTrue(durationCapture.awaitStopped(2_000L))
        assertEquals(0L, durationCapture.status().acceptedPackets)
        assertTrue(durationCapture.status().droppedByLimit >= 1L)
    }

    @Test
    fun serializedFileByteLimitIncludesSectionInterfaceAndEnhancedPacketFraming() {
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(
            output,
            RawPcapngCaptureLimits(maximumCapturedBytes = 1_024L, perPacketSnaplen = 1_024),
        )
        capture.offerRawIpPacket(ipv4Packet() + ByteArray(980) { 7 })
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))

        val status = capture.status()
        assertTrue(status.writtenFileBytes <= 1_024L)
        assertEquals(0L, status.writtenPackets)
        assertTrue(status.droppedByLimit >= 1L)
    }

    @Test
    fun boundedQueueDropsInsteadOfBlockingForwardingPath() {
        val gate = GateOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(gate, RawPcapngCaptureLimits(queueCapacity = 1, maximumCapturedBytes = 1_024L))
        assertTrue(gate.entered.await(1L, TimeUnit.SECONDS))
        capture.offerRawIpPacket(ipv4Packet())
        capture.offerRawIpPacket(ipv6Packet())
        assertTrue(capture.status().droppedQueueFull >= 1L)
        gate.release.countDown()
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))
    }

    @Test
    fun outputFailureUsesTypedReasonAndCallerStreamIsNeverClosed() {
        val output = FailingOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(output)
        assertTrue(capture.awaitStopped(2_000L))

        assertEquals(RawPcapngCaptureState.FAILED, capture.status().state)
        assertEquals(RawPcapngCaptureFailureReason.OUTPUT_WRITE_FAILED, capture.status().failureReason)
        assertFalse(output.closed)
    }

    @Test
    fun partiallyWrittenEnhancedPacketIsNotCountedAsWritten() {
        // SHB + IDB are 48 bytes. Permit an IPv4 EPB header and body, then fail
        // its four-byte trailer so the block is incomplete on disk.
        val output = FailAfterBytesOutputStream(maximumSuccessfulBytes = 96)
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(output)
        capture.offerRawIpPacket(ipv4Packet())
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))

        assertEquals(RawPcapngCaptureState.FAILED, capture.status().state)
        assertEquals(RawPcapngCaptureFailureReason.OUTPUT_WRITE_FAILED, capture.status().failureReason)
        assertEquals(1L, capture.status().acceptedPackets)
        assertEquals(0L, capture.status().writtenPackets)
    }

    @Test
    fun rejectsNonIpPacketsWithoutRetainingThem() {
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(output)
        capture.offerRawIpPacket(byteArrayOf(0x20))
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))
        assertEquals(0L, capture.status().acceptedPackets)
        assertEquals(1L, capture.status().droppedUnsupportedPacket)
        assertNull(capture.status().failureReason)
    }

    @Test
    fun permitsOnlyOneActiveSession() {
        val gate = GateOutputStream()
        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        assertTrue(capture.start(gate) is RawPcapngCaptureStartResult.Started)
        val rejected = capture.start(ByteArrayOutputStream()) as RawPcapngCaptureStartResult.Rejected
        assertEquals(RawPcapngCaptureStartRejection.ALREADY_ACTIVE, rejected.reason)
        gate.release.countDown()
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))
    }

    @Test
    fun rejectsNegativeOrUnavailableStartClockAndDropsNegativeObservedTime() {
        val negative = RawPcapngCaptureManager(MutableClock(-1L))
        val rejected = negative.start(ByteArrayOutputStream()) as RawPcapngCaptureStartResult.Rejected
        assertEquals(RawPcapngCaptureStartRejection.INVALID_START_TIME, rejected.reason)

        val unavailable = RawPcapngCaptureManager(EpochClock { error("clock provider text must not escape") })
        val unavailableResult = unavailable.start(ByteArrayOutputStream()) as RawPcapngCaptureStartResult.Rejected
        assertEquals(RawPcapngCaptureStartRejection.CLOCK_UNAVAILABLE, unavailableResult.reason)

        val capture = RawPcapngCaptureManager(MutableClock(1_700_000_000_000L))
        capture.start(ByteArrayOutputStream())
        capture.offerRawIpPacket(ipv4Packet(), observedAtMillis = -1L)
        assertEquals(0L, capture.status().acceptedPackets)
        assertEquals(1L, capture.status().droppedInvalidTimestamp)
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))
    }

    @Test
    fun saturatesNearMaximumEpochMillisWithoutOverflowingPcapngTimestamp() {
        val start = Long.MAX_VALUE - 500L
        val clock = MutableClock(start)
        val output = ByteArrayOutputStream()
        val capture = RawPcapngCaptureManager(clock)
        capture.start(output)
        capture.offerRawIpPacket(ipv4Packet(), observedAtMillis = Long.MAX_VALUE - 1L)
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))

        val epb = 48
        assertEquals(0x7FFFFFFF, intLe(output.toByteArray(), epb + 12))
        assertEquals(-1, intLe(output.toByteArray(), epb + 16))
    }

    @Test
    fun aClockThatBecomesNegativeFailsWithCodeAndDoesNotWriteNegativeTime() {
        val clock = MutableClock(1_700_000_000_000L)
        val output = GateOutputStream()
        val capture = RawPcapngCaptureManager(clock)
        capture.start(output)
        assertTrue(output.entered.await(1L, TimeUnit.SECONDS))
        clock.set(-1L)
        output.release.countDown()
        assertTrue(capture.awaitStopped(2_000L))
        assertEquals(RawPcapngCaptureState.FAILED, capture.status().state)
        assertEquals(RawPcapngCaptureFailureReason.INVALID_CLOCK_TIME, capture.status().failureReason)
        assertNull(capture.status().endedAtMillis)
    }

    @Test
    fun writerStartFailureLeavesNoActiveSessionAndReturnsOnlyCode() {
        val failFirstStart = AtomicBoolean(true)
        val capture = RawPcapngCaptureManager(
            clock = MutableClock(1_700_000_000_000L),
            workerStarter = { name, task ->
                if (failFirstStart.compareAndSet(true, false)) {
                    throw IllegalStateException("provider message must not escape")
                }
                Thread({ task() }, name).apply {
                    isDaemon = true
                    start()
                }
            },
        )
        val rejected = capture.start(ByteArrayOutputStream()) as RawPcapngCaptureStartResult.Rejected
        assertEquals(RawPcapngCaptureStartRejection.WRITER_START_FAILED, rejected.reason)
        assertEquals(RawPcapngCaptureState.FAILED, capture.status().state)
        assertEquals(RawPcapngCaptureFailureReason.WRITER_START_FAILED, capture.status().failureReason)
        assertTrue(capture.start(ByteArrayOutputStream()) is RawPcapngCaptureStartResult.Started)
        capture.stop()
        assertTrue(capture.awaitStopped(2_000L))
    }

    private class MutableClock(@Volatile private var value: Long) : EpochClock {
        override fun nowMillis(): Long = value
        fun advance(delta: Long) { value += delta }
        fun set(next: Long) { value = next }
    }

    private class GateOutputStream : OutputStream() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        private var first = true
        override fun write(value: Int) = Unit
        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (first) {
                first = false
                entered.countDown()
                release.await(2L, TimeUnit.SECONDS)
            }
        }
    }

    private class FailingOutputStream : OutputStream() {
        var closed = false
        override fun write(value: Int) { throw IOException("disk unavailable") }
        override fun write(bytes: ByteArray, offset: Int, length: Int) { throw IOException("disk unavailable") }
        override fun close() { closed = true }
    }

    private class FailAfterBytesOutputStream(private val maximumSuccessfulBytes: Int) : OutputStream() {
        private var written = 0
        override fun write(value: Int) {
            if (written + 1 > maximumSuccessfulBytes) throw IOException("simulated bounded provider failure")
            written++
        }
        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (written + length > maximumSuccessfulBytes) throw IOException("simulated bounded provider failure")
            written += length
        }
    }

    private fun ipv4Packet(): ByteArray = byteArrayOf(
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0,
        127, 0, 0, 1, 8, 8, 8, 8,
    )

    private fun ipv6Packet(): ByteArray = byteArrayOf(
        0x60, 0, 0, 0, 0, 0, 17, 64,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    )

    private fun shortLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

    private fun intLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
}
