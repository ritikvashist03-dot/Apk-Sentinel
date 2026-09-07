package app.apksentinel.networkmonitor

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadInspectionTest {
    private val flow = PayloadFlowKey("10.0.0.2", 44_000, "203.0.113.8", 80, PayloadInspectionTransport.TCP)

    @Test
    fun disabledSessionNeverRetainsPayload() {
        val collector = BoundedPayloadInspectionCollector(PayloadInspectionConfiguration())

        collector.offer(flow, PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, "GET / HTTP/1.1\r\n\r\n".toByteArray(), 1L)

        val snapshot = collector.snapshot()
        assertEquals(PayloadInspectionState.DISABLED, snapshot.state)
        assertTrue(snapshot.records.isEmpty())
        assertTrue(PayloadInspectionLimitation.DISABLED_BY_SESSION in snapshot.limitations)
    }

    @Test
    fun redactsCredentialsBeforeTextOrHexCanBeRevealed() {
        val collector = activeCollector()
        val source = "GET /p?token=secret HTTP/1.1\r\nAuthorization: Bearer abc.def\r\nCookie: sid=123\r\n\r\npassword=hidden"
        collector.offer(flow, PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, source.toByteArray(), 1L)
        val record = awaitRecord(collector)

        val token = collector.issueRevealToken(PayloadRevealAcknowledgement("payload-reveal-v1", 2L))
        assertNotNull(token)
        val text = collector.render(record.id, requireNotNull(token), PayloadRenderFormat.TEXT)
        val hex = collector.render(record.id, requireNotNull(token), PayloadRenderFormat.HEX)

        assertNotNull(text)
        assertNotNull(hex)
        assertTrue(requireNotNull(text).content.contains("[REDACTED]"))
        assertFalse(text.content.contains("secret"))
        assertFalse(text.content.contains("abc.def"))
        assertFalse(text.content.contains("sid=123"))
        assertFalse(text.content.contains("hidden"))
        assertFalse(requireNotNull(hex).content.contains("73 65 63 72 65 74")) // secret
        collector.stopAndClear()
    }

    @Test
    fun tlsAndOpaqueBytesAreRejectedWithoutRetention() {
        val collector = activeCollector()
        collector.offer(
            flow,
            PacketDirection.OUTBOUND,
            PayloadInspectionTransport.TCP,
            byteArrayOf(22, 3, 3, 0, 10, 1, 2, 3),
            1L,
        )
        collector.offer(flow, PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, byteArrayOf(0, 1, 2, 3, 4), 1L)

        waitUntil { collector.snapshot().drops[PayloadInspectionDropReason.NOT_PLAINTEXT_OR_ENCRYPTED] == 2L }
        assertTrue(collector.snapshot().records.isEmpty())
        collector.stopAndClear()
    }

    @Test
    fun malformedUtf8BecomesSafePlaceholder() {
        val collector = activeCollector()
        collector.offer(
            flow,
            PacketDirection.OUTBOUND,
            PayloadInspectionTransport.TCP,
            ("harmless text ".repeat(3)).toByteArray() + byteArrayOf(0xc3.toByte()),
            1L,
        )
        val record = awaitRecord(collector)
        assertTrue(record.malformedUtf8WasRedacted)
        val token = requireNotNull(collector.issueRevealToken(PayloadRevealAcknowledgement("reveal-v1", 2L)))
        val rendered = requireNotNull(collector.render(record.id, token, PayloadRenderFormat.TEXT))
        assertEquals("[invalid UTF-8 payload redacted]", rendered.content)
        collector.stopAndClear()
    }

    @Test
    fun strictBoundsAndStopZeroizeRetainedContent() {
        val collector = BoundedPayloadInspectionCollector(
            PayloadInspectionConfiguration(
                enabled = true,
                consent = PayloadInspectionConsent("payload-v1", 1L),
                maximumSessionBytes = 4 * 1_024,
                maximumBytesPerFlow = 1 * 1_024,
                maximumRecords = 1,
                maximumBytesPerRecord = 256,
            ),
        )
        val payload = ("X-Note: " + "a".repeat(600)).toByteArray()
        collector.offer(flow, PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, payload, 1L)
        collector.offer(flow.copy(sourcePort = 44_001), PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, payload, 1L)
        val record = awaitRecord(collector)
        waitUntil { collector.snapshot().drops[PayloadInspectionDropReason.RECORD_LIMIT_REACHED] == 1L }
        assertTrue(record.wasTruncated)
        assertTrue(collector.snapshot().retainedBytes <= 256L)
        val token = requireNotNull(collector.issueRevealToken(PayloadRevealAcknowledgement("reveal-v1", 2L)))

        collector.stopAndClear()

        assertTrue(collector.snapshot().records.isEmpty())
        assertEquals(0L, collector.snapshot().retainedBytes)
        assertNull(collector.render(record.id, token, PayloadRenderFormat.TEXT))
    }

    @Test
    fun hostCanRevokeRevealTokenWithoutStoppingBoundedCollection() {
        val collector = activeCollector()
        collector.offer(flow, PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, "GET / HTTP/1.1\r\n\r\n".toByteArray(), 1L)
        val record = awaitRecord(collector)
        val oldToken = requireNotNull(collector.issueRevealToken(PayloadRevealAcknowledgement("reveal-v1", 2L)))

        collector.revokeRevealTokens()

        assertNull(collector.render(record.id, oldToken, PayloadRenderFormat.TEXT))
        val newToken = requireNotNull(collector.issueRevealToken(PayloadRevealAcknowledgement("reveal-v1", 3L)))
        assertNotNull(collector.render(record.id, newToken, PayloadRenderFormat.TEXT))
        collector.stopAndClear()
    }

    @Test
    fun queuePressureIsNonBlockingAndBounded() {
        val collector = BoundedPayloadInspectionCollector(
            PayloadInspectionConfiguration(
                enabled = true,
                consent = PayloadInspectionConsent("payload-v1", 1L),
                ingressQueueCapacity = 1,
            ),
        )
        val latch = CountDownLatch(4)
        repeat(4) { worker ->
            Thread {
                repeat(250) { index ->
                    collector.offer(
                        flow.copy(sourcePort = 44_000 + worker),
                        PacketDirection.OUTBOUND,
                        PayloadInspectionTransport.TCP,
                        "GET /$index HTTP/1.1\r\n\r\n".toByteArray(),
                        1L,
                    )
                }
                latch.countDown()
            }.start()
        }
        assertTrue(latch.await(2L, TimeUnit.SECONDS))
        waitUntil { collector.snapshot().drops.isNotEmpty() || collector.snapshot().records.isNotEmpty() }
        assertTrue(collector.snapshot().records.size <= 128)
        assertTrue(collector.snapshot().retainedBytes <= 1L * 1_024 * 1_024)
        collector.stopAndClear()
    }

    @Test
    fun invalidClockProducesTypedFailure() {
        val collector = BoundedPayloadInspectionCollector(
            PayloadInspectionConfiguration(enabled = true, consent = PayloadInspectionConsent("payload-v1", 1L)),
            EpochClock { error("provider details must not escape") },
        )

        assertEquals(PayloadInspectionState.FAILED, collector.snapshot().state)
        assertEquals(PayloadInspectionFailureReason.CLOCK_UNAVAILABLE, collector.snapshot().failureReason)
    }

    @Test
    fun durationExpiryAndClockRollbackClearContentWithTypedState() {
        val clock = MutableClock(10_000L)
        val collector = BoundedPayloadInspectionCollector(
            PayloadInspectionConfiguration(
                enabled = true,
                consent = PayloadInspectionConsent("payload-v1", 1L),
                maximumDurationMillis = 5_000L,
            ),
            clock,
        )
        collector.offer(flow, PacketDirection.OUTBOUND, PayloadInspectionTransport.TCP, "GET / HTTP/1.1\r\n\r\n".toByteArray(), 10_000L)
        awaitRecord(collector)
        clock.value = 15_000L
        waitUntil { collector.snapshot().state == PayloadInspectionState.EXPIRED }
        assertTrue(collector.snapshot().records.isEmpty())

        val rollbackClock = MutableClock(10_000L)
        val rollback = BoundedPayloadInspectionCollector(
            PayloadInspectionConfiguration(enabled = true, consent = PayloadInspectionConsent("payload-v1", 1L)),
            rollbackClock,
        )
        rollbackClock.value = 9_000L
        waitUntil { rollback.snapshot().state == PayloadInspectionState.FAILED }
        assertEquals(PayloadInspectionFailureReason.INVALID_CLOCK_TIME, rollback.snapshot().failureReason)
    }

    private fun activeCollector(): BoundedPayloadInspectionCollector = BoundedPayloadInspectionCollector(
        PayloadInspectionConfiguration(enabled = true, consent = PayloadInspectionConsent("payload-v1", 1L)),
    )

    private fun awaitRecord(collector: BoundedPayloadInspectionCollector): PayloadInspectionRecord {
        waitUntil { collector.snapshot().records.isNotEmpty() }
        return collector.snapshot().records.single()
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L)
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(5L)
        assertTrue("Timed out waiting for payload collector", condition())
    }

    private class MutableClock(@Volatile var value: Long) : EpochClock {
        override fun nowMillis(): Long = value
    }
}
