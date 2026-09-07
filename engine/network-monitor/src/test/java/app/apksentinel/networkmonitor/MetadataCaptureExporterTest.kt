package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MetadataCaptureExporterTest {
    @Test
    fun exportIsDeterministicBoundedAndOmitsSensitivePacketMetadata() {
        val events = listOf(packetEvent(), firewallEvent())
        val first = TrackingOutputStream()
        val second = TrackingOutputStream()
        val limits = MetadataCaptureExportLimits(
            maximumEventsExamined = 8,
            maximumRecords = 8,
            maximumBytes = 4 * 1_024,
            maximumRecordBytes = 1_024,
        )

        val firstResult = SafeMetadataCaptureExporter.writeJsonLines(events, first, limits)
        SafeMetadataCaptureExporter.writeJsonLines(events, second, limits)
        val content = first.asUtf8()

        assertEquals(content, second.asUtf8())
        assertEquals(2, firstResult.recordsWritten)
        assertEquals(2, firstResult.eventsExamined)
        assertEquals(first.size(), firstResult.bytesWritten)
        assertFalse(firstResult.truncated)
        assertFalse(firstResult.containsRawPacketBytes)
        assertFalse(firstResult.containsEndpointAddresses)
        assertFalse(firstResult.containsPlaintextDnsNames)
        assertFalse(first.closed)
        assertFalse(second.closed)
        assertTrue(content.contains("\"metadata_source\":{\"id\":0"))
        assertFalse(content.contains("\"capture_interface\""))
        assertTrue(content.contains("\"raw_packet_bytes_retained\":false"))
        assertTrue(content.contains("\"pcapng_packet_export_available\":false"))
        assertTrue(content.contains("\"timestamp_millis\":1700000000123"))
        assertTrue(content.contains("\"record_type\":\"packet_metadata\""))
        assertTrue(content.contains("\"record_type\":\"firewall_decision\""))
        assertFalse(content.contains("192.0.2.10"))
        assertFalse(content.contains("203.0.113.99"))
        assertFalse(content.contains("private.example"))
        assertFalse(content.contains("sensitive-session-id"))
        assertFalse(content.contains("sensitive-flow-id"))
        assertFalse(content.contains("sensitive-rule-id"))
        assertFalse(content.contains("sensitive-directive-id"))
    }

    @Test
    fun exportStopsAtConfiguredRecordCountWithoutAccumulatingTheInput() {
        val output = TrackingOutputStream()
        val result = SafeMetadataCaptureExporter.writeJsonLines(
            events = listOf(packetEvent(), packetEvent(atMillis = 1700000000124L), packetEvent(atMillis = 1700000000125L)),
            output = output,
            limits = MetadataCaptureExportLimits(
                maximumEventsExamined = 3,
                maximumRecords = 1,
                maximumBytes = 4 * 1_024,
                maximumRecordBytes = 1_024,
            ),
        )

        assertEquals(1, result.recordsWritten)
        assertEquals(1, result.eventsExamined)
        assertTrue(result.truncated)
        assertEquals(2, output.asUtf8().lineSequence().filter { it.isNotEmpty() }.count())
    }

    @Test
    fun exportStopsAtConfiguredByteLimit() {
        val output = TrackingOutputStream()
        val result = SafeMetadataCaptureExporter.writeJsonLines(
            events = List(10) { index -> packetEvent(atMillis = 1700000000200L + index) },
            output = output,
            limits = MetadataCaptureExportLimits(
                maximumEventsExamined = 10,
                maximumRecords = 10,
                maximumBytes = 1_024,
                maximumRecordBytes = 1_024,
            ),
        )

        assertTrue(result.truncated)
        assertTrue(result.recordsWritten < 10)
        assertTrue(result.bytesWritten <= 1_024)
        assertEquals(output.size(), result.bytesWritten)
        assertFalse(output.closed)
    }

    @Test
    fun exportDoesNotSerializeFreeFormEventFieldsIntoJsonLines() {
        val hostileText = "attacker-quote-\"-newline-\n-record_type"
        val output = TrackingOutputStream()

        val result = SafeMetadataCaptureExporter.writeJsonLines(
            events = listOf(
                MonitorStateEvent(
                    sessionId = hostileText,
                    atMillis = 1L,
                    state = MonitorLifecycleState.ACTIVE,
                    detail = hostileText,
                ),
                PacketParseFailureEvent(
                    sessionId = hostileText,
                    atMillis = 2L,
                    reason = hostileText,
                ),
                EngineLimitationEvent(
                    sessionId = hostileText,
                    atMillis = 3L,
                    limitation = EngineLimitation(
                        code = EngineLimitationCode.PACKET_PAYLOADS_NOT_PARSED_OR_REVEALED,
                        detail = hostileText,
                    ),
                ),
            ),
            output = output,
        )

        val content = output.asUtf8()
        assertEquals(3, result.recordsWritten)
        assertFalse(content.contains(hostileText))
        assertFalse(content.contains("attacker-quote"))
        assertEquals(4, content.lineSequence().filter { it.isNotEmpty() }.count())
    }

    @Test
    fun exportDoesNotMaterializeOrAdvancePastConfiguredEventPrefix() {
        var nextCalls = 0
        val events = object : Iterable<NetworkEvent> {
            override fun iterator(): Iterator<NetworkEvent> = object : Iterator<NetworkEvent> {
                private var emitted = 0

                override fun hasNext(): Boolean = emitted < 3

                override fun next(): NetworkEvent {
                    nextCalls += 1
                    emitted += 1
                    return packetEvent(atMillis = emitted.toLong())
                }
            }
        }

        val result = SafeMetadataCaptureExporter.writeJsonLines(
            events = events,
            output = TrackingOutputStream(),
            limits = MetadataCaptureExportLimits(
                maximumEventsExamined = 1,
                maximumRecords = 1,
                maximumBytes = 4 * 1_024,
                maximumRecordBytes = 1_024,
            ),
        )

        assertEquals(1, nextCalls)
        assertEquals(1, result.eventsExamined)
        assertTrue(result.truncated)
    }

    private fun packetEvent(atMillis: Long = 1700000000123L): PacketObservedEvent = PacketObservedEvent(
        sessionId = "sensitive-session-id",
        atMillis = atMillis,
        flowId = "sensitive-flow-id",
        direction = PacketDirection.OUTBOUND,
        attribution = AppAttribution.Known("com.example.browser", uid = 10_001),
        metadata = PacketMetadata(
            ipVersion = IpVersion.IPV4,
            ipProtocolNumber = 6,
            transportProtocol = TransportProtocol.TCP,
            source = NetworkEndpoint("192.0.2.10", 50_000),
            destination = NetworkEndpoint("203.0.113.99", 443),
            declaredIpPacketBytes = 60,
            capturedPacketBytes = 60,
            dns = DnsMetadata(
                messageKind = DnsMessageKind.QUERY,
                transactionId = 7,
                questionCount = 1,
                responseCode = null,
                questionName = SafeDnsName.PlaintextAfterExplicitConsent("private.example"),
                questionType = 1,
                status = DnsParseStatus.PARSED,
            ),
            notes = setOf(PacketParserNote.DNS_NOT_PLAINTEXT),
        ),
    )

    private fun firewallEvent(): FirewallDecisionEvent = FirewallDecisionEvent(
        sessionId = "sensitive-session-id",
        atMillis = 1700000000126L,
        flowId = "sensitive-flow-id",
        decision = FirewallDecision(
            directiveId = "sensitive-directive-id",
            requestedAction = FirewallAction.BLOCK,
            matchedRuleId = "sensitive-rule-id",
            reason = FirewallDecisionReason.MATCHED_BLOCK_RULE,
            enforcement = FirewallEnforcementState.PENDING_FORWARDER_CONFIRMATION,
            matchedCriteria = setOf(RuleCriterion.DESTINATION_CIDR),
        ),
    )

    private class TrackingOutputStream : ByteArrayOutputStream() {
        var closed = false

        override fun close() {
            closed = true
            super.close()
        }

        fun asUtf8(): String = String(toByteArray(), StandardCharsets.UTF_8)
    }
}
