package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkReviewIndicatorsTest {
    @Test
    fun indicatorsAreNeutralDeterministicAndThresholded() {
        val flows = (0 until 3).map { index ->
            NetworkFlow(
                id = "flow-$index",
                key = NetworkFlowKey(
                    ipVersion = IpVersion.IPV4,
                    protocol = TransportProtocol.TCP,
                    source = NetworkEndpoint("10.0.0.2", 40_000 + index),
                    destination = NetworkEndpoint("203.0.113.${index + 1}", 443),
                    direction = PacketDirection.OUTBOUND,
                ),
                attribution = if (index == 0) AppAttribution.Unknown(AttributionUnavailableReason.NOT_ATTEMPTED)
                else AppAttribution.Known("app.example.test"),
                direction = PacketDirection.OUTBOUND,
                startedAtMillis = index.toLong(),
                lastSeenAtMillis = index.toLong(),
                packetCount = 40L,
                observedBytes = 400L,
            )
        }
        val block = FirewallDecisionEvent(
            sessionId = "session",
            atMillis = 1L,
            flowId = "flow-0",
            decision = FirewallDecision(
                directiveId = "directive",
                requestedAction = FirewallAction.BLOCK,
                reason = FirewallDecisionReason.MATCHED_BLOCK_RULE,
                enforcement = FirewallEnforcementState.CONFIRMED_BLOCKED,
                matchedRuleId = "rule",
            ),
        )
        val indicators = NetworkReviewAnalyzer.indicators(
            flows = flows,
            events = listOf(block, block),
            protocolEvidence = ProtocolEvidenceSnapshot(
                enabledForSession = true,
                sessionLimitations = emptySet(),
                observations = listOf(
                    ProtocolEvidenceObservation(
                        source = ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST,
                        direction = PacketDirection.OUTBOUND,
                        observedAtMillis = 2L,
                        confidence = ProtocolEvidenceConfidence.LIMITED,
                        value = null,
                        limitations = setOf(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE),
                    ),
                ),
            ),
            thresholds = NetworkReviewThresholds(highVolumePackets = 100L, manyDestinations = 3, repeatedBlocks = 2),
        )

        assertEquals(
            listOf(
                NetworkReviewIndicatorCode.UNKNOWN_ATTRIBUTION,
                NetworkReviewIndicatorCode.REPEATED_BLOCKS,
                NetworkReviewIndicatorCode.REVIEWED_HIGH_VOLUME,
                NetworkReviewIndicatorCode.MANY_DESTINATIONS,
                NetworkReviewIndicatorCode.PARSER_LIMITATION,
            ),
            indicators.map(NetworkReviewIndicator::code),
        )
        assertTrue(indicators.all { it.code != NetworkReviewIndicatorCode.UNKNOWN_ATTRIBUTION || it.count == 1L })
    }
}
