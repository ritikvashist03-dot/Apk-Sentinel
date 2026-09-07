package app.apksentinel.networkmonitor

/** Neutral, deterministic review cues. These are not threat or malware verdicts. */
enum class NetworkReviewIndicatorCode {
    UNKNOWN_ATTRIBUTION,
    REPEATED_BLOCKS,
    REVIEWED_HIGH_VOLUME,
    MANY_DESTINATIONS,
    PARSER_LIMITATION,
}

data class NetworkReviewIndicator(
    val code: NetworkReviewIndicatorCode,
    val count: Long,
)

data class NetworkReviewThresholds(
    val highVolumePackets: Long = 100L,
    val manyDestinations: Int = 10,
    val repeatedBlocks: Int = 2,
) {
    init {
        require(highVolumePackets > 0L) { "High-volume threshold must be positive." }
        require(manyDestinations > 0) { "Destination threshold must be positive." }
        require(repeatedBlocks > 0) { "Repeated-block threshold must be positive." }
    }
}

/** Pure review math over bounded metadata snapshots. No network, persistence, or classification calls. */
object NetworkReviewAnalyzer {
    fun indicators(
        flows: Iterable<NetworkFlow>,
        events: Iterable<NetworkEvent>,
        protocolEvidence: ProtocolEvidenceSnapshot = ProtocolEvidenceSnapshot(),
        thresholds: NetworkReviewThresholds = NetworkReviewThresholds(),
    ): List<NetworkReviewIndicator> {
        val flowList = flows.toList()
        val eventList = events.toList()
        val unknownAttribution = flowList.count { it.attribution is AppAttribution.Unknown }.toLong()
        val blocked = eventList.count {
            it is FirewallDecisionEvent &&
                it.decision.requestedAction == FirewallAction.BLOCK &&
                it.decision.enforcement == FirewallEnforcementState.CONFIRMED_BLOCKED
        }
        val packetCount = flowList.fold(0L) { total, flow -> saturatingAdd(total, flow.packetCount) }
        val destinations = flowList.map { it.key.destination.address }.toSet().size
        val packetParserLimitations = eventList.sumOf { event ->
            when (event) {
                is PacketObservedEvent -> event.metadata.notes.size
                is PacketParseFailureEvent -> 1
                else -> 0
            }
        }
        val limitationCount = packetParserLimitations +
            protocolEvidence.observations.count { it.limitations.isNotEmpty() } +
            protocolEvidence.sessionLimitations.count { it != ProtocolEvidenceLimitation.DISABLED_BY_SESSION }

        return buildList {
            if (unknownAttribution > 0L) add(NetworkReviewIndicator(NetworkReviewIndicatorCode.UNKNOWN_ATTRIBUTION, unknownAttribution))
            if (blocked >= thresholds.repeatedBlocks) add(NetworkReviewIndicator(NetworkReviewIndicatorCode.REPEATED_BLOCKS, blocked.toLong()))
            if (packetCount >= thresholds.highVolumePackets) add(NetworkReviewIndicator(NetworkReviewIndicatorCode.REVIEWED_HIGH_VOLUME, packetCount))
            if (destinations >= thresholds.manyDestinations) add(NetworkReviewIndicator(NetworkReviewIndicatorCode.MANY_DESTINATIONS, destinations.toLong()))
            if (limitationCount > 0) add(NetworkReviewIndicator(NetworkReviewIndicatorCode.PARSER_LIMITATION, limitationCount.toLong()))
        }
    }

    private fun saturatingAdd(left: Long, right: Long): Long =
        if (right > 0L && left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right
}
