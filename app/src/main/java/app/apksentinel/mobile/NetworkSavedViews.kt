package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.networkmonitor.AppAttribution
import app.apksentinel.networkmonitor.FirewallDecisionEvent
import app.apksentinel.networkmonitor.FirewallEnforcementState
import app.apksentinel.networkmonitor.PacketDirection
import app.apksentinel.networkmonitor.PacketObservedEvent
import app.apksentinel.networkmonitor.TransportProtocol

internal enum class NetworkFilterDirection { ANY, OUTBOUND, INBOUND, UNKNOWN }
internal enum class NetworkFilterProtocol { ANY, TCP, UDP, ICMP, OTHER }
internal enum class NetworkFilterAttribution { ANY, KNOWN, UNKNOWN }
internal enum class NetworkFilterDecision { ANY, BLOCKED, ALLOWED, UNKNOWN }

internal data class NetworkFlowFilter(
    val direction: NetworkFilterDirection = NetworkFilterDirection.ANY,
    val protocol: NetworkFilterProtocol = NetworkFilterProtocol.ANY,
    val attribution: NetworkFilterAttribution = NetworkFilterAttribution.ANY,
    val decision: NetworkFilterDecision = NetworkFilterDecision.ANY,
) {
    fun matches(event: PacketObservedEvent, decisionState: FirewallEnforcementState?): Boolean =
        matchesDirection(event.direction) &&
            matchesProtocol(event.metadata.transportProtocol) &&
            matchesAttribution(event.attribution) &&
            matchesDecision(decisionState)

    private fun matchesDirection(value: PacketDirection): Boolean = when (direction) {
        NetworkFilterDirection.ANY -> true
        NetworkFilterDirection.OUTBOUND -> value == PacketDirection.OUTBOUND
        NetworkFilterDirection.INBOUND -> value == PacketDirection.INBOUND
        NetworkFilterDirection.UNKNOWN -> value == PacketDirection.UNKNOWN
    }

    private fun matchesProtocol(value: TransportProtocol): Boolean = when (protocol) {
        NetworkFilterProtocol.ANY -> true
        NetworkFilterProtocol.TCP -> value == TransportProtocol.TCP
        NetworkFilterProtocol.UDP -> value == TransportProtocol.UDP
        NetworkFilterProtocol.ICMP -> value == TransportProtocol.ICMPV4 || value == TransportProtocol.ICMPV6
        NetworkFilterProtocol.OTHER -> value == TransportProtocol.OTHER
    }

    private fun matchesAttribution(value: AppAttribution): Boolean = when (attribution) {
        NetworkFilterAttribution.ANY -> true
        NetworkFilterAttribution.KNOWN -> value is AppAttribution.Known
        NetworkFilterAttribution.UNKNOWN -> value is AppAttribution.Unknown
    }

    private fun matchesDecision(value: FirewallEnforcementState?): Boolean = when (decision) {
        NetworkFilterDecision.ANY -> true
        NetworkFilterDecision.BLOCKED -> value == FirewallEnforcementState.CONFIRMED_BLOCKED
        NetworkFilterDecision.ALLOWED -> value == FirewallEnforcementState.CONFIRMED_ALLOWED
        NetworkFilterDecision.UNKNOWN -> value == null || value !in setOf(
            FirewallEnforcementState.CONFIRMED_BLOCKED,
            FirewallEnforcementState.CONFIRMED_ALLOWED,
        )
    }
}

internal enum class NetworkFilterParseFailure { TOO_LONG, TOO_MANY_TERMS, UNKNOWN_TERM, DUPLICATE_TERM }

internal sealed interface NetworkFilterParseResult {
    data class Success(val filter: NetworkFlowFilter, val canonicalExpression: String) : NetworkFilterParseResult
    data class Failure(val reason: NetworkFilterParseFailure) : NetworkFilterParseResult
}

internal object NetworkFilterParser {
    const val MAX_EXPRESSION_CODE_POINTS = 120
    private const val MAX_TERMS = 4

    fun parse(input: String): NetworkFilterParseResult {
        val trimmed = input.trim()
        if (trimmed.codePointCount(0, trimmed.length) > MAX_EXPRESSION_CODE_POINTS) {
            return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.TOO_LONG)
        }
        if (trimmed.isEmpty() || trimmed.equals("all", ignoreCase = true)) {
            return NetworkFilterParseResult.Success(NetworkFlowFilter(), "all")
        }
        val terms = trimmed.lowercase(java.util.Locale.ROOT).split(Regex("\\s+")).filter(String::isNotBlank)
        if (terms.size > MAX_TERMS) return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.TOO_MANY_TERMS)
        val seen = mutableSetOf<String>()
        var filter = NetworkFlowFilter()
        for (term in terms) {
            val parts = term.split(':', limit = 2)
            if (parts.size != 2 || !seen.add(parts[0])) {
                return NetworkFilterParseResult.Failure(
                    if (parts.size == 2) NetworkFilterParseFailure.DUPLICATE_TERM else NetworkFilterParseFailure.UNKNOWN_TERM,
                )
            }
            filter = when (parts[0]) {
                "direction" -> filter.copy(direction = when (parts[1]) {
                    "out" -> NetworkFilterDirection.OUTBOUND
                    "in" -> NetworkFilterDirection.INBOUND
                    "unknown" -> NetworkFilterDirection.UNKNOWN
                    "any" -> NetworkFilterDirection.ANY
                    else -> return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.UNKNOWN_TERM)
                })
                "protocol" -> filter.copy(protocol = when (parts[1]) {
                    "tcp" -> NetworkFilterProtocol.TCP
                    "udp" -> NetworkFilterProtocol.UDP
                    "icmp" -> NetworkFilterProtocol.ICMP
                    "other" -> NetworkFilterProtocol.OTHER
                    "any" -> NetworkFilterProtocol.ANY
                    else -> return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.UNKNOWN_TERM)
                })
                "app" -> filter.copy(attribution = when (parts[1]) {
                    "known" -> NetworkFilterAttribution.KNOWN
                    "unknown" -> NetworkFilterAttribution.UNKNOWN
                    "any" -> NetworkFilterAttribution.ANY
                    else -> return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.UNKNOWN_TERM)
                })
                "decision" -> filter.copy(decision = when (parts[1]) {
                    "blocked" -> NetworkFilterDecision.BLOCKED
                    "allowed" -> NetworkFilterDecision.ALLOWED
                    "unknown" -> NetworkFilterDecision.UNKNOWN
                    "any" -> NetworkFilterDecision.ANY
                    else -> return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.UNKNOWN_TERM)
                })
                else -> return NetworkFilterParseResult.Failure(NetworkFilterParseFailure.UNKNOWN_TERM)
            }
        }
        return NetworkFilterParseResult.Success(filter, terms.joinToString(" "))
    }
}

internal data class SavedNetworkView(val name: String, val expression: String)

/** Persists categorical expressions only; endpoint/package search text is never stored. */
internal class SavedNetworkViewStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun load(): List<SavedNetworkView> {
        val count = preferences.getInt(COUNT, 0).coerceIn(0, MAX_VIEWS)
        return (0 until count).mapNotNull { index ->
            val name = preferences.getString("name_$index", null) ?: return@mapNotNull null
            val expression = preferences.getString("expression_$index", null) ?: return@mapNotNull null
            if (!validName(name) || NetworkFilterParser.parse(expression) !is NetworkFilterParseResult.Success) null
            else SavedNetworkView(name, expression)
        }.distinctBy { it.name.lowercase(java.util.Locale.ROOT) }.take(MAX_VIEWS)
    }

    fun save(view: SavedNetworkView): Boolean {
        if (!validName(view.name)) return false
        val parsed = NetworkFilterParser.parse(view.expression) as? NetworkFilterParseResult.Success ?: return false
        val updated = (load().filterNot { it.name.equals(view.name, ignoreCase = true) } +
            view.copy(name = view.name.trim(), expression = parsed.canonicalExpression)).takeLast(MAX_VIEWS)
        return replace(updated)
    }

    fun remove(name: String): Boolean = replace(load().filterNot { it.name == name })
    fun clear(): Boolean = preferences.edit().clear().commit()

    private fun replace(views: List<SavedNetworkView>): Boolean {
        val editor = preferences.edit().clear().putInt(COUNT, views.size)
        views.forEachIndexed { index, view ->
            editor.putString("name_$index", view.name).putString("expression_$index", view.expression)
        }
        return editor.commit()
    }

    private fun validName(value: String): Boolean {
        val trimmed = value.trim()
        return trimmed.isNotEmpty() && trimmed.codePointCount(0, trimmed.length) <= MAX_NAME_CODE_POINTS &&
            trimmed.none { it.isISOControl() || it == '\u202A' || it == '\u202B' || it == '\u202D' || it == '\u202E' || it == '\u2066' || it == '\u2067' || it == '\u2068' || it == '\u2069' }
    }

    companion object {
        const val PREFERENCES = "network_saved_views"
        const val MAX_VIEWS = 12
        const val MAX_NAME_CODE_POINTS = 40
        private const val COUNT = "count"
    }
}

internal fun firewallDecisionsByFlow(events: List<app.apksentinel.networkmonitor.NetworkEvent>): Map<String, FirewallEnforcementState> =
    events.filterIsInstance<FirewallDecisionEvent>().mapNotNull { event ->
        event.flowId?.let { it to event.decision.enforcement }
    }.toMap()
