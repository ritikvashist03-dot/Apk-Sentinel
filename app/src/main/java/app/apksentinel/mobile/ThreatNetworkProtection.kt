package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.engine.threatintel.IndicatorType
import app.apksentinel.engine.threatintel.ThreatConfidence
import app.apksentinel.engine.threatintel.VerifiedThreatFeed
import app.apksentinel.networkmonitor.FirewallAction
import app.apksentinel.networkmonitor.FirewallRule
import app.apksentinel.networkmonitor.InMemoryFirewallRuleProvider
import app.apksentinel.networkmonitor.IpCidr
import app.apksentinel.networkmonitor.MonitorLifecycleState
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import java.security.MessageDigest

internal data class ThreatNetworkProtectionSnapshot(
    val enabled: Boolean = false,
    val activeRuleCount: Int = 0,
    val eligibleIndicatorCount: Int = 0,
    val truncated: Boolean = false,
    val feedAvailable: Boolean = false,
    val pendingUntilNextSession: Boolean = false,
)

/**
 * Explicitly opted-in, exact-IP-only threat-feed protection. Host indicators
 * are never inferred from packets, and feed matches remain evidence rather
 * than a general malware verdict. Provider mutation is refused while the VPN
 * is active so an established session cannot change policy silently.
 */
internal object ThreatNetworkProtectionComposition {
    private const val PREFERENCES = "threat_network_protection"
    private const val ENABLED = "enabled"
    private val lock = Any()
    private var initialized = false
    private val provider = InMemoryFirewallRuleProvider()
    private var snapshot = ThreatNetworkProtectionSnapshot()

    fun initialize(context: Context): ThreatNetworkProtectionSnapshot = synchronized(lock) {
        if (!initialized) {
            NetworkMonitorRuntime.addFirewallRuleProviderForFutureSessions(provider)
            initialized = true
        }
        refreshLocked(context.applicationContext)
    }

    fun current(context: Context): ThreatNetworkProtectionSnapshot = synchronized(lock) {
        if (!initialized) initialize(context) else snapshot
    }

    fun setEnabled(context: Context, enabled: Boolean): Boolean = synchronized(lock) {
        val saved = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(ENABLED, enabled)
            .commit()
        if (saved) refreshLocked(context.applicationContext)
        saved
    }

    /** Call immediately before creating a new monitor request. */
    fun refreshForNextSession(context: Context): ThreatNetworkProtectionSnapshot = synchronized(lock) {
        if (!initialized) {
            NetworkMonitorRuntime.addFirewallRuleProviderForFutureSessions(provider)
            initialized = true
        }
        refreshLocked(context.applicationContext)
    }

    fun erase(context: Context): Boolean = synchronized(lock) {
        if (NetworkMonitorRuntime.currentStatus().state != MonitorLifecycleState.STOPPED) return false
        provider.replace(emptyList())
        val erased = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        if (erased) snapshot = ThreatNetworkProtectionSnapshot()
        erased
    }

    private fun refreshLocked(context: Context): ThreatNetworkProtectionSnapshot {
        val enabled = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).getBoolean(ENABLED, false)
        val feed = ThreatIntelManager(context).activeFeed()
        val built = feed?.let(ThreatNetworkRuleBuilder::build) ?: ThreatNetworkRuleBuild()
        val stopped = NetworkMonitorRuntime.currentStatus().state == MonitorLifecycleState.STOPPED
        if (stopped) provider.replace(if (enabled) built.rules else emptyList())
        snapshot = ThreatNetworkProtectionSnapshot(
            enabled = enabled,
            activeRuleCount = if (stopped) provider.snapshot().size else snapshot.activeRuleCount,
            eligibleIndicatorCount = built.eligibleIndicatorCount,
            truncated = built.truncated,
            feedAvailable = feed != null,
            pendingUntilNextSession = !stopped,
        )
        return snapshot
    }
}

internal data class ThreatNetworkRuleBuild(
    val rules: List<FirewallRule> = emptyList(),
    val eligibleIndicatorCount: Int = 0,
    val truncated: Boolean = false,
)

internal object ThreatNetworkRuleBuilder {
    const val MAX_RULES = 512

    fun build(feed: VerifiedThreatFeed): ThreatNetworkRuleBuild {
        val eligible = feed.indicators.asSequence()
            .filter { it.type == IndicatorType.IP && it.confidence == ThreatConfidence.HIGH }
            .distinctBy { it.value }
            .sortedBy { it.value }
            .toList()
        val rules = eligible.take(MAX_RULES).mapNotNull { indicator ->
            val prefix = if (indicator.value.contains(':')) 128 else 32
            val cidr = IpCidr.parse("${indicator.value}/$prefix") ?: return@mapNotNull null
            FirewallRule(
                id = "threat.${sha256(indicator.value).take(24)}",
                action = FirewallAction.BLOCK,
                priority = 20_000,
                destinationCidrs = setOf(cidr),
            )
        }
        return ThreatNetworkRuleBuild(
            rules = rules,
            eligibleIndicatorCount = eligible.size,
            truncated = eligible.size > MAX_RULES,
        )
    }

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}
