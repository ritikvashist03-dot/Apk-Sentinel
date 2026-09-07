package app.apksentinel.mobile

import app.apksentinel.networkmonitor.DnsNameHandling
import app.apksentinel.networkmonitor.DnsNameKey
import app.apksentinel.networkmonitor.DomainBindingRegistry
import app.apksentinel.networkmonitor.NetworkMonitorRuntime

/**
 * Answers a domain firewall rule from what the active session actually observed.
 *
 * Until now this contract had no implementation, so [DomainDestinationSecurity] always
 * took its `AUTHENTICATED_RECEIVER_CONTRACT_MISSING` branch and a domain rule could never
 * become active — the user could type a host and save it, and nothing could ever match.
 * The missing piece was not this class but the evidence: the packet parser stopped at the
 * DNS question and never read answer records, so no observed address existed to bind to.
 *
 * It deliberately performs NO lookup of its own. Resolving independently would return
 * whatever this device's resolver answers now, which can differ from the address the
 * monitored app is actually talking to — that would both miss real traffic and block
 * unrelated traffic. A binding is only claimed when this session watched the resolution.
 */
internal class ObservedDomainReceiver(
    private val registry: DomainBindingRegistry,
    private val handling: DnsNameHandling,
    private val nowMillis: () -> Long = System::currentTimeMillis,
) : AuthenticatedDomainReceiver {

    override fun resolveAndPin(domain: String): Set<String> {
        val key = DnsNameKey.forQuery(domain, handling) ?: return emptySet()
        return registry.addressesFor(key, nowMillis())
    }

    /**
     * True only when every address still corresponds to a live observed binding. A pin
     * that has since expired is not authenticated any more, so enforcement stops rather
     * than continuing against a stale address.
     */
    override fun isAuthenticatedAndBound(domain: String, addresses: Set<String>): Boolean {
        if (addresses.isEmpty()) return false
        val key = DnsNameKey.forQuery(domain, handling) ?: return false
        val observed = registry.addressesFor(key, nowMillis())
        return observed.isNotEmpty() && observed.containsAll(addresses)
    }

    override fun ttlSeconds(domain: String): Long {
        val key = DnsNameKey.forQuery(domain, handling) ?: return 0L
        return registry.remainingTtlSeconds(key, nowMillis())
    }
}

/**
 * Builds a receiver for the running session, or null when there is nothing to bind
 * against — no active session, or DNS name capture is switched off entirely.
 */
internal object ObservedDomainReceivers {
    fun current(): AuthenticatedDomainReceiver? {
        val registry = NetworkMonitorRuntime.currentDomainBindings() ?: return null
        val handling = NetworkMonitorRuntime.currentDnsNameHandling() ?: return null
        if (handling is DnsNameHandling.Omit) return null
        return ObservedDomainReceiver(registry, handling)
    }
}
