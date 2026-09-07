package app.apksentinel.networkmonitor

/** Where a destination group's identity came from. Never inferred, never looked up. */
enum class DomainDestinationSource {
    /** The user typed this domain, so its name can be shown back to them. */
    USER_ENTERED,

    /** Seen resolving during this session. Its name stays hashed unless consent says otherwise. */
    OBSERVED,
}

/**
 * A set of addresses this session saw one domain resolve to.
 *
 * [displayName] is null whenever the name is only available as a per-session hash — which
 * is the default. That is deliberate: the group is still useful ("these four addresses are
 * one destination") without asserting a name the app cannot honestly show. Nothing here
 * claims the destination belongs to any organisation; it is only what resolved together.
 */
data class DomainDestinationGroup(
    val nameKey: String,
    val displayName: String?,
    val addresses: List<String>,
    val source: DomainDestinationSource,
    val freshnessSeconds: Long,
) {
    init {
        require(nameKey.isNotBlank()) { "A destination group needs a name key." }
        require(addresses.isNotEmpty()) { "A destination group needs at least one address." }
        require(freshnessSeconds >= 0) { "Freshness cannot be negative." }
    }
}

/**
 * Builds bounded destination groups from what the session observed.
 *
 * This is the "domain collector destinations" outcome. It exists so a user can reason
 * about related endpoints — which addresses belong together — without the app performing
 * its own lookups or asserting ownership. Every group is derived from an observed DNS
 * answer; a user-entered domain only supplies a NAME for a group that was already
 * observed, it never invents one.
 */
/**
 * Reports whether every domain in a rule is currently bound to an address this session
 * actually observed resolving.
 *
 * [FirewallPolicyController] takes this capability as an optional constructor argument and
 * defaults it to null, and nothing ever supplied one — so `domainDestinationAvailable`
 * always answered false and every domain rule was permanently marked
 * `UNSUPPORTED_SCOPE`. A user could type a host, save it, and it could never take effect.
 *
 * The strictness is deliberate and matches the parity contract: domain enforcement is
 * available only while packet-bound attribution exists. When the binding expires the rule
 * goes back to unsupported rather than silently enforcing against a stale address.
 */
object ObservedDomainDestinationCapability : AuthenticatedDomainDestinationCapability {
    override fun isAuthenticatedAndPacketBound(domains: Set<String>): Boolean {
        if (domains.isEmpty()) return false
        val registry = NetworkMonitorRuntime.currentDomainBindings() ?: return false
        val handling = NetworkMonitorRuntime.currentDnsNameHandling() ?: return false
        if (handling is DnsNameHandling.Omit) return false
        val now = System.currentTimeMillis()
        return domains.all { domain ->
            val key = DnsNameKey.forQuery(domain, handling)
            key != null && registry.addressesFor(key, now).isNotEmpty()
        }
    }
}

object DomainCollector {
    const val DEFAULT_MAXIMUM_GROUPS = 64

    fun collect(
        registry: DomainBindingRegistry,
        handling: DnsNameHandling,
        userDomains: Collection<String> = emptyList(),
        atMillis: Long,
        maximumGroups: Int = DEFAULT_MAXIMUM_GROUPS,
    ): List<DomainDestinationGroup> {
        if (maximumGroups <= 0) return emptyList()
        val observed = registry.snapshot(atMillis)
        if (observed.isEmpty()) return emptyList()

        // A user-entered domain reduces to the same key an observed name would, so it can
        // name a group without any un-hashing.
        val namesByKey = HashMap<String, String>()
        userDomains.forEach { domain ->
            val key = DnsNameKey.forQuery(domain, handling) ?: return@forEach
            namesByKey.putIfAbsent(key, DnsNameKey.normalize(domain))
        }

        return observed.entries
            .map { (key, addresses) ->
                val named = namesByKey[key]
                DomainDestinationGroup(
                    nameKey = key,
                    displayName = named,
                    addresses = addresses.sorted(),
                    source = if (named != null) {
                        DomainDestinationSource.USER_ENTERED
                    } else {
                        DomainDestinationSource.OBSERVED
                    },
                    freshnessSeconds = registry.remainingTtlSeconds(key, atMillis),
                )
            }
            // Named groups first (the user asked about those), then the freshest evidence.
            .sortedWith(
                compareByDescending<DomainDestinationGroup> { it.displayName != null }
                    .thenByDescending { it.freshnessSeconds },
            )
            .take(maximumGroups)
    }
}
