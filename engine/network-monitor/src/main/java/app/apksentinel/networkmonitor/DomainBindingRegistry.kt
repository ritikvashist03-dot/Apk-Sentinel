package app.apksentinel.networkmonitor

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/**
 * The single derivation of a DNS-name lookup key.
 *
 * A firewall rule names a host in plain text, but an observed DNS name is hashed per
 * session by default and must stay that way. Both sides therefore reduce to the same key
 * through this object: the rule's domain is hashed with the session salt, and the observed
 * name already carries that hash. Nothing has to be un-hashed for a rule to match.
 *
 * [PacketMetadataParser] delegates here so there is exactly one hashing implementation —
 * two copies would silently drift and every domain rule would stop matching.
 */
object DnsNameKey {
    const val HASH_PREFIX_HEX_CHARACTERS = 16

    fun hash(name: String, salt: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest((salt + "\u0000" + normalize(name)).toByteArray(StandardCharsets.UTF_8))
        return digest.joinToString(separator = "") { byte -> "%02x".format(Locale.ROOT, byte.toInt() and 0xff) }
            .take(HASH_PREFIX_HEX_CHARACTERS)
    }

    fun normalize(name: String): String = name.trim().trimEnd('.').lowercase(Locale.ROOT)

    /** The key for a domain the user typed, or null when name capture is disabled. */
    fun forQuery(domain: String, handling: DnsNameHandling): String? = when (handling) {
        DnsNameHandling.Omit -> null
        is DnsNameHandling.HashPerSession -> hash(domain, handling.salt)
        DnsNameHandling.PlaintextAfterExplicitConsent -> normalize(domain)
    }

    /** The key for a name the parser observed, or null when nothing usable was captured. */
    fun forObserved(name: SafeDnsName): String? = when (name) {
        SafeDnsName.NotCaptured -> null
        is SafeDnsName.Hashed -> name.sha256Prefix
        is SafeDnsName.PlaintextAfterExplicitConsent -> normalize(name.normalizedName)
    }
}

/** An address this session actually saw a domain resolve to, and when that stops counting. */
data class DomainBinding(
    val address: String,
    val expiresAtMillis: Long,
)

/**
 * Remembers which addresses a domain was observed resolving to, for this session only.
 *
 * This is what lets a domain firewall rule mean anything. The data plane sees addresses,
 * never hostnames, so a rule naming a host can only be enforced against traffic if the
 * app watched the resolution happen and bound the two together. Binding to an OBSERVED
 * answer — rather than performing its own lookup — is the point: an independent lookup
 * could return a different address than the one the app is actually talking to, which
 * would both miss real traffic and block unrelated traffic.
 *
 * Everything is in memory and dies with the session. Entries expire on the answer's own
 * TTL (clamped, since a hostile TTL is attacker-controlled) and the map is bounded with
 * oldest-first eviction.
 */
class DomainBindingRegistry(
    private val maximumDomains: Int = DEFAULT_MAXIMUM_DOMAINS,
    private val maximumAddressesPerDomain: Int = DEFAULT_MAXIMUM_ADDRESSES_PER_DOMAIN,
) {
    private val lock = Any()
    // Insertion-ordered so eviction removes the least recently recorded domain.
    private val bindings = LinkedHashMap<String, MutableList<DomainBinding>>()

    /** Records the A/AAAA answers of an observed DNS response. Queries contribute nothing. */
    fun observe(dns: DnsMetadata?, atMillis: Long) {
        val metadata = dns ?: return
        if (metadata.messageKind != DnsMessageKind.RESPONSE) return
        if (metadata.answers.isEmpty()) return
        val key = DnsNameKey.forObserved(metadata.questionName) ?: return
        synchronized(lock) {
            val existing = bindings.remove(key) ?: ArrayList()
            metadata.answers.forEach { answer ->
                val ttl = answer.ttlSeconds.coerceIn(MINIMUM_TTL_SECONDS, MAXIMUM_TTL_SECONDS)
                existing.removeAll { it.address == answer.address }
                existing.add(DomainBinding(answer.address, atMillis + ttl * 1_000L))
            }
            while (existing.size > maximumAddressesPerDomain) existing.removeAt(0)
            // Re-inserting moves this domain to the newest position.
            bindings[key] = existing
            while (bindings.size > maximumDomains) {
                val oldest = bindings.keys.firstOrNull() ?: break
                bindings.remove(oldest)
            }
        }
    }

    /** Unexpired addresses observed for [nameKey]; empty when nothing is currently bound. */
    fun addressesFor(nameKey: String, atMillis: Long): Set<String> = synchronized(lock) {
        val entries = bindings[nameKey] ?: return emptySet()
        entries.removeAll { it.expiresAtMillis <= atMillis }
        if (entries.isEmpty()) {
            bindings.remove(nameKey)
            return emptySet()
        }
        entries.map(DomainBinding::address).toSet()
    }

    /** The soonest expiry for [nameKey] as a remaining-seconds value, or 0 when unbound. */
    fun remainingTtlSeconds(nameKey: String, atMillis: Long): Long = synchronized(lock) {
        val entries = bindings[nameKey] ?: return 0L
        val soonest = entries.filter { it.expiresAtMillis > atMillis }.minOfOrNull { it.expiresAtMillis }
            ?: return 0L
        ((soonest - atMillis) / 1_000L).coerceAtLeast(1L)
    }

    /** Every currently-live binding, newest domain last. Expired entries are omitted. */
    fun snapshot(atMillis: Long): Map<String, Set<String>> = synchronized(lock) {
        buildMap {
            bindings.forEach { (key, entries) ->
                val live = entries.filter { it.expiresAtMillis > atMillis }
                    .map(DomainBinding::address)
                    .toSet()
                if (live.isNotEmpty()) put(key, live)
            }
        }
    }

    fun clear() = synchronized(lock) { bindings.clear() }

    fun boundDomainCount(): Int = synchronized(lock) { bindings.size }

    private companion object {
        const val DEFAULT_MAXIMUM_DOMAINS = 512
        const val DEFAULT_MAXIMUM_ADDRESSES_PER_DOMAIN = 16
        const val MINIMUM_TTL_SECONDS = 1L
        const val MAXIMUM_TTL_SECONDS = 86_400L
    }
}
