package app.apksentinel.mobile

import app.apksentinel.networkmonitor.FirewallPolicyRule
import java.net.InetAddress
import java.util.Locale

/**
 * A domain rule is not a DNS lookup instruction. This result makes the
 * destination contract explicit: without an authenticated receiver or a
 * packet-derived, bound DNS observation, no destination pin is claimed.
 */
internal sealed interface DomainDestinationResolution {
    data class Resolved(val domain: String, val addresses: Set<String>, val ttlSeconds: Long) : DomainDestinationResolution
    data class Unavailable(val reason: DomainDestinationUnavailableReason) : DomainDestinationResolution
}

internal enum class DomainDestinationUnavailableReason {
    AUTHENTICATED_RECEIVER_CONTRACT_MISSING,
    DNS_PIN_NOT_BOUND_TO_OBSERVED_FLOW,
    RESOLUTION_FAILED,
}

internal object DomainDestinationSecurity {
    fun resolveForPolicy(
        rule: FirewallPolicyRule,
        authenticatedReceiver: AuthenticatedDomainReceiver?,
    ): DomainDestinationResolution {
        val domain = rule.domainNames.firstOrNull()?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT)
            ?: return DomainDestinationResolution.Unavailable(DomainDestinationUnavailableReason.RESOLUTION_FAILED)
        val receiver = authenticatedReceiver
            ?: return DomainDestinationResolution.Unavailable(DomainDestinationUnavailableReason.AUTHENTICATED_RECEIVER_CONTRACT_MISSING)
        val addresses = runCatching { receiver.resolveAndPin(domain) }.getOrNull()
            ?.filter { isNumericAddress(it) }
            ?.toSet()
            ?.takeIf { it.isNotEmpty() }
            ?: return DomainDestinationResolution.Unavailable(DomainDestinationUnavailableReason.RESOLUTION_FAILED)
        if (!runCatching { receiver.isAuthenticatedAndBound(domain, addresses) }.getOrDefault(false)) {
            return DomainDestinationResolution.Unavailable(DomainDestinationUnavailableReason.DNS_PIN_NOT_BOUND_TO_OBSERVED_FLOW)
        }
        return DomainDestinationResolution.Resolved(domain, addresses, receiver.ttlSeconds(domain).coerceIn(1L, 86_400L))
    }

    private fun isNumericAddress(value: String): Boolean {
        val candidate = value.trim().removePrefix("[").removeSuffix("]")
        if (candidate.count { it == '.' } == 3) {
            val parts = candidate.split('.')
            return parts.size == 4 && parts.all { it.isNotEmpty() && it.length <= 3 && it.toIntOrNull()?.let { octet -> octet in 0..255 } == true }
        }
        // Numeric IPv6 is accepted only when it contains a colon and the
        // characters are hexadecimal separators; this path does not resolve a
        // hostname because no alphabetic hostname characters are permitted.
        if (!candidate.contains(':') || candidate.any { !(it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':') }) return false
        return runCatching { InetAddress.getByName(candidate).address.size == 16 }.getOrDefault(false)
    }
}

/** A receiver must prove how a resolved address is pinned to the authenticated flow. */
internal interface AuthenticatedDomainReceiver {
    fun resolveAndPin(domain: String): Set<String>
    fun isAuthenticatedAndBound(domain: String, addresses: Set<String>): Boolean
    fun ttlSeconds(domain: String): Long
}
