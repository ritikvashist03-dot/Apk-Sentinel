package app.apksentinel.mobile

import app.apksentinel.networkmonitor.FirewallPolicyAction
import app.apksentinel.networkmonitor.FirewallPolicyRule
import app.apksentinel.networkmonitor.FirewallPolicySafetyMode
import org.junit.Assert.assertEquals
import org.junit.Test

class DomainDestinationSecurityTest {
    @Test
    fun setupOnlyDomainHasNoFunctionalDestinationClaim() {
        val rule = domainRule()
        val result = DomainDestinationSecurity.resolveForPolicy(rule, authenticatedReceiver = null)
        assertEquals(
            DomainDestinationUnavailableReason.AUTHENTICATED_RECEIVER_CONTRACT_MISSING,
            (result as DomainDestinationResolution.Unavailable).reason,
        )
    }

    @Test
    fun receiverAddressesAreAcceptedOnlyWhenNumericAndPinned() {
        val rule = domainRule()
        val receiver = object : AuthenticatedDomainReceiver {
            override fun resolveAndPin(domain: String): Set<String> = setOf("192.0.2.4", "not-an-address")
            override fun isAuthenticatedAndBound(domain: String, addresses: Set<String>): Boolean = true
            override fun ttlSeconds(domain: String): Long = 90
        }
        val result = DomainDestinationSecurity.resolveForPolicy(rule, receiver)
        assertEquals(setOf("192.0.2.4"), (result as DomainDestinationResolution.Resolved).addresses)
        assertEquals(90L, result.ttlSeconds)
    }

    private fun domainRule(): FirewallPolicyRule = FirewallPolicyRule(
        id = "domain",
        action = FirewallPolicyAction.BLOCK,
        priority = 0,
        enabled = true,
        appUids = emptySet(),
        appPackageNames = setOf("com.example.app"),
        destinationCidrs = emptySet(),
        domainNames = setOf("example.test"),
        protocols = emptySet(),
        destinationPortRange = null,
        expiresAtMillis = null,
        unsupportedScopes = emptySet(),
        safetyMode = FirewallPolicySafetyMode.ATTRIBUTED_APP_ONLY,
    )
}
