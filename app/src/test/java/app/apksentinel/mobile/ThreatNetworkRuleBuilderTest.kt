package app.apksentinel.mobile

import app.apksentinel.engine.threatintel.IndicatorType
import app.apksentinel.engine.threatintel.ThreatConfidence
import app.apksentinel.engine.threatintel.ThreatIndicator
import app.apksentinel.engine.threatintel.VerifiedThreatFeed
import app.apksentinel.networkmonitor.FirewallAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatNetworkRuleBuilderTest {
    @Test fun `only high confidence exact IP indicators become bounded block rules`() {
        val indicators = buildList {
            add(indicator(IndicatorType.HOST, "bad.example", ThreatConfidence.HIGH))
            add(indicator(IndicatorType.IP, "192.0.2.1", ThreatConfidence.LOW))
            add(indicator(IndicatorType.IP, "192.0.2.2", ThreatConfidence.HIGH))
            add(indicator(IndicatorType.IP, "2001:db8::1", ThreatConfidence.HIGH))
            repeat(ThreatNetworkRuleBuilder.MAX_RULES + 4) { add(indicator(IndicatorType.IP, "198.51.${it / 250}.${it % 250}", ThreatConfidence.HIGH)) }
        }

        val result = ThreatNetworkRuleBuilder.build(feed(indicators))

        assertEquals(ThreatNetworkRuleBuilder.MAX_RULES, result.rules.size)
        assertTrue(result.truncated)
        assertTrue(result.eligibleIndicatorCount > result.rules.size)
        assertTrue(result.rules.all { it.action == FirewallAction.BLOCK })
        assertTrue(result.rules.all { it.destinationCidrs.size == 1 })
        assertFalse(result.rules.any { it.domainNames.isNotEmpty() })
    }

    @Test fun `duplicate exact IPs produce one rule`() {
        val same = indicator(IndicatorType.IP, "203.0.113.7", ThreatConfidence.HIGH)
        assertEquals(1, ThreatNetworkRuleBuilder.build(feed(listOf(same, same))).rules.size)
    }

    private fun indicator(type: IndicatorType, value: String, confidence: ThreatConfidence) =
        ThreatIndicator(type, value, "test", confidence, "evidence")

    private fun feed(indicators: List<ThreatIndicator>) = VerifiedThreatFeed(
        version = 1,
        issuedAtMillis = 1,
        expiresAtMillis = Long.MAX_VALUE,
        keyId = "test",
        indicators = indicators,
        payloadSha256 = "0".repeat(64),
    )
}
