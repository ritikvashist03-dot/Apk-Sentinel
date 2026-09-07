package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainCollectorTest {
    private val handling = DnsNameHandling.HashPerSession("collector-salt")

    @Test
    fun groupsTheAddressesOneDomainResolvedTo() {
        val registry = DomainBindingRegistry()
        registry.observe(response("cdn.example", listOf(answer("1.1.1.1", 300), answer("1.1.1.2", 300))), 0)

        val groups = DomainCollector.collect(registry, handling, atMillis = 1_000)

        assertEquals(1, groups.size)
        assertEquals(listOf("1.1.1.1", "1.1.1.2"), groups.single().addresses)
    }

    @Test
    fun anObservedOnlyGroupIsNotGivenAName() {
        val registry = DomainBindingRegistry()
        registry.observe(response("private.example", listOf(answer("10.0.0.1", 60))), 0)

        val group = DomainCollector.collect(registry, handling, atMillis = 0).single()

        // The observed name exists only as a per-session hash, so no name is asserted.
        assertNull(group.displayName)
        assertEquals(DomainDestinationSource.OBSERVED, group.source)
    }

    @Test
    fun aUserEnteredDomainNamesTheGroupItAlreadyMatched() {
        val registry = DomainBindingRegistry()
        registry.observe(response("shop.example", listOf(answer("203.0.113.7", 120))), 0)

        val group = DomainCollector.collect(
            registry = registry,
            handling = handling,
            userDomains = listOf("SHOP.example."),
            atMillis = 0,
        ).single()

        assertEquals("shop.example", group.displayName)
        assertEquals(DomainDestinationSource.USER_ENTERED, group.source)
    }

    @Test
    fun aUserEnteredDomainNeverInventsAGroupThatWasNotObserved() {
        val registry = DomainBindingRegistry()
        registry.observe(response("seen.example", listOf(answer("1.2.3.4", 60))), 0)

        val groups = DomainCollector.collect(
            registry = registry,
            handling = handling,
            userDomains = listOf("never-seen.example"),
            atMillis = 0,
        )

        assertEquals(1, groups.size)
        assertEquals("seen.example", groups.single().displayName ?: "seen.example")
        assertTrue(groups.none { it.addresses.isEmpty() })
    }

    @Test
    fun expiredBindingsDropOutOfTheCollection() {
        val registry = DomainBindingRegistry()
        registry.observe(response("brief.example", listOf(answer("1.2.3.4", 5))), 0)

        assertTrue(DomainCollector.collect(registry, handling, atMillis = 4_000).isNotEmpty())
        assertTrue(DomainCollector.collect(registry, handling, atMillis = 6_000).isEmpty())
    }

    @Test
    fun namedGroupsSortFirstAndTheResultStaysBounded() {
        val registry = DomainBindingRegistry()
        repeat(5) { index ->
            registry.observe(response("host$index.example", listOf(answer("10.0.0.$index", 600))), 0)
        }

        val groups = DomainCollector.collect(
            registry = registry,
            handling = handling,
            userDomains = listOf("host3.example"),
            atMillis = 0,
            maximumGroups = 3,
        )

        assertEquals(3, groups.size)
        assertEquals("host3.example", groups.first().displayName)
    }

    private fun answer(address: String, ttl: Long) =
        DnsAnswerRecord(address = address, ttlSeconds = ttl, isIpv6 = false)

    private fun response(name: String, answers: List<DnsAnswerRecord>) = DnsMetadata(
        messageKind = DnsMessageKind.RESPONSE,
        transactionId = 1,
        questionCount = 1,
        responseCode = 0,
        questionName = SafeDnsName.Hashed(DnsNameKey.hash(name, handling.salt), labelCount = 2),
        questionType = 1,
        status = DnsParseStatus.PARSED,
        answers = answers,
    )
}
