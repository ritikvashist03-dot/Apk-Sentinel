package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainBindingRegistryTest {

    @Test
    fun bindsAnObservedResponseToTheDomainTheUserWouldType() {
        val handling = DnsNameHandling.HashPerSession("session-salt")
        val registry = DomainBindingRegistry()
        // The observed name is hashed, exactly as the parser would emit it.
        registry.observe(response("example.com", handling, listOf(answer("93.184.216.34", 300))), atMillis = 0)

        // A rule names the host in plain text; it reduces to the same key.
        val key = requireNotNull(DnsNameKey.forQuery("EXAMPLE.com.", handling))
        assertEquals(setOf("93.184.216.34"), registry.addressesFor(key, atMillis = 1_000))
    }

    @Test
    fun aBindingStopsCountingOnceItsTtlHasPassed() {
        val handling = DnsNameHandling.HashPerSession("s")
        val registry = DomainBindingRegistry()
        registry.observe(response("short.example", handling, listOf(answer("10.0.0.1", 5))), atMillis = 0)
        val key = requireNotNull(DnsNameKey.forQuery("short.example", handling))

        assertEquals(setOf("10.0.0.1"), registry.addressesFor(key, atMillis = 4_000))
        assertTrue(registry.addressesFor(key, atMillis = 5_001).isEmpty())
    }

    @Test
    fun aQueryNeverCreatesABinding() {
        val handling = DnsNameHandling.HashPerSession("s")
        val registry = DomainBindingRegistry()
        registry.observe(
            DnsMetadata(
                messageKind = DnsMessageKind.QUERY,
                transactionId = 1,
                questionCount = 1,
                responseCode = null,
                questionName = SafeDnsName.Hashed(DnsNameKey.hash("example.com", "s"), labelCount = 2),
                questionType = 1,
                status = DnsParseStatus.PARSED,
                answers = listOf(answer("1.2.3.4", 60)),
            ),
            atMillis = 0,
        )
        assertEquals(0, registry.boundDomainCount())
    }

    @Test
    fun omittedNameCaptureCannotProduceAKeyOrABinding() {
        val registry = DomainBindingRegistry()
        registry.observe(
            DnsMetadata(
                messageKind = DnsMessageKind.RESPONSE,
                transactionId = 1,
                questionCount = 1,
                responseCode = 0,
                questionName = SafeDnsName.NotCaptured,
                questionType = 1,
                status = DnsParseStatus.PARSED,
                answers = listOf(answer("1.2.3.4", 60)),
            ),
            atMillis = 0,
        )
        assertEquals(0, registry.boundDomainCount())
        assertNull(DnsNameKey.forQuery("example.com", DnsNameHandling.Omit))
    }

    @Test
    fun theDomainMapStaysBoundedAndEvictsOldestFirst() {
        val handling = DnsNameHandling.HashPerSession("s")
        val registry = DomainBindingRegistry(maximumDomains = 3)
        listOf("a.test", "b.test", "c.test", "d.test").forEachIndexed { index, host ->
            registry.observe(response(host, handling, listOf(answer("10.0.0.$index", 600))), atMillis = index.toLong())
        }

        assertEquals(3, registry.boundDomainCount())
        val oldest = requireNotNull(DnsNameKey.forQuery("a.test", handling))
        assertTrue(registry.addressesFor(oldest, atMillis = 10).isEmpty())
        val newest = requireNotNull(DnsNameKey.forQuery("d.test", handling))
        assertEquals(setOf("10.0.0.3"), registry.addressesFor(newest, atMillis = 10))
    }

    @Test
    fun aHostileTtlIsClampedRatherThanTrusted() {
        val handling = DnsNameHandling.HashPerSession("s")
        val registry = DomainBindingRegistry()
        registry.observe(response("forever.test", handling, listOf(answer("10.0.0.9", 4_000_000_000L))), atMillis = 0)
        val key = requireNotNull(DnsNameKey.forQuery("forever.test", handling))

        // Clamped to 86_400s, so it must be gone a day and a second later.
        assertEquals(setOf("10.0.0.9"), registry.addressesFor(key, atMillis = 86_399_000))
        assertTrue(registry.addressesFor(key, atMillis = 86_401_000).isEmpty())
    }

    private fun answer(address: String, ttl: Long) =
        DnsAnswerRecord(address = address, ttlSeconds = ttl, isIpv6 = address.contains(':'))

    private fun response(
        name: String,
        handling: DnsNameHandling.HashPerSession,
        answers: List<DnsAnswerRecord>,
    ) = DnsMetadata(
        messageKind = DnsMessageKind.RESPONSE,
        transactionId = 1,
        questionCount = 1,
        responseCode = 0,
        questionName = SafeDnsName.Hashed(DnsNameKey.hash(name, handling.salt), labelCount = name.count { it == '.' } + 1),
        questionType = 1,
        status = DnsParseStatus.PARSED,
        answers = answers,
    )
}
