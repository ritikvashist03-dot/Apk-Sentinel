package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class OfflineIpAttributionTest {
    private val keyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private val now = 1_000_000L

    @Test
    fun `accepts signed bundle and selects longest IPv4 and IPv6 prefixes`() {
        val payload = bundle(
            entries = listOf(
                "0.0.0.0/0|US|1|Default Network",
                "203.0.113.0/24|IN|64496|Example Transit",
                "203.0.113.128/25|DE|64497|Specific Network",
                "2001:db8::/32|US|64498|IPv6 Registry",
                "2001:db8:abcd::/48|IN|64499|IPv6 Specific",
            ),
        )
        val accepted = verifier().verify(payload, sign(payload), now) as OfflineAttributionLoadResult.Accepted

        val v4 = accepted.lookup.lookup("203.0.113.200") as OfflineIpAttributionResult.Match
        assertEquals("DE", v4.attribution.countryCode)
        assertEquals(25, v4.matchedPrefixLength)
        val v6 = accepted.lookup.lookup("2001:db8:abcd::42") as OfflineIpAttributionResult.Match
        assertEquals("IN", v6.attribution.countryCode)
        assertEquals(48, v6.matchedPrefixLength)
        assertTrue(accepted.lookup.lookup("not-a-literal") is OfflineIpAttributionResult.InvalidLiteral)
    }

    @Test
    fun `rejects wrong signing key signature and expiry`() {
        val payload = bundle(entries = listOf("203.0.113.0/24|IN|64496|Example Transit"))
        val other = newKeyPair()
        assertEquals(
            OfflineAttributionFailure.SIGNATURE_INVALID,
            (verifier().verify(payload, sign(payload, other), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
        assertEquals(
            OfflineAttributionFailure.KEY_UNKNOWN,
            (OfflineIpAttributionVerifier(emptyList()).verify(payload, sign(payload), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
        val expired = bundle(issued = 100, expires = 999_999, entries = listOf("203.0.113.0/24|IN|64496|Example Transit"))
        assertEquals(
            OfflineAttributionFailure.EXPIRED,
            (verifier().verify(expired, sign(expired), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
    }

    @Test
    fun `rejects version and clock rollback through host guard`() {
        val payload = bundle(version = 7, entries = listOf("203.0.113.0/24|IN|64496|Example Transit"))
        val versionGuard = object : OfflineAttributionRollbackGuard {
            override fun highestAcceptedVersion(keyId: String): Long? = 7L
            override fun latestTrustedNowMillis(): Long? = null
        }
        assertEquals(
            OfflineAttributionFailure.VERSION_ROLLBACK,
            (verifier().verify(payload, sign(payload), now, versionGuard) as OfflineAttributionLoadResult.Rejected).reason,
        )
        val clockGuard = object : OfflineAttributionRollbackGuard {
            override fun highestAcceptedVersion(keyId: String): Long? = null
            override fun latestTrustedNowMillis(): Long? = now + 1
        }
        assertEquals(
            OfflineAttributionFailure.CLOCK_ROLLBACK,
            (verifier().verify(payload, sign(payload), now, clockGuard) as OfflineAttributionLoadResult.Rejected).reason,
        )
    }

    @Test
    fun `rejects malformed duplicate and host-bit prefixes without partial activation`() {
        val malformed = "APK_SENTINEL_IP_ATTRIBUTION_V1\r\n"
        assertEquals(
            OfflineAttributionFailure.FORMAT,
            (verifier().verify(malformed.toByteArray(), sign(malformed.toByteArray()), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
        val duplicate = bundle(entries = listOf(
            "203.0.113.0/24|IN|64496|Example Transit",
            "203.0.113.0/24|DE|64497|Other Network",
        ))
        assertEquals(
            OfflineAttributionFailure.DUPLICATE_PREFIX,
            (verifier().verify(duplicate, sign(duplicate), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
        val hostBits = bundle(entries = listOf("203.0.113.7/24|IN|64496|Example Transit"))
        assertEquals(
            OfflineAttributionFailure.INVALID_ENTRY,
            (verifier().verify(hostBits, sign(hostBits), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
    }

    @Test
    fun `enforces declared prefix and payload bounds`() {
        val twoEntries = bundle(entries = listOf(
            "203.0.113.0/24|IN|64496|Example Transit",
            "2001:db8::/32|US|64498|IPv6 Registry",
        ))
        assertEquals(
            OfflineAttributionFailure.ENTRY_LIMIT,
            (verifier(maximumPrefixes = 1).verify(twoEntries, sign(twoEntries), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
        val tooSmall = OfflineIpAttributionVerifier(
            trustedKeys = listOf(signingKey()),
            maximumPayloadBytes = 256,
        )
        val large = bundle(entries = List(10) { index -> "203.0.$index.0/24|IN|64496|Example Transit" })
        assertTrue(large.size > 256)
        assertEquals(
            OfflineAttributionFailure.PAYLOAD_SIZE,
            (tooSmall.verify(large, sign(large), now) as OfflineAttributionLoadResult.Rejected).reason,
        )
    }

    @Test
    fun `background loader keeps old lookup when candidate fails and can clear`() {
        val loader = OfflineIpAttributionLoader(verifier(), clock = EpochClock { now })
        val good = bundle(entries = listOf("203.0.113.0/24|IN|64496|Example Transit"))
        val first = awaitLoad(loader, good, sign(good))
        assertTrue(first is OfflineAttributionLoadResult.Accepted)
        assertTrue(loader.currentLookup().lookup("203.0.113.1") is OfflineIpAttributionResult.Match)
        val rejected = awaitLoad(loader, good, sign(good, newKeyPair()))
        assertEquals(OfflineAttributionFailure.SIGNATURE_INVALID, (rejected as OfflineAttributionLoadResult.Rejected).reason)
        assertTrue(loader.currentLookup().lookup("203.0.113.1") is OfflineIpAttributionResult.Match)
        loader.clear()
        assertTrue(loader.currentLookup().lookup("203.0.113.1") is OfflineIpAttributionResult.Unavailable)
        loader.close()
    }

    private fun awaitLoad(loader: OfflineIpAttributionLoader, payload: ByteArray, signature: String): OfflineAttributionLoadResult {
        val latch = CountDownLatch(1)
        var result: OfflineAttributionLoadResult? = null
        assertTrue(loader.loadInBackground(payload, signature) {
            result = it
            latch.countDown()
        })
        assertTrue(latch.await(2, TimeUnit.SECONDS))
        return requireNotNull(result)
    }

    private fun verifier(maximumPrefixes: Int = 50_000): OfflineIpAttributionVerifier =
        OfflineIpAttributionVerifier(listOf(signingKey()), maximumPrefixes = maximumPrefixes)

    private fun signingKey(): OfflineAttributionSigningKey = OfflineAttributionSigningKey(
        keyId = "test-key",
        x509EcPublicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded),
    )

    private fun bundle(
        version: Long = 7,
        issued: Long = 999_000,
        expires: Long = 1_001_000,
        entries: List<String>,
    ): ByteArray = buildString {
        appendLine("APK_SENTINEL_IP_ATTRIBUTION_V1")
        appendLine("version=$version")
        appendLine("issuedAtMillis=$issued")
        appendLine("expiresAtMillis=$expires")
        appendLine("keyId=test-key")
        appendLine("provider=Example Registry")
        appendLine("entries:")
        entries.forEach(::appendLine)
    }.toByteArray(Charsets.UTF_8)

    private fun sign(payload: ByteArray, pair: KeyPair = keyPair): String = Signature.getInstance("SHA256withECDSA").run {
        initSign(pair.private)
        update(payload)
        Base64.getEncoder().encodeToString(sign())
    }

    private fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
}
