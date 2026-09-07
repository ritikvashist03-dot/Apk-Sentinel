package app.apksentinel.engine.threatintel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ThreatFeedVerifierTest {
    private val keyPair = newEcKeyPair("secp256r1")
    private val now = 1_800_000_000_000L

    @Test
    fun acceptsCanonicalFeedAndNormalizesHostIpAndApkLookup() {
        val bytes = payload(
            entries = listOf(
                "HOST|bad.example|phishing|HIGH|source-1",
                "HOST|xn--bcher-kva.example|lookalike|MEDIUM|source-2",
                "IP|192.0.2.10|command-control|HIGH|source-3",
                "IP|2001:db8::1|command-control|HIGH|source-4",
                "APK_SHA256|${"a".repeat(64)}|malware|MEDIUM|source-5",
            ),
        )

        val feed = accepted(verifier(), bytes)

        assertEquals(1, feed.matchHost("login.bad.example").size)
        assertEquals(1, feed.matchHost("bücher.example").size)
        assertTrue(feed.matchHost("notbad.example").isEmpty())
        assertTrue(feed.matchHost("bad.example:443").isEmpty())
        assertEquals(1, feed.matchIp("192.0.2.10").size)
        assertEquals(1, feed.matchIp("2001:0DB8:0:0:0:0:0:1").size)
        assertTrue(feed.matchIp("999.0.0.1").isEmpty())
        assertEquals(1, feed.matchApkSha256("A".repeat(64)).size)
        assertTrue(feed.matchApkSha256("a".repeat(63)).isEmpty())
    }

    @Test
    fun rejectsTamperingExpiryRollbackAndNonCanonicalPayloads() {
        val bytes = payload(version = 2)
        val tampered = bytes.toString(Charsets.UTF_8).replace("bad.example", "sad.example").toByteArray()
        assertRejected("SIGNATURE", verifier().verify(tampered, sign(bytes), now, 1))

        val expired = payload(expiry = now)
        assertRejected("EXPIRED", verifier().verify(expired, sign(expired), now, 1))
        assertRejected("ROLLBACK", verifier().verify(bytes, sign(bytes), now, 2))

        val crlf = payload().toString(Charsets.UTF_8).replace("\n", "\r\n").toByteArray()
        assertRejected("FORMAT", verifier().verify(crlf, sign(crlf), now, null))
        val noFinalNewline = payload().dropLast(1).toByteArray()
        assertRejected("FORMAT", verifier().verify(noFinalNewline, sign(noFinalNewline), now, null))
        val invalidUtf8 = byteArrayOf(0x80.toByte())
        assertRejected("FORMAT", verifier().verify(invalidUtf8, sign(invalidUtf8), now, null))
    }

    @Test
    fun rejectsNonCanonicalIndicatorsAndDuplicates() {
        val invalidIp = payload(entries = listOf("IP|999.1.1.1|malware|HIGH|source-1"))
        assertRejected("ENTRY", verifier().verify(invalidIp, sign(invalidIp), now, null))

        val uppercaseHash = payload(entries = listOf("APK_SHA256|${"A".repeat(64)}|malware|HIGH|source-1"))
        assertRejected("ENTRY", verifier().verify(uppercaseHash, sign(uppercaseHash), now, null))

        val duplicate = payload(entries = listOf(
            "HOST|bad.example|phishing|HIGH|source-1",
            "HOST|bad.example|phishing|HIGH|source-1",
        ))
        assertRejected("DUPLICATE_ENTRY", verifier().verify(duplicate, sign(duplicate), now, null))
    }

    @Test
    fun enforcesKeyStatusValidityAndFailsClosedForBadKeyringConfiguration() {
        val bytes = payload()
        val retired = verifier(status = ThreatFeedKeyStatus.RETIRED)
        assertRejected("KEY_RETIRED", retired.verify(bytes, sign(bytes), now, null))
        assertTrue(retired.verifyStored(bytes, sign(bytes), now) is ThreatFeedVerification.Accepted)

        val revoked = verifier(status = ThreatFeedKeyStatus.REVOKED)
        assertRejected("KEY_REVOKED", revoked.verifyStored(bytes, sign(bytes), now))

        val futureValidity = verifier(validFromMillis = now + 1)
        assertRejected("KEY_VALIDITY", futureValidity.verify(bytes, sign(bytes), now, null))

        val publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        val duplicated = ThreatFeedVerifier(listOf(
            ThreatFeedKey("test-key", publicKey),
            ThreatFeedKey("test-key", publicKey),
        ))
        assertRejected("KEY_CONFIG", duplicated.verify(bytes, sign(bytes), now, null))

        val p384 = newEcKeyPair("secp384r1")
        val unsupportedCurve = ThreatFeedVerifier(listOf(
            ThreatFeedKey("test-key", Base64.getEncoder().encodeToString(p384.public.encoded)),
        ))
        assertRejected("KEY_CONFIG", unsupportedCurve.verify(bytes, sign(bytes), now, null))
    }

    @Test
    fun rejectsFutureAndOverlongValidityWindows() {
        val futureIssuedAt = now + 5 * 60 * 1_000L + 1L
        val future = payload(issuedAtMillis = futureIssuedAt, expiry = futureIssuedAt + 10_000L)
        assertRejected("FUTURE", verifier().verify(future, sign(future), now, null))

        val longLived = payload(
            issuedAtMillis = now - 1_000L,
            expiry = now - 1_000L + 31L * 24L * 60L * 60L * 1_000L + 1L,
        )
        assertRejected("LIFETIME", verifier().verify(longLived, sign(longLived), now, null))
    }

    private fun verifier(
        status: ThreatFeedKeyStatus = ThreatFeedKeyStatus.ACTIVE,
        validFromMillis: Long? = null,
    ): ThreatFeedVerifier = ThreatFeedVerifier(
        listOf(
            ThreatFeedKey(
                keyId = "test-key",
                x509EcPublicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.public.encoded),
                status = status,
                validFromMillis = validFromMillis,
            ),
        ),
    )

    private fun payload(
        version: Long = 2L,
        issuedAtMillis: Long = now - 1_000L,
        expiry: Long = now + 10_000L,
        entries: List<String> = listOf(
            "HOST|bad.example|phishing|HIGH|source-1",
            "APK_SHA256|${"a".repeat(64)}|malware|MEDIUM|source-2",
        ),
    ): ByteArray = buildString {
        append("APK_SENTINEL_FEED_V1\n")
        append("version=$version\n")
        append("issuedAtMillis=$issuedAtMillis\n")
        append("expiresAtMillis=$expiry\n")
        append("keyId=test-key\n")
        append("entries:\n")
        entries.forEach { append(it).append('\n') }
    }.toByteArray()

    private fun sign(bytes: ByteArray): String = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(bytes)
            sign()
        },
    )

    private fun accepted(verifier: ThreatFeedVerifier, bytes: ByteArray): VerifiedThreatFeed =
        (verifier.verify(bytes, sign(bytes), now, null) as ThreatFeedVerification.Accepted).feed

    private fun assertRejected(expectedCode: String, result: ThreatFeedVerification) {
        val rejected = result as ThreatFeedVerification.Rejected
        assertEquals(expectedCode, rejected.code)
        assertFalse(rejected.safeReason.isBlank())
    }
}

private fun newEcKeyPair(curve: String): KeyPair = KeyPairGenerator.getInstance("EC").apply {
    initialize(ECGenParameterSpec(curve))
}.generateKeyPair()
