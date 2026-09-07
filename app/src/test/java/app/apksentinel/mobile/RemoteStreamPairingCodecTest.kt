package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class RemoteStreamPairingCodecTest {
    @Test fun acceptsOnlyVerifiedP256LiteralPairingAndRoundTripsBoundedly() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val publicKey = Base64.getEncoder().encodeToString(pair.public.encoded)
        val fingerprint = sha256(pair.public.encoded)
        val parsed = RemoteStreamPairingCodec.parseUserInput("192.0.2.10", "443", "receiver-1", publicKey, fingerprint)

        assertTrue(parsed is RemoteStreamPairingInputResult.Accepted)
        val material = (parsed as RemoteStreamPairingInputResult.Accepted).material
        val encoded = requireNotNull(RemoteStreamPairingCodec.encode(material))
        val decoded = RemoteStreamPairingCodec.decode(encoded)
        encoded.fill(0)

        assertEquals(material, decoded)
        assertFalse(RemoteStreamPairingCodec.isValid(material.copy(literalAddress = "receiver.example")))
        assertFalse(RemoteStreamPairingCodec.isValid(material.copy(receiverFingerprint = "0".repeat(64))))
    }

    @Test fun rejectsNonP256EcReceiverKey() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        val encoded = Base64.getEncoder().encodeToString(pair.public.encoded)
        val result = RemoteStreamPairingCodec.parseUserInput("2001:db8::10", "8443", "receiver-2", encoded, sha256(pair.public.encoded))

        assertEquals(
            RemoteStreamPairingInputIssue.UNSUPPORTED_RECEIVER_KEY,
            (result as RemoteStreamPairingInputResult.Rejected).issue,
        )
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
}
