package app.apksentinel.engine.tlsinspection

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsKeyLogTest {

    @Test
    fun readsASecretWithoutDestroyingIt() {
        val crypto = BcTlsCrypto(SecureRandom())
        val secret = crypto.createSecret(ByteArray(32) { it.toByte() })

        val copied = BcTlsSecretAccess.copyOf(secret)

        assertNotNull(copied)
        assertEquals(32, copied!!.size)
        assertEquals(0, copied[0].toInt())
        assertEquals(31, copied[31].toInt())
        // The whole point: the live session's secret must still be usable afterwards.
        assertTrue(secret.isAlive)
    }

    @Test
    fun readsADerivedTrafficSecretToo() {
        // TLS 1.3 traffic secrets are derived, not created from bytes we already hold, so
        // this is the case that decides whether a 1.3 key log is possible at all.
        val crypto = BcTlsCrypto(SecureRandom())
        val parent = crypto.createSecret(ByteArray(32) { 7 })
        val derived = parent.hkdfExpand(2, ByteArray(4), 32)

        val copied = BcTlsSecretAccess.copyOf(derived)

        assertNotNull(copied)
        assertEquals(32, copied!!.size)
        assertTrue(parent.isAlive)
        assertTrue(derived.isAlive)
    }

    @Test
    fun aDestroyedSecretYieldsNothingRatherThanThrowing() {
        val crypto = BcTlsCrypto(SecureRandom())
        val secret = crypto.createSecret(ByteArray(32))
        secret.destroy()

        assertNull(BcTlsSecretAccess.copyOf(secret))
        assertNull(BcTlsSecretAccess.copyOf(null))
    }

    @Test
    fun aTls12SessionProducesTheSingleClientRandomLine() {
        val lines = TlsKeyLog.linesFor(
            TlsKeyLogSecrets(
                clientRandom = ByteArray(32) { 0x11 },
                masterSecret = ByteArray(48) { 0x22 },
            ),
        )

        assertEquals(1, lines.size)
        assertTrue(lines.single().startsWith("CLIENT_RANDOM "))
        assertTrue(lines.single().contains("11".repeat(32)))
        assertTrue(lines.single().endsWith("22".repeat(48)))
    }

    @Test
    fun aTls13SessionProducesOneLinePerCapturedTrafficSecret() {
        val lines = TlsKeyLog.linesFor(
            TlsKeyLogSecrets(
                clientRandom = ByteArray(32) { 0x01 },
                clientHandshakeTrafficSecret = ByteArray(32) { 0x02 },
                serverHandshakeTrafficSecret = ByteArray(32) { 0x03 },
                clientApplicationTrafficSecret = ByteArray(32) { 0x04 },
                serverApplicationTrafficSecret = ByteArray(32) { 0x05 },
            ),
        )

        assertEquals(4, lines.size)
        assertTrue(lines[0].startsWith(TlsKeyLog.LABEL_CLIENT_HANDSHAKE))
        assertTrue(lines[3].startsWith(TlsKeyLog.LABEL_SERVER_APPLICATION))
    }

    @Test
    fun aSecretThatWasNotCapturedIsOmittedRatherThanFaked() {
        // A zero-filled or invented line would make a session look decryptable when it is
        // not, which is worse than a shorter key log.
        val lines = TlsKeyLog.linesFor(
            TlsKeyLogSecrets(
                clientRandom = ByteArray(32),
                masterSecret = null,
                clientApplicationTrafficSecret = ByteArray(32) { 0x09 },
            ),
        )

        assertEquals(1, lines.size)
        assertFalse(lines.any { it.startsWith(TlsKeyLog.LABEL_CLIENT_RANDOM) })
        assertTrue(lines.single().startsWith(TlsKeyLog.LABEL_CLIENT_APPLICATION))
    }

    @Test
    fun writingAppendsOneAsciiLinePerSecret() {
        val output = ByteArrayOutputStream()
        val written = TlsKeyLog.appendTo(
            output,
            TlsKeyLogSecrets(clientRandom = ByteArray(32), masterSecret = ByteArray(48) { 0x0f }),
        )

        assertEquals(1, written)
        val text = output.toString("US-ASCII")
        assertTrue(text.endsWith("\n"))
        assertEquals(1, text.count { it == '\n' })
    }

    @Test
    fun aClientRandomMustBeTheRealLength() {
        runCatching { TlsKeyLogSecrets(clientRandom = ByteArray(8)) }
            .also { assertTrue(it.isFailure) }
    }
}
