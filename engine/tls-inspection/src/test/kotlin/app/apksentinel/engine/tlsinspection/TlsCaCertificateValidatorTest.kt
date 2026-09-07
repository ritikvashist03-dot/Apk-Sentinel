package app.apksentinel.engine.tlsinspection

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.util.Date

class TlsCaCertificateValidatorTest {
    @Test
    fun validCaDerRequiresCriticalExtensionsMatchingKeyAndFingerprint() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2_048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 60_000L)
        val notAfter = Date(now + 86_400_000L)
        val cert = JcaX509CertificateConverter()
            .getCertificate(
                JcaX509v3CertificateBuilder(
                    X500Name("CN=Test CA"),
                    BigInteger("123456789"),
                    notBefore,
                    notAfter,
                    X500Name("CN=Test CA"),
                    keyPair.public,
                )
                    .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
                    .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
                    .build(TlsContentSignerFactory.create("SHA256withRSA", keyPair.private)),
            )
        val der = cert.encoded
        val fingerprint = TlsCaCertificateValidator.sha256Fingerprint(der)

        assertTrue(TlsCaCertificateValidator.isValidCa(der, keyPair.public, fingerprint, now))
        assertEquals(cert, TlsCaCertificateValidator.parseDer(der))
        assertFalse(TlsCaCertificateValidator.isValidCa(der.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }, keyPair.public, fingerprint, now))
    }
}
