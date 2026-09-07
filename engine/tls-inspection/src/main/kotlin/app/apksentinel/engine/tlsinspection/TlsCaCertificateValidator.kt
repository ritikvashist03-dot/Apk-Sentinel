package app.apksentinel.engine.tlsinspection

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date

/** Public, pure validation boundary used by setup tests and Android adapters. */
object TlsCaCertificateValidator {
    fun parseDer(der: ByteArray): X509Certificate? = try {
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        if (!der.contentEquals(certificate.encoded)) null else certificate
    } catch (_: Exception) {
        null
    }

    fun sha256Fingerprint(der: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(der)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** Checks DER canonicality, CA constraints, key usage, signature and identity. */
    fun isValidCa(
        der: ByteArray,
        expectedPublicKey: PublicKey,
        expectedFingerprint: String? = null,
        nowMillis: Long = System.currentTimeMillis(),
    ): Boolean = try {
        val certificate = parseDer(der) ?: return false
        if (expectedFingerprint != null && !expectedFingerprint.equals(sha256Fingerprint(der), ignoreCase = true)) return false
        if (!certificate.publicKey.encoded.contentEquals(expectedPublicKey.encoded)) return false
        certificate.verify(expectedPublicKey)
        certificate.checkValidity(Date(nowMillis))
        if (certificate.notAfter.time <= certificate.notBefore.time ||
            certificate.notAfter.time - certificate.notBefore.time > MAX_CERTIFICATE_VALIDITY_MILLIS
        ) return false
        if (certificate.basicConstraints != 0) return false
        if (!certificate.sigAlgName.uppercase().startsWith("SHA256WITH")) return false
        val keyUsage = certificate.keyUsage ?: return false
        if (keyUsage.size <= 6 || !keyUsage[5] || !keyUsage[6]) return false
        val critical = certificate.criticalExtensionOIDs ?: emptySet()
        "2.5.29.19" in critical && "2.5.29.15" in critical
    } catch (_: Exception) {
        false
    }

    private const val MAX_CERTIFICATE_VALIDITY_MILLIS = 90L * 24L * 60L * 60L * 1_000L + 120_000L
}
