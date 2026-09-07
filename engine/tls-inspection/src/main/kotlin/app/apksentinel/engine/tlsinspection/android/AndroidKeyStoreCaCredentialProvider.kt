package app.apksentinel.engine.tlsinspection.android

import android.content.Intent
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.apksentinel.engine.tlsinspection.AndroidCaStorePresence
import app.apksentinel.engine.tlsinspection.AndroidCaStoreVerification
import app.apksentinel.engine.tlsinspection.CertificateInstallationState
import app.apksentinel.engine.tlsinspection.CertificateInstallationVerification
import app.apksentinel.engine.tlsinspection.CertificateInstallationVerificationReason
import app.apksentinel.engine.tlsinspection.CertificateInstallationVerifier
import app.apksentinel.engine.tlsinspection.CertificateRemovalGuidance
import app.apksentinel.engine.tlsinspection.CertificateSetupConsent
import app.apksentinel.engine.tlsinspection.TlsCaCertificateMetadata
import app.apksentinel.engine.tlsinspection.TlsCaCredentialFailure
import app.apksentinel.engine.tlsinspection.TlsCaCredentialLookup
import app.apksentinel.engine.tlsinspection.TlsCaCredentialProvider
import app.apksentinel.engine.tlsinspection.TlsCaCredentialProvisioning
import app.apksentinel.engine.tlsinspection.TlsContentSignerFactory
import app.apksentinel.engine.tlsinspection.TlsPrivateKeyStorage
import app.apksentinel.engine.tlsinspection.UserMediatedCertificateInstallAction
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * Creates a per-install CA key in Android Keystore. The CA certificate is
 * signed by that key, but only its public DER is persisted in a certificate
 * entry. No private-key encoding or export API exists in this adapter.
 */
class AndroidKeyStoreCaCredentialProvider(
    private val alias: String = DEFAULT_ALIAS,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val secureRandom: SecureRandom = SecureRandom(),
) : TlsCaCredentialProvider {

    override fun existingMetadata(): TlsCaCredentialLookup {
        val keyStore = loadKeyStore() ?: return unavailable(TlsCaCredentialFailure.KEYSTORE_UNAVAILABLE)
        val privateKey = try {
            keyStore.getKey(alias, null) as? PrivateKey
        } catch (_: Exception) {
            null
        } ?: return unavailable(TlsCaCredentialFailure.CERTIFICATE_UNAVAILABLE)
        val publicKey = try {
            keyStore.getCertificate(alias)?.publicKey
        } catch (_: Exception) {
            null
        } ?: return unavailable(TlsCaCredentialFailure.CERTIFICATE_UNAVAILABLE)
        val certificate = try {
            keyStore.getCertificate(publicCertificateAlias(alias)) as? X509Certificate
        } catch (_: Exception) {
            null
        } ?: return unavailable(TlsCaCredentialFailure.CERTIFICATE_UNAVAILABLE)
        val now = safeNow() ?: return unavailable(TlsCaCredentialFailure.CLOCK_UNAVAILABLE)
        return validateAndMetadata(certificate, publicKey, now)
            ?.let(TlsCaCredentialLookup::Available)
            ?: unavailable(TlsCaCredentialFailure.CERTIFICATE_INVALID)
    }

    override fun provisionForCertificateSetup(consent: CertificateSetupConsent): TlsCaCredentialProvisioning {
        // Consent is deliberately a required argument; the crypto adapter does
        // not retain it or make a UI decision.
        consent.hashCode()
        when (val existing = existingMetadata()) {
            is TlsCaCredentialLookup.Available -> return TlsCaCredentialProvisioning.Available(existing.metadata)
            is TlsCaCredentialLookup.Unavailable -> when (existing.reason) {
                TlsCaCredentialFailure.CERTIFICATE_UNAVAILABLE -> Unit
                else -> return TlsCaCredentialProvisioning.Unavailable(existing.reason)
            }
        }
        val now = safeNow() ?: return unavailableProvisioning(TlsCaCredentialFailure.CLOCK_UNAVAILABLE)
        val notBefore = (now - CLOCK_SKEW_MILLIS).coerceAtLeast(1L)
        val notAfter = safeAdd(now, CERTIFICATE_LIFETIME_MILLIS)
            ?: return unavailableProvisioning(TlsCaCredentialFailure.CLOCK_UNAVAILABLE)
        val serial = uniquePositiveSerial()
        val generated = try {
            val existingStore = loadKeyStore()
            val existingPrivate = existingStore?.getKey(alias, null) as? PrivateKey
            val existingPublic = existingStore?.getCertificate(alias)?.publicKey
            if (existingPrivate != null && existingPublic != null) {
                // Migrate an older placeholder self-signed certificate by
                // retaining its non-exportable key and replacing only the
                // persisted public CA certificate entry.
                KeyPair(existingPublic, existingPrivate)
            } else {
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE).apply {
                    initialize(
                        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                            .setKeySize(2048)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setCertificateSubject(X500Principal(CERTIFICATE_SUBJECT))
                            .setCertificateSerialNumber(serial)
                            .setCertificateNotBefore(Date(notBefore))
                            .setCertificateNotAfter(Date(notAfter))
                            .build(),
                    )
                }.generateKeyPair()
            }
        } catch (_: Exception) {
            null
        } ?: return unavailableProvisioning(TlsCaCredentialFailure.KEY_GENERATION_FAILED)

        val caCertificate = try {
            generateCaCertificate(generated.private, generated.public, serial, Date(notBefore), Date(notAfter))
        } catch (_: Exception) {
            return unavailableProvisioning(TlsCaCredentialFailure.CERTIFICATE_INVALID)
        }
        if (!validateCaCertificate(caCertificate, generated.public, now, notBefore, notAfter)) {
            return unavailableProvisioning(TlsCaCredentialFailure.CERTIFICATE_INVALID)
        }

        // Android Keystore certificate entries persist the public DER only.
        // The private key remains behind the Android Keystore provider.
        val persisted = try {
            loadKeyStore()?.apply { setCertificateEntry(publicCertificateAlias(alias), caCertificate) }
            val roundTrip = loadKeyStore()?.getCertificate(publicCertificateAlias(alias)) as? X509Certificate
            roundTrip != null && validateCaCertificate(roundTrip, generated.public, now, notBefore, notAfter)
        } catch (_: Exception) {
            false
        }
        if (!persisted) return unavailableProvisioning(TlsCaCredentialFailure.CERTIFICATE_PERSIST_FAILED)
        return when (val created = existingMetadata()) {
            is TlsCaCredentialLookup.Available -> TlsCaCredentialProvisioning.Available(created.metadata)
            is TlsCaCredentialLookup.Unavailable -> unavailableProvisioning(created.reason)
        }
    }

    /** Public certificate bytes for a user-mediated installer/export only. */
    /** Returns only a copied public DER certificate after alias/fingerprint matching. */
    fun publicCertificateDerFor(alias: String, fingerprint: String): ByteArray? {
        if (alias != this.alias) return null
        val metadata = (existingMetadata() as? TlsCaCredentialLookup.Available)?.metadata ?: return null
        if (metadata.sha256Fingerprint != fingerprint) return null
        return try {
            (loadKeyStore()?.getCertificate(publicCertificateAlias(alias)) as? X509Certificate)
                ?.encoded
                ?.copyOf()
        } catch (_: Exception) {
            null
        }
    }

    internal fun publicCertificateDer(): ByteArray? = try {
        val current = existingMetadata() as? TlsCaCredentialLookup.Available ?: return null
        publicCertificateDerFor(current.metadata.alias, current.metadata.sha256Fingerprint)
    } catch (_: Exception) {
        null
    }

    /**
     * Runs a process-local bridge factory with the non-exportable Keystore key.
     * The key is never encoded, returned, or persisted by this adapter; the
     * host must retain only the resulting bounded session route in memory.
     */
    fun <T> withEphemeralCredential(block: (X509Certificate, PrivateKey) -> T): T? {
        val metadata = (existingMetadata() as? TlsCaCredentialLookup.Available)?.metadata ?: return null
        return try {
            val store = loadKeyStore() ?: return null
            val key = store.getKey(alias, null) as? PrivateKey ?: return null
            val certificate = store.getCertificate(publicCertificateAlias(alias)) as? X509Certificate ?: return null
            block(certificate, key)
        } catch (_: Exception) {
            null
        }
    }

    private fun validateAndMetadata(certificate: X509Certificate, publicKey: PublicKey, now: Long): TlsCaCertificateMetadata? {
        if (!validateCaCertificate(certificate, publicKey, now, certificate.notBefore.time, certificate.notAfter.time)) return null
        return try {
            TlsCaCertificateMetadata(
                alias = alias,
                subject = certificate.subjectX500Principal.name,
                serialNumberHex = certificate.serialNumber.toString(16).padStart(2, '0'),
                sha256Fingerprint = sha256(certificate.encoded),
                notBeforeMillis = certificate.notBefore.time,
                notAfterMillis = certificate.notAfter.time,
                keyStorage = TlsPrivateKeyStorage.ANDROID_KEYSTORE_NON_EXPORTABLE,
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun generateCaCertificate(
        privateKey: PrivateKey,
        publicKey: PublicKey,
        serial: BigInteger,
        notBefore: Date,
        notAfter: Date,
    ): X509Certificate {
        val issuer = X500Name(CERTIFICATE_SUBJECT)
        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, publicKey,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        val signer: ContentSigner = TlsContentSignerFactory.create("SHA256withRSA", privateKey)
        return JcaX509CertificateConverter()
            .setProvider(BC_PROVIDER)
            .getCertificate(builder.build(signer))
    }

    private fun validateCaCertificate(
        certificate: X509Certificate,
        publicKey: PublicKey,
        now: Long,
        expectedNotBefore: Long,
        expectedNotAfter: Long,
    ): Boolean = try {
        val encoded = certificate.encoded
        val parsed = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
        if (!encoded.contentEquals(parsed.encoded)) return false
        if (!certificate.publicKey.encoded.contentEquals(publicKey.encoded)) return false
        certificate.verify(publicKey)
        certificate.checkValidity(Date(now))
        if (certificate.notBefore.time != expectedNotBefore || certificate.notAfter.time != expectedNotAfter) return false
        if (certificate.notAfter.time <= certificate.notBefore.time ||
            certificate.notAfter.time - certificate.notBefore.time > MAX_CERTIFICATE_VALIDITY_MILLIS
        ) return false
        if (certificate.sigAlgName.uppercase() != "SHA256WITHRSA") return false
        if (certificate.basicConstraints != 0) return false
        val keyUsage = certificate.keyUsage ?: return false
        if (keyUsage.size <= KeyUsage.cRLSign || !keyUsage[KeyUsage.keyCertSign] || !keyUsage[KeyUsage.cRLSign]) return false
        val critical = certificate.criticalExtensionOIDs ?: emptySet()
        Extension.basicConstraints.id in critical && Extension.keyUsage.id in critical
    } catch (_: Exception) {
        false
    }

    private fun uniquePositiveSerial(): BigInteger = generateSequence {
        BigInteger(128, secureRandom).takeIf { it.signum() > 0 }
    }.first()

    private fun loadKeyStore(): KeyStore? = try {
        KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
    } catch (_: Exception) {
        null
    }

    private fun safeNow(): Long? = try {
        nowMillis().takeIf { it > 0L }
    } catch (_: RuntimeException) {
        null
    }

    private fun safeAdd(left: Long, right: Long): Long? =
        if (left > Long.MAX_VALUE - right) null else left + right

    private fun unavailable(reason: TlsCaCredentialFailure) = TlsCaCredentialLookup.Unavailable(reason)
    private fun unavailableProvisioning(reason: TlsCaCredentialFailure) = TlsCaCredentialProvisioning.Unavailable(reason)

    companion object {
        const val DEFAULT_ALIAS = "apk-sentinel-tls-inspection-ca-v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val CERTIFICATE_SUBJECT = "CN=APK Sentinel Local Inspection CA"
        private const val CLOCK_SKEW_MILLIS = 60_000L
        private const val CERTIFICATE_LIFETIME_MILLIS = 90L * 24L * 60L * 60L * 1_000L
        private const val MAX_CERTIFICATE_VALIDITY_MILLIS = CERTIFICATE_LIFETIME_MILLIS + (2L * CLOCK_SKEW_MILLIS)
        private val BC_PROVIDER = BouncyCastleProvider()

        fun publicCertificateAlias(privateAlias: String): String = "$privateAlias-public"

        private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}

sealed interface AndroidCertificateInstallIntentResult {
    /** API 26-29 only: the user-mediated Android KeyChain installer. */
    data class KeyChainInstaller(val intent: Intent, val certificateDer: ByteArray) : AndroidCertificateInstallIntentResult

    /** API 30-36 only: a public-CA DER export chosen by the user through SAF. */
    data class SafCertificateExport(val intent: Intent, val certificateDer: ByteArray) : AndroidCertificateInstallIntentResult

    data object UnsupportedApi : AndroidCertificateInstallIntentResult
    data object CertificateUnavailable : AndroidCertificateInstallIntentResult
}

enum class AndroidCertificateInstallApiRoute {
    KEYCHAIN_USER_INSTALLER,
    SAF_PUBLIC_EXPORT,
    UNSUPPORTED,
}

object AndroidCertificateInstallRoutePolicy {
    fun forApi(apiLevel: Int): AndroidCertificateInstallApiRoute = when {
        apiLevel in 26..29 -> AndroidCertificateInstallApiRoute.KEYCHAIN_USER_INSTALLER
        apiLevel in 30..36 -> AndroidCertificateInstallApiRoute.SAF_PUBLIC_EXPORT
        else -> AndroidCertificateInstallApiRoute.UNSUPPORTED
    }
}

/** Builds, but never launches, the API-specific user action. */
class AndroidUserMediatedCertificateInstallIntentFactory(
    private val credentialProvider: AndroidKeyStoreCaCredentialProvider,
) {
    fun createInstallIntent(action: UserMediatedCertificateInstallAction): AndroidCertificateInstallIntentResult =
        createInstallRoute(apiLevel = 29, action = action)

    fun createInstallRoute(apiLevel: Int, action: UserMediatedCertificateInstallAction): AndroidCertificateInstallIntentResult {
        val der = credentialProvider.publicCertificateDerFor(action.certificateAlias, action.certificateSha256Fingerprint)
            ?: return AndroidCertificateInstallIntentResult.CertificateUnavailable
        return when (AndroidCertificateInstallRoutePolicy.forApi(apiLevel)) {
            AndroidCertificateInstallApiRoute.KEYCHAIN_USER_INSTALLER -> AndroidCertificateInstallIntentResult.KeyChainInstaller(
                intent = KeyChain.createInstallIntent().putExtra(KeyChain.EXTRA_CERTIFICATE, der.copyOf()),
                certificateDer = der,
            )
            AndroidCertificateInstallApiRoute.SAF_PUBLIC_EXPORT -> AndroidCertificateInstallIntentResult.SafCertificateExport(
                intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("application/x-x509-ca-cert")
                    .putExtra(Intent.EXTRA_TITLE, "apk-sentinel-local-inspection-ca.cer"),
                certificateDer = der,
            )
            AndroidCertificateInstallApiRoute.UNSUPPORTED -> {
                der.fill(0)
                AndroidCertificateInstallIntentResult.UnsupportedApi
            }
        }
    }
}

/** AndroidCAStore proves only exact certificate presence, never target-app trust. */
class AndroidCaStoreCertificateInstallationVerifier(
    private val publicCertificateDerProvider: (TlsCaCertificateMetadata) -> ByteArray?,
) : CertificateInstallationVerifier {
    override fun verify(metadata: TlsCaCertificateMetadata): CertificateInstallationVerification {
        val result = verifyPresence(publicCertificateDerProvider(metadata))
        return when (result.presence) {
            AndroidCaStorePresence.CA_STORE_PRESENT -> CertificateInstallationVerification(
                CertificateInstallationState.INSTALLED,
                CertificateInstallationVerificationReason.CA_STORE_PRESENCE_ONLY,
            )
            AndroidCaStorePresence.CA_STORE_NOT_PRESENT -> CertificateInstallationVerification(
                CertificateInstallationState.NOT_INSTALLED,
                CertificateInstallationVerificationReason.NOT_FOUND_BY_PUBLIC_OR_MANAGED_CAPABILITY,
            )
            AndroidCaStorePresence.CA_STORE_UNKNOWN -> CertificateInstallationVerification(
                CertificateInstallationState.UNKNOWN,
                result.reason,
            )
        }
    }

    companion object {
        fun verifyPresence(certificateDer: ByteArray?): AndroidCaStoreVerification {
            if (certificateDer == null || certificateDer.isEmpty()) {
                return AndroidCaStoreVerification(AndroidCaStorePresence.CA_STORE_UNKNOWN, CertificateInstallationVerificationReason.VERIFIER_FAILURE)
            }
            return try {
                val expected = CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(certificateDer)) as X509Certificate
                val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
                val aliases = store.aliases()
                while (aliases.hasMoreElements()) {
                    val candidate = store.getCertificate(aliases.nextElement()) as? X509Certificate ?: continue
                    if (candidate.encoded.contentEquals(expected.encoded)) {
                        return AndroidCaStoreVerification(
                            AndroidCaStorePresence.CA_STORE_PRESENT,
                            CertificateInstallationVerificationReason.CA_STORE_PRESENCE_ONLY,
                        )
                    }
                }
                AndroidCaStoreVerification(
                    AndroidCaStorePresence.CA_STORE_NOT_PRESENT,
                    CertificateInstallationVerificationReason.NOT_FOUND_BY_PUBLIC_OR_MANAGED_CAPABILITY,
                )
            } catch (_: Exception) {
                AndroidCaStoreVerification(
                    AndroidCaStorePresence.CA_STORE_UNKNOWN,
                    CertificateInstallationVerificationReason.VERIFIER_FAILURE,
                )
            }
        }
    }
}

/** Compatibility-safe verifier when no public DER provider is available. */
object AndroidPublicApiCertificateInstallationVerifier : CertificateInstallationVerifier {
    override fun verify(metadata: TlsCaCertificateMetadata): CertificateInstallationVerification =
        CertificateInstallationVerification(
            state = CertificateInstallationState.UNKNOWN,
            reason = CertificateInstallationVerificationReason.PUBLIC_API_UNAVAILABLE,
        )
}

/** OEM wording varies; this remains guidance, never a claim of removal. */
object AndroidCertificateRemovalGuidance {
    fun forVerificationState(state: CertificateInstallationState): CertificateRemovalGuidance = CertificateRemovalGuidance(
        title = "Remove the inspection certificate",
        steps = listOf(
            "Stop inspection first.",
            "Open Android Settings and search for User credentials or Trusted credentials.",
            "Find the APK Sentinel local inspection certificate and remove it using Android's confirmation screen.",
            "Return here and check CA-store presence. CA-store presence does not prove target-app trust; Unknown remains blocked.",
        ),
        verificationState = state,
    )
}
