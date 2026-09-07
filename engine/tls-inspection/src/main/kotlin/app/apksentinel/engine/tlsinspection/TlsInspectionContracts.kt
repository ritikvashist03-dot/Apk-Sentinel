package app.apksentinel.engine.tlsinspection

/**
 * This module is a containment-first foundation, not a universal HTTPS
 * decryption engine. It has no VPN service, socket, proxy, disk, export, or
 * remote-upload implementation. A separately reviewed host data plane is
 * required before a session can become active.
 */
enum class TlsInspectionSupport {
    /** The platform behaviour depends on the target app or device configuration. */
    VARIES_BY_APP_OR_DEVICE,

    /** The capability is intentionally not available in this product boundary. */
    UNSUPPORTED,

    /** A future, separately reviewed bridge may use this foundation narrowly. */
    FOUNDATION_ONLY,
}

enum class TlsInspectionLimitation {
    USER_CA_TRUST_VARIES_BY_APP,
    CERTIFICATE_PINNING_NOT_BYPASSED,
    NON_HTTP_TLS_NOT_SUPPORTED,
    TLS_1_3_NOT_SUPPORTED,
    QUIC_NOT_SUPPORTED,
    UNIVERSAL_HTTPS_DECRYPTION_NOT_SUPPORTED,
    NO_CAPTURE_WITHOUT_REVIEWED_DATA_PLANE,
    NO_CREDENTIAL_OR_BODY_LOGGING,
    IN_MEMORY_ONLY_NO_EXPORT_OR_REMOTE,
    SENSITIVE_APP_CATEGORIES_EXCLUDED,
}

/** Typed Android 26-36 capability row. It deliberately does not assert that an app will trust a user CA. */
data class AndroidTlsInspectionCapability(
    val apiLevel: Int,
    val userAddedCaTrust: TlsInspectionSupport,
    val certificatePinning: TlsInspectionSupport,
    val nonHttpTls: TlsInspectionSupport,
    val tls13: TlsInspectionSupport,
    val quic: TlsInspectionSupport,
    val universalHttpsDecryption: TlsInspectionSupport,
    val foundation: TlsInspectionSupport,
    val limitations: Set<TlsInspectionLimitation>,
) {
    init {
        require(apiLevel in AndroidTlsInspectionCapabilityMatrix.MIN_API..AndroidTlsInspectionCapabilityMatrix.MAX_API) {
            "TLS inspection capability is defined only for Android 26-36."
        }
    }
}

/**
 * Android 7+ changed user CA handling, but each target application's network
 * security configuration and pinning behaviour still decide trust. The row is
 * explicit for every supported API to avoid silently treating newer releases
 * as equivalent to a tested device.
 */
object AndroidTlsInspectionCapabilityMatrix {
    const val MIN_API = 26
    const val MAX_API = 36

    val rows: Map<Int, AndroidTlsInspectionCapability> = (MIN_API..MAX_API).associateWith(::row)

    fun forApi(apiLevel: Int): AndroidTlsInspectionCapability? = rows[apiLevel]

    private fun row(apiLevel: Int): AndroidTlsInspectionCapability = AndroidTlsInspectionCapability(
        apiLevel = apiLevel,
        userAddedCaTrust = TlsInspectionSupport.VARIES_BY_APP_OR_DEVICE,
        certificatePinning = TlsInspectionSupport.UNSUPPORTED,
        nonHttpTls = TlsInspectionSupport.UNSUPPORTED,
        tls13 = TlsInspectionSupport.UNSUPPORTED,
        quic = TlsInspectionSupport.UNSUPPORTED,
        universalHttpsDecryption = TlsInspectionSupport.UNSUPPORTED,
        foundation = TlsInspectionSupport.FOUNDATION_ONLY,
        limitations = setOf(
            TlsInspectionLimitation.USER_CA_TRUST_VARIES_BY_APP,
            TlsInspectionLimitation.CERTIFICATE_PINNING_NOT_BYPASSED,
            TlsInspectionLimitation.NON_HTTP_TLS_NOT_SUPPORTED,
            TlsInspectionLimitation.TLS_1_3_NOT_SUPPORTED,
            TlsInspectionLimitation.QUIC_NOT_SUPPORTED,
            TlsInspectionLimitation.UNIVERSAL_HTTPS_DECRYPTION_NOT_SUPPORTED,
            TlsInspectionLimitation.NO_CAPTURE_WITHOUT_REVIEWED_DATA_PLANE,
            TlsInspectionLimitation.NO_CREDENTIAL_OR_BODY_LOGGING,
            TlsInspectionLimitation.IN_MEMORY_ONLY_NO_EXPORT_OR_REMOTE,
            TlsInspectionLimitation.SENSITIVE_APP_CATEGORIES_EXCLUDED,
        ),
    )
}

/** Separate acknowledgement, required only to prepare an Android certificate-install screen. */
data class CertificateSetupConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120) {
            "A certificate-setup disclosure version is required."
        }
        require(acknowledgedAtMillis > 0L) { "Certificate-setup acknowledgement time must be positive." }
    }
}

/** Separate acknowledgement, required for each inspection session. Certificate setup never implies this consent. */
data class TlsInspectionSessionConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank() && disclosureVersion.length <= 120) {
            "A session-inspection disclosure version is required."
        }
        require(acknowledgedAtMillis > 0L) { "Session-inspection acknowledgement time must be positive." }
    }
}

/** Public metadata only. Neither a private key nor a private-key export operation exists in this contract. */
data class TlsCaCertificateMetadata(
    val alias: String,
    val subject: String,
    val serialNumberHex: String,
    val sha256Fingerprint: String,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
    val keyStorage: TlsPrivateKeyStorage,
) {
    init {
        require(ALIAS_PATTERN.matches(alias)) { "Certificate alias is invalid." }
        require(subject.isNotBlank() && subject.length <= 512) { "Certificate subject is invalid." }
        require(HEX_PATTERN.matches(serialNumberHex)) { "Certificate serial is invalid." }
        require(SHA256_PATTERN.matches(sha256Fingerprint)) { "Certificate fingerprint is invalid." }
        require(notBeforeMillis >= 0L && notAfterMillis > notBeforeMillis) { "Certificate validity is invalid." }
    }

    private companion object {
        val ALIAS_PATTERN = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
        val HEX_PATTERN = Regex("^[0-9A-Fa-f]{2,256}$")
        val SHA256_PATTERN = Regex("^[0-9a-f]{64}$")
    }
}

enum class TlsPrivateKeyStorage { ANDROID_KEYSTORE_NON_EXPORTABLE, HOST_DEFINED_NON_EXPORTABLE }

sealed interface TlsCaCredentialLookup {
    data class Available(val metadata: TlsCaCertificateMetadata) : TlsCaCredentialLookup
    data class Unavailable(val reason: TlsCaCredentialFailure) : TlsCaCredentialLookup
}

sealed interface TlsCaCredentialProvisioning {
    data class Available(val metadata: TlsCaCertificateMetadata) : TlsCaCredentialProvisioning
    data class Unavailable(val reason: TlsCaCredentialFailure) : TlsCaCredentialProvisioning
}

enum class TlsCaCredentialFailure {
    KEYSTORE_UNAVAILABLE,
    KEY_GENERATION_FAILED,
    CERTIFICATE_UNAVAILABLE,
    CERTIFICATE_INVALID,
    CERTIFICATE_PERSIST_FAILED,
    CLOCK_UNAVAILABLE,
}

/**
 * A host crypto boundary. Implementations may create a per-install CA but
 * must return metadata only and must never expose its private key.
 */
interface TlsCaCredentialProvider {
    fun existingMetadata(): TlsCaCredentialLookup

    /** Must be invoked only after [CertificateSetupConsent] has been collected by the host. */
    fun provisionForCertificateSetup(consent: CertificateSetupConsent): TlsCaCredentialProvisioning
}

/** The only installation action this foundation can request. It cannot silently install a user CA. */
data class UserMediatedCertificateInstallAction(
    val certificateAlias: String,
    val certificateSha256Fingerprint: String,
    val action: CertificateInstallAction = CertificateInstallAction.OPEN_SYSTEM_INSTALLER,
    val removalGuidance: CertificateRemovalGuidance,
) {
    init {
        require(certificateAlias.isNotBlank()) { "Certificate alias is required." }
        require(certificateSha256Fingerprint.matches(Regex("^[0-9a-f]{64}$"))) { "Certificate fingerprint is invalid." }
    }
}

enum class CertificateInstallAction { OPEN_SYSTEM_INSTALLER }

data class CertificateRemovalGuidance(
    val title: String,
    val steps: List<String>,
    val verificationState: CertificateInstallationState,
) {
    init {
        require(title.isNotBlank() && steps.isNotEmpty() && steps.all { it.isNotBlank() }) {
            "Removal guidance must be actionable."
        }
    }
}

/**
 * Android has no generally reliable public API for asking whether a specific
 * user CA is trusted for all apps. UNKNOWN is a real result, never a guess.
 */
enum class CertificateInstallationState { INSTALLED, NOT_INSTALLED, UNKNOWN }

/**
 * Presence of this exact public certificate in AndroidCAStore. This does not
 * prove that any target app trusts a user CA or that pinning is absent.
 */
enum class AndroidCaStorePresence {
    CA_STORE_PRESENT,
    CA_STORE_NOT_PRESENT,
    CA_STORE_UNKNOWN,
}

data class AndroidCaStoreVerification(
    val presence: AndroidCaStorePresence,
    val reason: CertificateInstallationVerificationReason,
)

data class CertificateInstallationVerification(
    val state: CertificateInstallationState,
    val reason: CertificateInstallationVerificationReason,
)

enum class CertificateInstallationVerificationReason {
    VERIFIED_BY_PUBLIC_OR_MANAGED_CAPABILITY,
    NOT_FOUND_BY_PUBLIC_OR_MANAGED_CAPABILITY,
    PUBLIC_API_UNAVAILABLE,
    VERIFIER_FAILURE,
    /** The verifier reports CA-store presence only, never target-app trust. */
    CA_STORE_PRESENCE_ONLY,
}

interface CertificateInstallationVerifier {
    fun verify(metadata: TlsCaCertificateMetadata): CertificateInstallationVerification
}

/** Safe default whenever the host has no legitimate public or managed verification capability. */
object UnknownCertificateInstallationVerifier : CertificateInstallationVerifier {
    override fun verify(metadata: TlsCaCertificateMetadata): CertificateInstallationVerification =
        CertificateInstallationVerification(
            state = CertificateInstallationState.UNKNOWN,
            reason = CertificateInstallationVerificationReason.PUBLIC_API_UNAVAILABLE,
        )
}

sealed interface CertificateSetupResult {
    data class ReadyForUserMediatedInstall(
        val metadata: TlsCaCertificateMetadata,
        val installAction: UserMediatedCertificateInstallAction,
    ) : CertificateSetupResult

    data class Rejected(val reason: CertificateSetupRejection) : CertificateSetupResult
}

enum class CertificateSetupRejection { CREDENTIAL_PROVISIONING_FAILED }

/** Coordinates consent and key provisioning only; it does not launch an Android activity or install a certificate. */
class TlsCertificateSetupCoordinator(
    private val credentialProvider: TlsCaCredentialProvider,
    private val removalGuidanceProvider: (CertificateInstallationState) -> CertificateRemovalGuidance,
) {
    fun prepareUserMediatedInstall(consent: CertificateSetupConsent): CertificateSetupResult {
        val provisioned = credentialProvider.provisionForCertificateSetup(consent)
        if (provisioned !is TlsCaCredentialProvisioning.Available) {
            return CertificateSetupResult.Rejected(CertificateSetupRejection.CREDENTIAL_PROVISIONING_FAILED)
        }
        val metadata = provisioned.metadata
        return CertificateSetupResult.ReadyForUserMediatedInstall(
            metadata = metadata,
            installAction = UserMediatedCertificateInstallAction(
                certificateAlias = metadata.alias,
                certificateSha256Fingerprint = metadata.sha256Fingerprint,
                removalGuidance = removalGuidanceProvider(CertificateInstallationState.UNKNOWN),
            ),
        )
    }
}
