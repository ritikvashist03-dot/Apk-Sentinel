package app.apksentinel.mobile

import app.apksentinel.engine.tlsinspection.TlsInspectionPackageCategory
import app.apksentinel.engine.tlsinspection.CertificateInstallationState

internal enum class TlsInspectionCertificateUiState {
    VERIFIED_INSTALLED,
    VERIFIED_NOT_INSTALLED,
    UNKNOWN,
}

/** Pure UI gates that mirror the TLS foundation's fail-closed product boundary. */
internal object TlsInspectionUiPolicy {
    /** A bounded selected-app HTTP-over-TLS bridge is composed into NetworkMonitor. */
    const val reviewedDataPlaneAvailable: Boolean = true

    fun canPrepareCertificateSetup(
        advancedEnabled: Boolean,
        setupConsentAcknowledged: Boolean,
        busy: Boolean,
    ): Boolean = advancedEnabled && setupConsentAcknowledged && !busy

    /** Session acknowledgement is deliberately separate from certificate-setup acknowledgement. */
    fun canRecordSessionConsent(advancedEnabled: Boolean): Boolean = advancedEnabled

    /** Traffic starts only through the active, user-consented NetworkMonitor VPN. */
    fun canOfferTrafficStart(
        reviewedDataPlane: Boolean = reviewedDataPlaneAvailable,
        certificateStateKnownInstalled: Boolean = false,
        sessionConsentAcknowledged: Boolean = false,
    ): Boolean = reviewedDataPlane && certificateStateKnownInstalled && sessionConsentAcknowledged

    /**
     * The bounded picker uses a conservative package-name classifier and
     * excludes mandatory sensitive categories and shared-UID packages.
     */
    fun canOfferPackageSelection(reviewedClassifierAvailable: Boolean = true): Boolean =
        reviewedDataPlaneAvailable && reviewedClassifierAvailable

    fun isMandatoryExcluded(category: TlsInspectionPackageCategory): Boolean =
        category in setOf(
            TlsInspectionPackageCategory.BANKING,
            TlsInspectionPackageCategory.PAYMENT,
            TlsInspectionPackageCategory.AUTHENTICATION,
            TlsInspectionPackageCategory.PASSWORD_MANAGER,
            TlsInspectionPackageCategory.HEALTH,
            TlsInspectionPackageCategory.SHARED,
            TlsInspectionPackageCategory.SHARED_UID,
            TlsInspectionPackageCategory.UNKNOWN,
        )

    fun certificateUiState(state: CertificateInstallationState): TlsInspectionCertificateUiState = when (state) {
        CertificateInstallationState.INSTALLED -> TlsInspectionCertificateUiState.VERIFIED_INSTALLED
        CertificateInstallationState.NOT_INSTALLED -> TlsInspectionCertificateUiState.VERIFIED_NOT_INSTALLED
        CertificateInstallationState.UNKNOWN -> TlsInspectionCertificateUiState.UNKNOWN
    }

    /** If a future reviewed integration becomes active, both signals are mandatory. */
    fun requiresProminentStopControl(active: Boolean): Boolean = active
}
