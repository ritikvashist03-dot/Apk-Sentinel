package app.apksentinel.mobile

import app.apksentinel.engine.tlsinspection.CertificateInstallationState
import app.apksentinel.engine.tlsinspection.TlsInspectionPackageCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsInspectionUiPolicyTest {
    @Test fun certificate_setup_requires_its_own_fresh_acknowledgement() {
        assertFalse(TlsInspectionUiPolicy.canPrepareCertificateSetup(false, true, false))
        assertFalse(TlsInspectionUiPolicy.canPrepareCertificateSetup(true, false, false))
        assertFalse(TlsInspectionUiPolicy.canPrepareCertificateSetup(true, true, true))
        assertTrue(TlsInspectionUiPolicy.canPrepareCertificateSetup(true, true, false))
    }

    @Test fun session_acknowledgement_never_unblocks_current_traffic_start() {
        assertTrue(TlsInspectionUiPolicy.canRecordSessionConsent(advancedEnabled = true))
        assertFalse(TlsInspectionUiPolicy.canOfferTrafficStart())
        assertFalse(
            TlsInspectionUiPolicy.canOfferTrafficStart(
                reviewedDataPlane = false,
                certificateStateKnownInstalled = true,
                sessionConsentAcknowledged = true,
            ),
        )
    }

    @Test fun sensitive_and_unknown_app_categories_are_mandatory_exclusions() {
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.BANKING))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.PAYMENT))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.AUTHENTICATION))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.PASSWORD_MANAGER))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.HEALTH))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.UNKNOWN))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.SHARED))
        assertTrue(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.SHARED_UID))
        assertFalse(TlsInspectionUiPolicy.isMandatoryExcluded(TlsInspectionPackageCategory.GENERAL))
        assertTrue(TlsInspectionUiPolicy.canOfferPackageSelection(reviewedClassifierAvailable = true))
    }

    @Test fun certificate_status_mapping_keeps_unknown_distinct() {
        assertEquals(
            TlsInspectionCertificateUiState.UNKNOWN,
            TlsInspectionUiPolicy.certificateUiState(CertificateInstallationState.UNKNOWN),
        )
        assertEquals(
            TlsInspectionCertificateUiState.VERIFIED_INSTALLED,
            TlsInspectionUiPolicy.certificateUiState(CertificateInstallationState.INSTALLED),
        )
        assertTrue(TlsInspectionUiPolicy.requiresProminentStopControl(active = true))
        assertFalse(TlsInspectionUiPolicy.requiresProminentStopControl(active = false))
    }
}
