package app.apksentinel.engine.tlsinspection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsInspectionPolicyTest {
    @Test
    fun capabilityMatrixHasAnExplicitContainedRowForEveryAndroid26To36Api() {
        assertEquals((26..36).toSet(), AndroidTlsInspectionCapabilityMatrix.rows.keys)
        AndroidTlsInspectionCapabilityMatrix.rows.values.forEach { row ->
            assertEquals(TlsInspectionSupport.VARIES_BY_APP_OR_DEVICE, row.userAddedCaTrust)
            assertEquals(TlsInspectionSupport.UNSUPPORTED, row.certificatePinning)
            assertEquals(TlsInspectionSupport.UNSUPPORTED, row.nonHttpTls)
            assertEquals(TlsInspectionSupport.UNSUPPORTED, row.tls13)
            assertEquals(TlsInspectionSupport.UNSUPPORTED, row.quic)
            assertEquals(TlsInspectionSupport.UNSUPPORTED, row.universalHttpsDecryption)
            assertTrue(TlsInspectionLimitation.CERTIFICATE_PINNING_NOT_BYPASSED in row.limitations)
            assertTrue(TlsInspectionLimitation.NO_CREDENTIAL_OR_BODY_LOGGING in row.limitations)
        }
        assertEquals(null, AndroidTlsInspectionCapabilityMatrix.forApi(25))
        assertEquals(null, AndroidTlsInspectionCapabilityMatrix.forApi(37))
    }

    @Test
    fun highSensitivityAndUnknownCategoriesAreMandatoryExclusions() {
        TlsInspectionPackageScope.mandatoryExcludedCategories.forEach { category ->
            val result = TlsInspectionPackageScope.create(listOf(target("com.example.$category", category)))
            assertEquals(
                TlsInspectionPackageScopeRejection.SENSITIVE_CATEGORY_EXCLUDED,
                (result as TlsInspectionPackageScopeResult.Rejected).reason,
            )
        }
        val general = TlsInspectionPackageScope.create(listOf(target("com.example.reader", TlsInspectionPackageCategory.GENERAL)))
        assertTrue(general is TlsInspectionPackageScopeResult.Allowed)
    }

    @Test
    fun sharedUidCategoriesAreMandatoryExclusions() {
        listOf(TlsInspectionPackageCategory.SHARED, TlsInspectionPackageCategory.SHARED_UID).forEach { category ->
            val result = TlsInspectionPackageScope.create(listOf(target("com.example.shared", category)))
            assertEquals(
                TlsInspectionPackageScopeRejection.SENSITIVE_CATEGORY_EXCLUDED,
                (result as TlsInspectionPackageScopeResult.Rejected).reason,
            )
        }
        val sharedFlag = TlsInspectionPackageScope.create(
            listOf(TlsInspectionPackageTarget("com.example.flagged", TlsInspectionPackageCategory.GENERAL, sharedUid = true)),
        )
        assertEquals(
            TlsInspectionPackageScopeRejection.SENSITIVE_CATEGORY_EXCLUDED,
            (sharedFlag as TlsInspectionPackageScopeResult.Rejected).reason,
        )
    }

    @Test
    fun packageScopeIsBoundedAndNeverActsAsABroadCaptureSelection() {
        val empty = TlsInspectionPackageScope.create(emptyList()) as TlsInspectionPackageScopeResult.Rejected
        assertEquals(TlsInspectionPackageScopeRejection.EMPTY_SELECTION, empty.reason)

        val tooMany = (1..TlsInspectionPackageScope.MAX_SELECTED_PACKAGES + 1).map {
            target("com.example.app$it", TlsInspectionPackageCategory.GENERAL)
        }
        assertEquals(
            TlsInspectionPackageScopeRejection.TOO_MANY_PACKAGES,
            (TlsInspectionPackageScope.create(tooMany) as TlsInspectionPackageScopeResult.Rejected).reason,
        )

        val duplicate = listOf(
            target("com.example.reader", TlsInspectionPackageCategory.GENERAL),
            target("com.example.reader", TlsInspectionPackageCategory.GENERAL),
        )
        assertEquals(
            TlsInspectionPackageScopeRejection.DUPLICATE_PACKAGE,
            (TlsInspectionPackageScope.create(duplicate) as TlsInspectionPackageScopeResult.Rejected).reason,
        )
    }

    @Test
    fun certificateSetupAndInspectionConsentAreDifferentTypesAndSetupDoesNotStartAnything() {
        val provider = FakeCredentialProvider()
        val coordinator = TlsCertificateSetupCoordinator(
            credentialProvider = provider,
            removalGuidanceProvider = { state -> guidance(state) },
        )
        val result = coordinator.prepareUserMediatedInstall(CertificateSetupConsent("certificate-v1", 100L))

        assertTrue(result is CertificateSetupResult.ReadyForUserMediatedInstall)
        assertEquals(1, provider.provisionCalls)
    }

    private fun target(packageName: String, category: TlsInspectionPackageCategory) =
        TlsInspectionPackageTarget(packageName, category)
}

internal fun testCertificateMetadata(): TlsCaCertificateMetadata = TlsCaCertificateMetadata(
    alias = "test-tls-ca",
    subject = "CN=Test",
    serialNumberHex = "01",
    sha256Fingerprint = "a".repeat(64),
    notBeforeMillis = 1L,
    notAfterMillis = 2_000_000L,
    keyStorage = TlsPrivateKeyStorage.HOST_DEFINED_NON_EXPORTABLE,
)

internal fun guidance(state: CertificateInstallationState) = CertificateRemovalGuidance(
    title = "Remove",
    steps = listOf("Stop", "Remove through Android Settings", "Check status"),
    verificationState = state,
)

internal class FakeCredentialProvider(
    private val lookup: TlsCaCredentialLookup = TlsCaCredentialLookup.Available(testCertificateMetadata()),
) : TlsCaCredentialProvider {
    var provisionCalls = 0

    override fun existingMetadata(): TlsCaCredentialLookup = lookup

    override fun provisionForCertificateSetup(consent: CertificateSetupConsent): TlsCaCredentialProvisioning {
        provisionCalls += 1
        return TlsCaCredentialProvisioning.Available(testCertificateMetadata())
    }
}
