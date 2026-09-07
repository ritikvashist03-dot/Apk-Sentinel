package app.apksentinel.feature.apps

import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InstalledAppReviewSynthesizerTest {
    @Test
    fun playInstallerAndSignerBecomeSupportingContextNotAuthenticityVerdict() {
        val app = record(InstallSourceKind.PLAY_STORE, listOf("sha256"))

        val summary = InstalledAppReviewSynthesizer.summarize(
            app = app,
            permissionEvidence = emptyList(),
            components = emptyList(),
            sdkIndicators = emptyList(),
            hardware = HardwareFeatureEvidenceResult(emptyList(), HardwareFeatureAvailability.AVAILABLE, false),
        )

        assertEquals(LocalContextStatus.SUPPORTING_EVIDENCE, summary.authenticityContext.status)
        assertEquals(LocalEvidenceConfidence.MEDIUM, summary.authenticityContext.confidence)
        assertTrue(summary.authenticityContext.limitations.any { it.contains("not a malware or adware verdict") })
    }

    @Test
    fun adSdkAndAdjacentCapabilityRemainLocalSignalsOnly() {
        val app = record(InstallSourceKind.UNKNOWN, emptyList())

        val summary = InstalledAppReviewSynthesizer.summarize(
            app = app,
            permissionEvidence = listOf(
                PermissionEvidence(
                    name = "android.permission.SYSTEM_ALERT_WINDOW",
                    granted = false,
                    protection = PermissionProtection.SIGNATURE,
                    group = null,
                ),
            ),
            components = emptyList(),
            sdkIndicators = listOf(SdkIndicatorEvidence("Google Mobile Ads", "ads.key")),
            hardware = HardwareFeatureEvidenceResult(emptyList(), HardwareFeatureAvailability.UNKNOWN, false),
        )

        // Not UNKNOWN: this fixture carries firstInstallMillis and lastUpdateMillis, and
        // InstalledAppReview counts each as local authenticity evidence, so the only
        // reachable outcome here is LOCAL_SIGNALS_ONLY. UNKNOWN requires a record with no
        // installer, no signer and no timestamps at all. The old expectation could never
        // have passed against this fixture; the assertion this test is actually named for
        // is the adware one below.
        assertEquals(LocalContextStatus.LOCAL_SIGNALS_ONLY, summary.authenticityContext.status)
        assertEquals(LocalContextStatus.LOCAL_SIGNALS_ONLY, summary.adwareContext.status)
        assertEquals(LocalEvidenceConfidence.LOW, summary.adwareContext.confidence)
    }

    private fun record(source: InstallSourceKind, signers: List<String>) = InstalledAppRecord(
        label = "Example",
        packageName = "com.example.app",
        versionName = "1.0",
        versionCode = 1,
        firstInstallMillis = 1,
        lastUpdateMillis = 2,
        minSdk = 26,
        targetSdk = 35,
        enabled = true,
        isSystemApp = false,
        installSourcePackage = if (source == InstallSourceKind.PLAY_STORE) "com.android.vending" else null,
        installSourceKind = source,
        requestedPermissionCount = 0,
        grantedPermissionCount = 0,
        requestedPermissions = emptyList(),
        grantedPermissions = emptyList(),
        activityCount = 0,
        serviceCount = 0,
        receiverCount = 0,
        providerCount = 0,
        exportedComponentCount = 0,
        splitApkCount = 0,
        signerSha256 = signers,
    )
}
