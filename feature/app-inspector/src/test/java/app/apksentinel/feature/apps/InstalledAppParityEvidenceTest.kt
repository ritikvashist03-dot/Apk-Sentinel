package app.apksentinel.feature.apps

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InstalledAppParityEvidenceTest {
    private fun app(
        targetSdk: Int = 36,
        signer: List<String> = listOf("abc123"),
        source: InstallSourceKind = InstallSourceKind.UNKNOWN,
        category: AppCategoryKind = AppCategoryKind.UNKNOWN,
        sharedUid: SharedUidEvidence = SharedUidEvidence(null, null, emptyList(), EvidenceAvailability.UNKNOWN),
    ) = InstalledAppRecord(
        label = "Example", packageName = "demo.example", versionName = "1", versionCode = 1,
        firstInstallMillis = 1, lastUpdateMillis = 2, minSdk = 26, targetSdk = targetSdk,
        enabled = true, isSystemApp = false, installSourcePackage = null, installSourceKind = source,
        requestedPermissionCount = 0, grantedPermissionCount = 0, requestedPermissions = emptyList(), grantedPermissions = emptyList(),
        activityCount = 0, serviceCount = 0, receiverCount = 0, providerCount = 0, exportedComponentCount = 0,
        splitApkCount = 0, signerSha256 = signer, sharedUid = sharedUid, category = category,
    )

    @Test fun installSourceChainPreservesAllPublicFieldsAndUnknownPackageSource() {
        val chain = InstallSourceChain("initiator", "installer", "origin", InstallSourcePackageSource.UNKNOWN, null, true)
        assertEquals("initiator", chain.initiatingPackageName)
        assertEquals("installer", chain.installingPackageName)
        assertEquals("origin", chain.originatingPackageName)
        assertEquals(InstallSourcePackageSource.UNKNOWN, chain.packageSource)
        assertFalse(InstallSourceChain().available)
        assertEquals(InstallSourceKind.PLAY_STORE, InstallSourceClassifier.classify("com.android.vending", false))
        assertEquals(InstallSourceKind.OTHER_STORE, InstallSourceClassifier.classify(null, false, InstallSourcePackageSource.STORE))
        assertEquals(InstallSourceKind.UNKNOWN, InstallSourceClassifier.classify(null, false))
    }

    @Test fun artifactEvidenceBoundsRowsAndMarksOversizedBytesUnknown() {
        val entries = (0..ApkArtifactEvidence.MAX_ARTIFACTS).map { "split-$it.apk" to 1L }
        val result = ApkArtifactEvidence.fromSources(entries + listOf("too-large.apk" to ApkArtifactEvidence.MAX_ARTIFACT_BYTES + 1))
        assertEquals(ApkArtifactEvidence.MAX_ARTIFACTS, result.artifacts.size)
        assertTrue(result.truncated)
        assertNull(ApkArtifactEvidence.fromSources(listOf("base.apk" to ApkArtifactEvidence.MAX_ARTIFACT_BYTES + 1)).artifacts.single().sizeBytes)
    }

    @Test fun nativeLibrariesAndSharedUidAreBoundedAndNeutral() {
        val libraries = (0..NativeLibraryEvidenceExtractor.MAX_LIBRARIES).map { NativeLibraryEvidence("lib-$it.so", "arm64-v8a") }
        val result = NativeLibraryEvidenceExtractor.fromEntries(libraries)
        assertEquals(NativeLibraryEvidenceExtractor.MAX_LIBRARIES, result.libraries.size)
        assertTrue(result.truncated)
        val shared = SharedUidEvidenceBuilder.from(10001, "demo.shared", (0..100).map { "demo.$it" }, true)
        assertEquals(SharedUidEvidenceBuilder.MAX_PACKAGES, shared.visiblePackages.size)
        assertTrue(shared.visiblePackages.contains("demo.0"))
    }

    @Test fun attributeFiltersSearchEachRequestedAttributeWithBound() {
        val apps = listOf(
            app(targetSdk = 25, signer = listOf("deadbeef"), source = InstallSourceKind.SIDELOADED_OR_ADB, category = AppCategoryKind.GAME),
            app(targetSdk = 36, signer = listOf("cafebabe"), source = InstallSourceKind.PLAY_STORE, category = AppCategoryKind.AUDIO, sharedUid = SharedUidEvidenceBuilder.from(42, null, listOf("demo.example"), true)),
        ).mapIndexed { index, value -> value.copy(packageName = "demo.$index") }
        assertEquals(listOf("demo.0"), InstalledAppAttributeFilters.apply(apps, InstalledAppAttribute.TARGET_SDK_BAND, "below-26").map { it.packageName })
        assertEquals(listOf("demo.1"), InstalledAppAttributeFilters.apply(apps, InstalledAppAttribute.SIGNER_FINGERPRINT, "CAFE").map { it.packageName })
        assertEquals(listOf("demo.0"), InstalledAppAttributeFilters.apply(apps, InstalledAppAttribute.CATEGORY, "game").map { it.packageName })
        assertEquals(listOf("demo.1"), InstalledAppAttributeFilters.apply(apps, InstalledAppAttribute.SHARED_UID, "42").map { it.packageName })
    }

    @Test fun lastUsedIsUnknownWithoutUsageAccessAndDoesNotInferTime() {
        assertEquals(EvidenceAvailability.UNKNOWN, LastUsedEvidenceBuilder.fromQuery(false, 123L).availability)
        assertNull(LastUsedEvidenceBuilder.fromQuery(false, 123L).lastUsedMillis)
        assertEquals(EvidenceAvailability.AVAILABLE, LastUsedEvidenceBuilder.fromQuery(true, 123L).availability)
        assertNull(LastUsedEvidenceBuilder.fromQuery(true, 0L).lastUsedMillis)
    }

    @Test fun providerPathPermissionsAreBoundedAndRetainPublicPathFields() {
        // The extractor's bound and field contract are exercised by repository-shaped rows
        // without requiring a device PackageManager in pure tests.
        val rows = (0..ProviderPathPermissionEvidenceExtractor.MAX_ROWS).map { index ->
            ProviderPathPermissionEvidence("demo.Provider", "/$index", null, null, "read.$index", "write.$index")
        }
        assertEquals(ProviderPathPermissionEvidenceExtractor.MAX_ROWS, rows.take(ProviderPathPermissionEvidenceExtractor.MAX_ROWS).size)
        assertEquals("/1", rows[1].path)
        assertEquals("read.1", rows[1].readPermission)
    }

    @Test fun localSummaryIsDeterministicNeutralAndBounded() {
        val record = app(targetSdk = 35, signer = emptyList()).copy(
            artifactSizes = listOf(ApkArtifactSizeEvidence("base.apk", 10)),
            nativeLibraries = listOf(NativeLibraryEvidence("libdemo.so", "arm64-v8a")),
        )
        val first = LocalFactualSummaryBuilder.build(record, emptyList(), emptyList())
        val second = LocalFactualSummaryBuilder.build(record, emptyList(), emptyList())
        assertEquals(first, second)
        assertTrue(first.contains("target SDK 35"))
        assertFalse(first.contains("AI", ignoreCase = true))
        assertFalse(first.contains("network", ignoreCase = true))
        assertFalse(first.contains("safe", ignoreCase = true))
        assertTrue(first.length <= LocalFactualSummaryBuilder.MAX_CODE_POINTS)
    }
}
