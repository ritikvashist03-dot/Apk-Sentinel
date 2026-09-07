package app.apksentinel.feature.apps

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

class InstalledAppFiltersTest {
    private val now = Instant.parse("2026-08-09T00:00:00Z").toEpochMilli()
    private fun app(label: String, source: InstallSourceKind, updatedOn: LocalDate = LocalDate.of(2026, 8, 9)) = InstalledAppRecord(
        label = label,
        packageName = "test.${label.lowercase()}",
        versionName = null,
        versionCode = 1,
        firstInstallMillis = now,
        lastUpdateMillis = updatedOn.atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli(),
        minSdk = 23,
        targetSdk = 36,
        enabled = true,
        isSystemApp = false,
        installSourcePackage = null,
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
        signerSha256 = emptyList(),
    )

    @Test fun searchMatchesLabelAndPackageCaseInsensitively() {
        val apps = listOf(app("Camera", InstallSourceKind.PLAY_STORE), app("Notes", InstallSourceKind.OTHER_STORE))
        assertEquals(listOf("Camera"), InstalledAppFilters.apply(apps, "CAM", false, null, now).map { it.label })
        assertEquals(listOf("Notes"), InstalledAppFilters.apply(apps, "test.notes", false, null, now).map { it.label })
    }

    @Test fun filtersSideloadedAndUpdateAgeWithoutCallingThemMalware() {
        val apps = listOf(app("Old", InstallSourceKind.SIDELOADED_OR_ADB, LocalDate.of(2025, 2, 9)), app("New", InstallSourceKind.SIDELOADED_OR_ADB, LocalDate.of(2026, 7, 9)), app("Store", InstallSourceKind.PLAY_STORE, LocalDate.of(2025, 2, 9)))
        assertEquals(listOf("Old"), InstalledAppFilters.apply(apps, "", true, 12, now).map { it.label })
    }

    @Test fun updateAgeThresholdsUseCalendarMonthsAndAllLeavesAppsUnfiltered() {
        val apps = listOf(
            app("Five", InstallSourceKind.PLAY_STORE, LocalDate.of(2026, 3, 9)),
            app("Six", InstallSourceKind.PLAY_STORE, LocalDate.of(2026, 2, 9)),
            app("Twelve", InstallSourceKind.PLAY_STORE, LocalDate.of(2025, 8, 9)),
            app("TwentyFour", InstallSourceKind.PLAY_STORE, LocalDate.of(2024, 8, 9)),
        )
        assertEquals(listOf("Five", "Six", "Twelve", "TwentyFour").sorted(), InstalledAppFilters.apply(apps, "", false, UpdateAgeFilter.ALL.months, now).map { it.label }.sorted())
        assertEquals(listOf("Six", "Twelve", "TwentyFour").sorted(), InstalledAppFilters.apply(apps, "", false, UpdateAgeFilter.SIX_MONTHS.months, now).map { it.label }.sorted())
        assertEquals(listOf("Twelve", "TwentyFour").sorted(), InstalledAppFilters.apply(apps, "", false, UpdateAgeFilter.TWELVE_MONTHS.months, now).map { it.label }.sorted())
        assertEquals(listOf("TwentyFour"), InstalledAppFilters.apply(apps, "", false, UpdateAgeFilter.TWENTY_FOUR_MONTHS.months, now).map { it.label })
    }

    @Test fun unknownLifecycleTimeIsNotMisclassifiedAsAStaleApp() {
        val unknown = app("Unknown", InstallSourceKind.OTHER_STORE).copy(lastUpdateMillis = 0L)
        assertEquals(null, unknown.monthsSinceUpdate(now))
        assertEquals(listOf("Unknown"), InstalledAppFilters.apply(listOf(unknown), "", false, null, now).map { it.label })
        assertEquals(emptyList<String>(), InstalledAppFilters.apply(listOf(unknown), "", false, 6, now).map { it.label })
    }

    @Test(expected = IllegalArgumentException::class)
    fun updateAgeFilterRejectsNegativeMonthThresholds() {
        InstalledAppFilters.apply(listOf(app("Current", InstallSourceKind.PLAY_STORE)), "", false, -1, now)
    }

    @Test fun permissionExplorerSearchesPermissionAppAndPackageWithNeutralFilters() {
        val rows = listOf(
            PermissionAppEvidence("android.permission.CAMERA", "Camera", "demo.camera", true, PermissionProtection.DANGEROUS),
            PermissionAppEvidence("android.permission.INTERNET", "Notes", "demo.notes", true, PermissionProtection.NORMAL),
            PermissionAppEvidence("demo.permission.INTERNAL", "Notes", "demo.notes", false, PermissionProtection.SIGNATURE),
        )
        assertEquals(listOf("demo.camera"), PermissionExplorerFilters.apply(rows, "camera", PermissionGrantFilter.REQUESTED, null).map { it.packageName })
        assertEquals(listOf("android.permission.INTERNET"), PermissionExplorerFilters.apply(rows, "", PermissionGrantFilter.GRANTED, PermissionProtection.NORMAL).map { it.permission })
        assertEquals(emptyList<String>(), PermissionExplorerFilters.apply(rows, "", PermissionGrantFilter.GRANTED, PermissionProtection.SIGNATURE).map { it.permission })
    }

    @Test fun permissionExplorerBoundsResultsDeterministically() {
        val rows = (0..PermissionExplorerFilters.MAX_ROWS).map { index ->
            PermissionAppEvidence("permission.$index", "App $index", "demo.$index", false, PermissionProtection.UNKNOWN)
        }
        val result = PermissionExplorerFilters.apply(rows, "", PermissionGrantFilter.REQUESTED, null)
        assertEquals(PermissionExplorerFilters.MAX_ROWS, result.size)
        assertTrue(result.all { it.protection == PermissionProtection.UNKNOWN })
    }

    @Test fun launcherContractRejectsUnexportedDisabledCrossPackageAndChangedTargets() {
        assertTrue(LauncherActionContract.isSafe("demo.safe", "demo.safe", "demo.safe.Main", exported = true, enabled = true))
        assertEquals(false, LauncherActionContract.isSafe("demo.safe", "demo.other", "demo.other.Main", exported = true, enabled = true))
        assertEquals(false, LauncherActionContract.isSafe("demo.safe", "demo.safe", "demo.safe.Hidden", exported = false, enabled = true))
        assertEquals(false, LauncherActionContract.isSafe("demo.safe", "demo.safe", "demo.safe.Main", exported = true, enabled = false))
        assertEquals(false, LauncherActionContract.isSafe("demo.safe", "demo.safe", "demo.safe.Changed", expectedClass = "demo.safe.Main", exported = true, enabled = true))
    }

    @Test fun snapshotsDistinguishFirstUnchangedChangedAndBoundedCoverage() {
        val current = mapOf("demo.one" to "a", "demo.two" to "b")
        assertEquals(InventorySnapshotState.FIRST_SCAN, InstalledAppChangeDetector.compare(null, current).state)
        assertEquals(InventorySnapshotState.UNCHANGED, InstalledAppChangeDetector.compare(current, current).state)
        val changed = InstalledAppChangeDetector.compare(current, mapOf("demo.one" to "new", "demo.three" to "c"))
        assertEquals(InventorySnapshotState.CHANGED, changed.state)
        assertEquals(1, changed.addedCount)
        assertEquals(1, changed.removedCount)
        assertEquals(1, changed.changedCount)
        assertEquals(InventorySnapshotState.COVERAGE_UNKNOWN, InstalledAppChangeDetector.compare(null, (0..InstalledAppChangeDetector.MAX_SNAPSHOT_APPS).associate { "demo.$it" to "x" }).state)
    }

    @Test fun knownSdkMarkersAreEvidenceOnlyAndUnknownMarkersAreIgnored() {
        val indicators = KnownSdkIndicators.fromMetadata(setOf("com.google.android.gms.ads.APPLICATION_ID", "other.marker"))
        assertEquals(listOf("Google Mobile Ads"), indicators.map { it.name })
        assertEquals(emptyList<SdkIndicatorEvidence>(), KnownSdkIndicators.fromMetadata(setOf("other.marker")))
    }

    @Test fun snapshotCodecRoundTripsOnlyBoundedLengthPrefixedEntries() {
        val entries = linkedMapOf("demo.one" to "fingerprint-one", "demo.two" to "fingerprint-two")
        assertEquals(entries, InstalledAppSnapshotCodec.decode(requireNotNull(InstalledAppSnapshotCodec.encode(entries))))
        assertEquals(null, InstalledAppSnapshotCodec.decode(byteArrayOf(0, 0, 0, 1, 0, 0, 16, 0)))
        assertEquals(null, InstalledAppSnapshotCodec.decode(ByteArray(256 * 1024 + 1)))
    }

    @Test fun snapshotCodecRejectsOversizedCollection() {
        val entries = (0..InstalledAppChangeDetector.MAX_SNAPSHOT_APPS).associate { "demo.$it" to "fingerprint" }
        assertEquals(null, InstalledAppSnapshotCodec.encode(entries))
    }

    @Test fun advancedInsightsAreBoundedAndDescribeEvidenceCoverageWithoutVerdicts() {
        val apps = (0..AdvancedInsightsAggregator.MAX_APPS).map { index ->
            app("App$index", if (index % 2 == 0) InstallSourceKind.SIDELOADED_OR_ADB else InstallSourceKind.PLAY_STORE).copy(
                packageName = "demo.$index",
                targetSdk = when (index % 4) { 0 -> 25; 1 -> 30; 2 -> 36; else -> 0 },
                isSystemApp = index % 3 == 0,
                signerSha256 = if (index % 2 == 0) listOf("hash") else emptyList(),
                activityCount = 2,
                exportedComponentCount = 1,
            )
        }
        val insights = AdvancedInsightsAggregator.from(apps, apps.take(AdvancedInsightsAggregator.MAX_APPS).associate { it.packageName to SdkIndicatorEvidenceResult(emptyList(), true) })
        assertEquals(AdvancedInsightsAggregator.MAX_APPS, insights.visibleApps)
        assertEquals(true, insights.truncated)
        assertEquals(AdvancedInsightsAggregator.MAX_APPS * 2, insights.components)
        assertEquals(AdvancedInsightsAggregator.MAX_APPS, insights.exportedComponents)
    }

    @Test fun advancedInsightsPartitionsSdkLevelsAndTreatsMissingSdkMetadataAsUnknownCoverage() {
        val apps = listOf(
            app("Legacy", InstallSourceKind.SYSTEM_IMAGE).copy(packageName = "demo.legacy", targetSdk = 25, activityCount = 1),
            app("Middle", InstallSourceKind.SIDELOADED_OR_ADB).copy(packageName = "demo.middle", targetSdk = 32, serviceCount = 2, exportedComponentCount = 1),
            app("Modern", InstallSourceKind.PLAY_STORE).copy(packageName = "demo.modern", targetSdk = 33, signerSha256 = listOf("hash")),
            app("Unknown", InstallSourceKind.UNKNOWN).copy(packageName = "demo.unknown", targetSdk = 0),
        )
        val insights = AdvancedInsightsAggregator.from(
            apps,
            mapOf(
                "demo.legacy" to SdkIndicatorEvidenceResult(listOf(SdkIndicatorEvidence("Google Mobile Ads", "key")), true),
                "demo.middle" to SdkIndicatorEvidenceResult(emptyList(), true),
                "demo.modern" to SdkIndicatorEvidenceResult(emptyList(), false),
            ),
        )
        assertEquals(1, insights.targetSdkBelow26)
        assertEquals(1, insights.targetSdk26To32)
        assertEquals(1, insights.targetSdk33Plus)
        assertEquals(1, insights.targetSdkUnknown)
        assertEquals(4, insights.targetSdkBelow26 + insights.targetSdk26To32 + insights.targetSdk33Plus + insights.targetSdkUnknown)
        assertEquals(3, insights.components)
        assertEquals(1, insights.exportedComponents)
        assertEquals(1, insights.sdkIndicatorApps)
        assertEquals(2, insights.sdkEvidenceUnknownApps)
    }
}
