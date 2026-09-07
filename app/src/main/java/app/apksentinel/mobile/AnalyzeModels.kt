package app.apksentinel.mobile

import app.apksentinel.feature.apps.InstalledAppRecord

/** Evidence comparison data kept with the APK-analysis feature boundary. */
internal data class InstalledApkComparison(
    val installed: InstalledAppRecord,
    val sameSigner: Boolean?,
    val sameVersion: Boolean,
    val requestedPermissionsAdded: List<String>,
    val requestedPermissionsRemoved: List<String>,
    val selectedExportedComponentCount: Int,
)
