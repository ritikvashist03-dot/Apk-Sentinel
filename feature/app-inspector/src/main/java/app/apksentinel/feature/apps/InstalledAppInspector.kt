package app.apksentinel.feature.apps

import android.content.Context
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.FeatureInfo
import android.os.PatternMatcher
import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.os.Process
import android.provider.Settings
import android.os.Build
import android.graphics.Bitmap
import android.graphics.Canvas
import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.security.MessageDigest
import java.io.OutputStream
import java.io.FileInputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.CancellationException

enum class InstallSourceKind { PLAY_STORE, SYSTEM_IMAGE, OTHER_STORE, SIDELOADED_OR_ADB, UNKNOWN }

/** Public PackageInstaller source chain. Missing fields stay UNKNOWN/absent. */
enum class InstallSourcePackageSource { STORE, LOCAL_FILE, DOWNLOADED_FILE, OTHER, UNKNOWN }

data class InstallSourceChain(
    val initiatingPackageName: String? = null,
    val installingPackageName: String? = null,
    val originatingPackageName: String? = null,
    val packageSource: InstallSourcePackageSource = InstallSourcePackageSource.UNKNOWN,
    val packageSourceCode: Int? = null,
    val available: Boolean = false,
)

object InstallSourceClassifier {
    fun classify(installer: String?, systemImage: Boolean, packageSource: InstallSourcePackageSource = InstallSourcePackageSource.UNKNOWN): InstallSourceKind = when {
        systemImage -> InstallSourceKind.SYSTEM_IMAGE
        installer == "com.android.vending" -> InstallSourceKind.PLAY_STORE
        installer in setOf("com.android.packageinstaller", "com.google.android.packageinstaller", "com.android.permissioncontroller") -> InstallSourceKind.SIDELOADED_OR_ADB
        installer != null -> InstallSourceKind.OTHER_STORE
        packageSource == InstallSourcePackageSource.STORE -> InstallSourceKind.OTHER_STORE
        else -> InstallSourceKind.UNKNOWN
    }
}

enum class EvidenceAvailability { AVAILABLE, UNKNOWN }

data class ApkArtifactSizeEvidence(
    val name: String,
    val sizeBytes: Long?,
)

data class ApkArtifactSizeResult(
    val artifacts: List<ApkArtifactSizeEvidence>,
    val availability: EvidenceAvailability,
    val truncated: Boolean,
)

data class NativeLibraryEvidence(val name: String, val abi: String?)

data class NativeLibraryEvidenceResult(
    val libraries: List<NativeLibraryEvidence>,
    val availability: EvidenceAvailability,
    val truncated: Boolean,
)

data class SharedUidEvidence(
    val uid: Int?,
    val sharedUserId: String?,
    val visiblePackages: List<String>,
    val availability: EvidenceAvailability,
)

data class AppSecurityFlagEvidence(val name: String, val enabled: Boolean)

enum class AppCategoryKind { GAME, AUDIO, VIDEO, IMAGE, UNKNOWN }

data class ProviderPathPermissionEvidence(
    val provider: String,
    val path: String?,
    val pathPattern: String?,
    val pathPrefix: String?,
    val readPermission: String?,
    val writePermission: String?,
)

data class LastUsedEvidence(
    val lastUsedMillis: Long?,
    val availability: EvidenceAvailability,
    val usageAccessGranted: Boolean,
)

data class InstalledAppRecord(
    val label: String,
    val packageName: String,
    val versionName: String?,
    val versionCode: Long,
    val firstInstallMillis: Long,
    val lastUpdateMillis: Long,
    val minSdk: Int,
    val targetSdk: Int,
    val enabled: Boolean,
    val isSystemApp: Boolean,
    val installSourcePackage: String?,
    val installSourceKind: InstallSourceKind,
    val requestedPermissionCount: Int,
    val grantedPermissionCount: Int,
    val requestedPermissions: List<String>,
    val grantedPermissions: List<String>,
    val activityCount: Int,
    val serviceCount: Int,
    val receiverCount: Int,
    val providerCount: Int,
    val exportedComponentCount: Int,
    val splitApkCount: Int,
    val signerSha256: List<String>,
    val signerSha1: List<String> = emptyList(),
    val installSourceChain: InstallSourceChain = InstallSourceChain(),
    val artifactSizes: List<ApkArtifactSizeEvidence> = emptyList(),
    val artifactSizesAvailability: EvidenceAvailability = EvidenceAvailability.UNKNOWN,
    val artifactSizesTruncated: Boolean = false,
    val nativeLibraries: List<NativeLibraryEvidence> = emptyList(),
    val nativeLibrariesAvailability: EvidenceAvailability = EvidenceAvailability.UNKNOWN,
    val nativeLibrariesTruncated: Boolean = false,
    val sharedUid: SharedUidEvidence = SharedUidEvidence(null, null, emptyList(), EvidenceAvailability.UNKNOWN),
    val securityFlags: List<AppSecurityFlagEvidence> = emptyList(),
    val category: AppCategoryKind = AppCategoryKind.UNKNOWN,
) {
    fun monthsSinceUpdate(nowMillis: Long): Long? {
        if (lastUpdateMillis <= 0L || nowMillis < 0L) return null
        val updatedMonth = Instant.ofEpochMilli(lastUpdateMillis)
            .atZone(java.time.ZoneOffset.UTC).toLocalDate().withDayOfMonth(1)
        val currentMonth = Instant.ofEpochMilli(nowMillis)
            .atZone(java.time.ZoneOffset.UTC).toLocalDate().withDayOfMonth(1)
        return ChronoUnit.MONTHS.between(updatedMonth, currentMonth).coerceAtLeast(0)
    }
}

/** Pure bounds for paths Android exposes as installed APK artifacts. */
object ApkArtifactEvidence {
    const val MAX_ARTIFACTS = 64
    const val MAX_ARTIFACT_BYTES = 512L * 1024L * 1024L

    fun fromSources(sources: List<Pair<String, Long?>>): ApkArtifactSizeResult {
        val bounded = sources.asSequence()
            .filter { it.first.isNotBlank() }
            .distinctBy { it.first }
            .take(MAX_ARTIFACTS)
            .map { (name, bytes) ->
                ApkArtifactSizeEvidence(name.take(160), bytes?.takeIf { it in 0..MAX_ARTIFACT_BYTES })
            }
            .toList()
        return ApkArtifactSizeResult(
            artifacts = bounded,
            availability = if (bounded.isEmpty() && sources.isNotEmpty() || bounded.any { it.sizeBytes == null }) EvidenceAvailability.UNKNOWN else EvidenceAvailability.AVAILABLE,
            truncated = sources.count { it.first.isNotBlank() } > bounded.size,
        )
    }
}

/** Pure bounds/normalisation for native-library directory evidence. */
object NativeLibraryEvidenceExtractor {
    const val MAX_LIBRARIES = 128
    const val MAX_NAME_CODE_POINTS = 200

    fun fromEntries(entries: List<NativeLibraryEvidence>, available: Boolean = true): NativeLibraryEvidenceResult {
        val bounded = entries.asSequence()
            .filter { it.name.isNotBlank() }
            .distinctBy { it.name to it.abi }
            .take(MAX_LIBRARIES)
            .map { it.copy(name = it.name.take(MAX_NAME_CODE_POINTS), abi = it.abi?.take(MAX_NAME_CODE_POINTS)) }
            .toList()
        return NativeLibraryEvidenceResult(
            libraries = bounded,
            availability = if (available) EvidenceAvailability.AVAILABLE else EvidenceAvailability.UNKNOWN,
            truncated = entries.count { it.name.isNotBlank() } > bounded.size,
        )
    }
}

/** Shared UID is identity/context evidence only; it carries no maliciousness conclusion. */
object SharedUidEvidenceBuilder {
    const val MAX_PACKAGES = 64

    fun from(uid: Int?, sharedUserId: String?, visiblePackages: List<String>, available: Boolean): SharedUidEvidence {
        val packages = visiblePackages.asSequence()
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
            .take(MAX_PACKAGES)
            .toList()
        return SharedUidEvidence(uid, sharedUserId?.take(200), packages, if (available) EvidenceAvailability.AVAILABLE else EvidenceAvailability.UNKNOWN)
    }
}

/** Public ApplicationInfo flags only. A flag is a declaration, not a threat finding. */
object AppSecurityFlags {
    fun from(info: ApplicationInfo): List<AppSecurityFlagEvidence> = buildList {
        fun addFlag(name: String, enabled: Boolean) { add(AppSecurityFlagEvidence(name, enabled)) }
        addFlag("DEBUGGABLE", info.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        addFlag("TEST_ONLY", info.flags and ApplicationInfo.FLAG_TEST_ONLY != 0)
        addFlag("HAS_CODE", info.flags and ApplicationInfo.FLAG_HAS_CODE != 0)
        addFlag("ALLOW_CLEAR_USER_DATA", info.flags and ApplicationInfo.FLAG_ALLOW_CLEAR_USER_DATA != 0)
        addFlag("FACTORY_TEST", info.flags and ApplicationInfo.FLAG_FACTORY_TEST != 0)
        addFlag("VM_SAFE_MODE", info.flags and ApplicationInfo.FLAG_VM_SAFE_MODE != 0)
        addFlag("ALLOW_BACKUP", info.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0)
        addFlag("FULL_BACKUP_ONLY", info.flags and ApplicationInfo.FLAG_FULL_BACKUP_ONLY != 0)
        addFlag("KILL_AFTER_RESTORE", info.flags and ApplicationInfo.FLAG_KILL_AFTER_RESTORE != 0)
        addFlag("LARGE_HEAP", info.flags and ApplicationInfo.FLAG_LARGE_HEAP != 0)
        addFlag("EXTERNAL_STORAGE", info.flags and ApplicationInfo.FLAG_EXTERNAL_STORAGE != 0)
        addFlag("SUSPENDED", info.flags and ApplicationInfo.FLAG_SUSPENDED != 0)
        addFlag("STOPPED", info.flags and ApplicationInfo.FLAG_STOPPED != 0)
        if (Build.VERSION.SDK_INT >= 24) addFlag("IS_DATA_ONLY", info.flags and ApplicationInfo.FLAG_IS_DATA_ONLY != 0)
        addFlag("UPDATED_SYSTEM_APP", info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0)
        if (Build.VERSION.SDK_INT >= 23) addFlag("USES_CLEARTEXT_TRAFFIC", info.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0)
    }
}

object ProviderPathPermissionEvidenceExtractor {
    const val MAX_ROWS = 128

    fun from(providers: Array<android.content.pm.ProviderInfo>?): List<ProviderPathPermissionEvidence> = providers.orEmpty()
        .asSequence()
        .flatMap { provider ->
            provider.pathPermissions.orEmpty().asSequence().map { permission ->
                ProviderPathPermissionEvidence(
                    provider = provider.name,
                    path = permission.path.takeIf { permission.type == PatternMatcher.PATTERN_LITERAL },
                    pathPattern = permission.path.takeIf {
                        permission.type == PatternMatcher.PATTERN_SIMPLE_GLOB ||
                            permission.type == PatternMatcher.PATTERN_ADVANCED_GLOB ||
                            permission.type == PatternMatcher.PATTERN_SUFFIX
                    },
                    pathPrefix = permission.path.takeIf { permission.type == PatternMatcher.PATTERN_PREFIX },
                    readPermission = permission.readPermission,
                    writePermission = permission.writePermission,
                )
            }
        }
        .take(MAX_ROWS)
        .toList()
}

object LastUsedEvidenceBuilder {
    fun unknown(): LastUsedEvidence = LastUsedEvidence(null, EvidenceAvailability.UNKNOWN, usageAccessGranted = false)

    fun fromQuery(usageAccessGranted: Boolean, lastUsedMillis: Long?): LastUsedEvidence =
        if (!usageAccessGranted) unknown()
        else LastUsedEvidence(lastUsedMillis?.takeIf { it > 0L }, EvidenceAvailability.AVAILABLE, usageAccessGranted = true)
}

data class InstalledAppInventory(
    val apps: List<InstalledAppRecord>,
    val generatedAtMillis: Long,
    val visibilityNotice: String,
    val snapshot: InventorySnapshotResult,
)

enum class InventorySnapshotState { FIRST_SCAN, UNCHANGED, CHANGED, COVERAGE_UNKNOWN }

data class InventorySnapshotResult(
    val state: InventorySnapshotState,
    val addedCount: Int = 0,
    val removedCount: Int = 0,
    val changedCount: Int = 0,
)

/** Pure bounded comparison contract; it never assigns a security meaning to a change. */
object InstalledAppChangeDetector {
    const val MAX_SNAPSHOT_APPS = 500

    fun compare(previous: Map<String, String>?, current: Map<String, String>): InventorySnapshotResult {
        if (current.size > MAX_SNAPSHOT_APPS) return InventorySnapshotResult(InventorySnapshotState.COVERAGE_UNKNOWN)
        if (previous == null) return InventorySnapshotResult(InventorySnapshotState.FIRST_SCAN)
        val added = (current.keys - previous.keys).size
        val removed = (previous.keys - current.keys).size
        val changed = current.keys.intersect(previous.keys).count { current[it] != previous[it] }
        return if (added + removed + changed == 0) InventorySnapshotResult(InventorySnapshotState.UNCHANGED)
        else InventorySnapshotResult(InventorySnapshotState.CHANGED, added, removed, changed)
    }

    fun fingerprint(app: InstalledAppRecord): String = listOf(
        app.versionCode,
        app.lastUpdateMillis,
        app.enabled,
        app.installSourcePackage.orEmpty(),
        app.installSourceChain.initiatingPackageName.orEmpty(),
        app.installSourceChain.installingPackageName.orEmpty(),
        app.installSourceChain.originatingPackageName.orEmpty(),
        app.installSourceChain.packageSource.name,
        app.sharedUid.uid ?: -1,
        app.signerSha256.sorted().joinToString(","),
    ).joinToString("|")
}

/** Length-prefixed, bounded plaintext codec. Ciphertext is the only persisted form. */
object InstalledAppSnapshotCodec {
    private const val MAX_BYTES = 256 * 1024
    private const val MAX_FIELD_BYTES = 2 * 1024

    fun encode(entries: Map<String, String>): ByteArray? = runCatching {
        if (entries.size > InstalledAppChangeDetector.MAX_SNAPSHOT_APPS) return null
        val output = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(output).use { stream ->
            stream.writeInt(entries.size)
            entries.toSortedMap().forEach { (name, fingerprint) ->
                writeField(stream, name)
                writeField(stream, fingerprint)
            }
        }
        output.toByteArray().takeIf { it.size <= MAX_BYTES }
    }.getOrNull()

    fun decode(payload: ByteArray): Map<String, String>? = runCatching {
        if (payload.size !in 4..MAX_BYTES) return null
        val input = java.io.DataInputStream(java.io.ByteArrayInputStream(payload))
        val count = input.readInt()
        if (count !in 0..InstalledAppChangeDetector.MAX_SNAPSHOT_APPS) return null
        val result = LinkedHashMap<String, String>(count)
        repeat(count) {
            val name = readField(input) ?: return null
            val fingerprint = readField(input) ?: return null
            if (name.isBlank() || result.put(name, fingerprint) != null) return null
        }
        if (input.available() != 0) return null
        result
    }.getOrNull()

    private fun writeField(stream: java.io.DataOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_FIELD_BYTES)
        stream.writeInt(bytes.size)
        stream.write(bytes)
    }

    private fun readField(input: java.io.DataInputStream): String? {
        val length = input.readInt()
        if (length !in 1..MAX_FIELD_BYTES || length > input.available()) return null
        return ByteArray(length).also(input::readFully).toString(Charsets.UTF_8)
    }
}

enum class InstalledAppSnapshotEraseResult { ERASED, FAILED }

object InstalledAppSnapshotController {
    fun erase(context: Context): InstalledAppSnapshotEraseResult {
        val encrypted = encryptedStorage(context)
        val removed = encrypted.remove(SNAPSHOT_KEY) is SecureStorageResult.Success
        val legacyCleared = context.getSharedPreferences(LEGACY_PREFS, Context.MODE_PRIVATE).edit().clear().commit()
        return if (removed && legacyCleared && encrypted.deleteEncryptionKey()) InstalledAppSnapshotEraseResult.ERASED
        else InstalledAppSnapshotEraseResult.FAILED
    }

    internal fun encryptedStorage(context: Context) = AndroidKeystoreEncryptedStorage(
        context.getSharedPreferences(SECURE_PREFS, Context.MODE_PRIVATE), KEY_ALIAS, NAMESPACE,
    )

    internal val SNAPSHOT_KEY = SecureStorageKey("installed-app-snapshot-v1")
    private const val SECURE_PREFS = "installed_app_snapshot_secure"
    private const val LEGACY_PREFS = "installed_app_snapshot"
    private const val KEY_ALIAS = "apk_sentinel.installed_app_snapshot.v1"
    private const val NAMESPACE = "installed_app_snapshot"
}

private class InstalledAppSnapshotStore(private val context: Context) {
    fun compareAndSave(apps: List<InstalledAppRecord>): InventorySnapshotResult {
        val current = apps.associate { it.packageName to InstalledAppChangeDetector.fingerprint(it) }
        if (!context.getSharedPreferences("installed_app_snapshot", Context.MODE_PRIVATE).edit().clear().commit()) return unknown()
        if (current.size > InstalledAppChangeDetector.MAX_SNAPSHOT_APPS) return unknown()
        val storage = InstalledAppSnapshotController.encryptedStorage(context)
        val previous: Map<String, String>? = when (val read = storage.read(InstalledAppSnapshotController.SNAPSHOT_KEY)) {
            is SecureStorageResult.Success -> read.value?.let(InstalledAppSnapshotCodec::decode) ?: if (read.value == null) null else return unknown()
            is SecureStorageResult.Failure -> return unknown()
        }
        val result = InstalledAppChangeDetector.compare(previous, current)
        val encoded = InstalledAppSnapshotCodec.encode(current) ?: return unknown()
        return if (storage.write(InstalledAppSnapshotController.SNAPSHOT_KEY, encoded) is SecureStorageResult.Success) result else unknown()
    }

    private fun unknown() = InventorySnapshotResult(InventorySnapshotState.COVERAGE_UNKNOWN)
}

data class SdkIndicatorEvidence(val name: String, val manifestKey: String)
data class SdkIndicatorEvidenceResult(val indicators: List<SdkIndicatorEvidence>, val available: Boolean)

enum class HardwareFeatureAvailability { AVAILABLE, UNKNOWN }
data class HardwareFeatureEvidence(val name: String, val required: Boolean)
data class HardwareFeatureEvidenceResult(
    val features: List<HardwareFeatureEvidence>,
    val availability: HardwareFeatureAvailability,
    val truncated: Boolean,
)

data class AdvancedInsights(
    val visibleApps: Int,
    val systemApps: Int,
    val sideloadedEvidenceApps: Int,
    val targetSdkBelow26: Int,
    val targetSdk26To32: Int,
    val targetSdk33Plus: Int,
    val targetSdkUnknown: Int,
    val signerAvailable: Int,
    val signerUnavailable: Int,
    val components: Int,
    val exportedComponents: Int,
    val sdkIndicatorApps: Int,
    val sdkEvidenceUnknownApps: Int,
    val truncated: Boolean,
)

object AdvancedInsightsAggregator {
    const val MAX_APPS = 500

    fun from(apps: List<InstalledAppRecord>, sdkResults: Map<String, SdkIndicatorEvidenceResult>): AdvancedInsights {
        val covered = apps.sortedBy { it.packageName }.take(MAX_APPS)
        return AdvancedInsights(
            visibleApps = covered.size,
            systemApps = covered.count { it.isSystemApp },
            sideloadedEvidenceApps = covered.count { it.installSourceKind == InstallSourceKind.SIDELOADED_OR_ADB },
            targetSdkBelow26 = covered.count { it.targetSdk in 1..25 },
            targetSdk26To32 = covered.count { it.targetSdk in 26..32 },
            targetSdk33Plus = covered.count { it.targetSdk >= 33 },
            targetSdkUnknown = covered.count { it.targetSdk <= 0 },
            signerAvailable = covered.count { it.signerSha256.isNotEmpty() },
            signerUnavailable = covered.count { it.signerSha256.isEmpty() },
            components = covered.sumOf { it.activityCount + it.serviceCount + it.receiverCount + it.providerCount },
            exportedComponents = covered.sumOf { it.exportedComponentCount },
            sdkIndicatorApps = covered.count { sdkResults[it.packageName]?.indicators?.isNotEmpty() == true },
            sdkEvidenceUnknownApps = covered.count { sdkResults[it.packageName]?.available != true },
            truncated = apps.size > covered.size,
        )
    }
}

/** Known manifest metadata markers only; absence does not establish that an SDK is absent. */
object KnownSdkIndicators {
    private val markers = listOf(
        "Google Mobile Ads" to "com.google.android.gms.ads.APPLICATION_ID",
        "Meta Audience Network" to "com.facebook.sdk.ApplicationId",
        "AppLovin MAX" to "applovin.sdk.key",
        "Unity Ads" to "com.unity3d.ads.metadata.gameId",
    )

    fun fromMetadata(keys: Set<String>): List<SdkIndicatorEvidence> = markers
        .filter { (_, key) -> key in keys }
        .map { (name, key) -> SdkIndicatorEvidence(name, key) }
}

data class PermissionEvidence(
    val name: String,
    val granted: Boolean,
    val protection: PermissionProtection,
    val group: String?,
)

/** Package-manager metadata category, not a risk or misuse conclusion. */
enum class PermissionProtection { DANGEROUS, SIGNATURE, NORMAL, UNKNOWN }

/** One bounded, manifest-derived permission-to-app relationship. */
data class PermissionAppEvidence(
    val permission: String,
    val appLabel: String,
    val packageName: String,
    val granted: Boolean,
    val protection: PermissionProtection,
)

data class PermissionAppEvidenceResult(val rows: List<PermissionAppEvidence>, val truncated: Boolean)

enum class PermissionGrantFilter { REQUESTED, GRANTED }

/** A launcher target Android itself resolved for this installed package. */
data class LauncherActionEvidence(
    val component: ComponentName,
)

/** Pure contract used before an Android launcher target is exposed or launched. */
object LauncherActionContract {
    fun isSafe(
        expectedPackage: String,
        resolvedPackage: String?,
        resolvedClass: String?,
        expectedClass: String? = null,
        exported: Boolean,
        enabled: Boolean,
    ): Boolean = expectedPackage.isNotBlank() && expectedPackage == resolvedPackage &&
        !resolvedClass.isNullOrBlank() && (expectedClass == null || expectedClass == resolvedClass) && exported && enabled
}

/**
 * A bounded, PackageManager-derived manifest component record. This is exposure
 * context, not an exploitability or malware assessment.
 */
data class ComponentEvidence(
    val name: String,
    val kind: ComponentKind,
    val exported: Boolean,
    val requiredPermission: String?,
)

enum class ComponentKind { ACTIVITY, SERVICE, RECEIVER, PROVIDER }

data class InstallBundleExport(
    val bytesCopied: Long,
    val apkFileCount: Int,
)

data class IconExport(val width: Int, val height: Int)

/**
 * A deliberately small, presentation-safe error vocabulary for user-selected
 * document exports.  It avoids leaking package-install paths or provider
 * exception text into the UI.
 */
sealed interface InstalledExportResult<out T> {
    data class Saved<T>(val value: T) : InstalledExportResult<T>
    data object PackageUnavailable : InstalledExportResult<Nothing>
    data object DestinationUnavailable : InstalledExportResult<Nothing>
    data object LimitReached : InstalledExportResult<Nothing>
    data object Failed : InstalledExportResult<Nothing>
}

private class InstalledExportLimitException(message: String) : IllegalStateException(message)

object InstalledAppFilters {
    fun apply(
        apps: List<InstalledAppRecord>,
        query: String,
        sideloadedOnly: Boolean,
        staleMonths: Int?,
        nowMillis: Long,
    ): List<InstalledAppRecord> {
        require(staleMonths == null || staleMonths >= 0) { "Update-age months cannot be negative." }
        val needle = query.trim().lowercase()
        return apps.asSequence()
            .filter { needle.isBlank() || it.label.lowercase().contains(needle) || it.packageName.lowercase().contains(needle) }
            .filter { !sideloadedOnly || it.installSourceKind == InstallSourceKind.SIDELOADED_OR_ADB }
            .filter { app ->
                staleMonths == null || app.monthsSinceUpdate(nowMillis)?.let { it >= staleMonths } == true
            }
            .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER) { it.label })
            .toList()
    }
}

object PermissionExplorerFilters {
    const val MAX_ROWS = 1_000

    fun apply(
        evidence: List<PermissionAppEvidence>,
        query: String,
        grantFilter: PermissionGrantFilter,
        protection: PermissionProtection?,
    ): List<PermissionAppEvidence> {
        val needle = query.trim().lowercase()
        return evidence.asSequence()
            .filter { grantFilter != PermissionGrantFilter.GRANTED || it.granted }
            .filter { protection == null || it.protection == protection }
            .filter {
                needle.isBlank() || it.permission.lowercase().contains(needle) ||
                    it.appLabel.lowercase().contains(needle) || it.packageName.lowercase().contains(needle)
            }
            .sortedWith(compareBy<PermissionAppEvidence, String>(String.CASE_INSENSITIVE_ORDER) { it.permission }
                .thenBy(String.CASE_INSENSITIVE_ORDER) { it.appLabel }
                .thenBy { it.packageName })
            .take(MAX_ROWS)
            .toList()
    }
}

enum class InstalledAppAttribute {
    TARGET_SDK_BAND,
    SIGNER_FINGERPRINT,
    ORIGIN,
    CATEGORY,
    SHARED_UID,
}

object InstalledAppAttributeFilters {
    const val MAX_ROWS = 500

    fun targetSdkBand(targetSdk: Int): String = when {
        targetSdk in 1..25 -> "below-26"
        targetSdk in 26..32 -> "26-32"
        targetSdk >= 33 -> "33-plus"
        else -> "unknown"
    }

    fun categoryValue(category: AppCategoryKind): String = when (category) {
        AppCategoryKind.GAME -> "game"
        AppCategoryKind.AUDIO -> "audio"
        AppCategoryKind.VIDEO -> "video"
        AppCategoryKind.IMAGE -> "image"
        AppCategoryKind.UNKNOWN -> "unknown"
    }

    fun originValue(app: InstalledAppRecord): String = listOfNotNull(
        app.installSourceKind.name.lowercase(),
        app.installSourceChain.packageSource.name.lowercase(),
        app.installSourceChain.installingPackageName,
        app.installSourceChain.initiatingPackageName,
        app.installSourceChain.originatingPackageName,
    ).joinToString(" ")

    fun apply(
        apps: List<InstalledAppRecord>,
        attribute: InstalledAppAttribute,
        query: String,
    ): List<InstalledAppRecord> {
        val needle = query.trim().lowercase()
        return apps.asSequence()
            .filter { app ->
                val value = when (attribute) {
                    InstalledAppAttribute.TARGET_SDK_BAND -> targetSdkBand(app.targetSdk)
                    InstalledAppAttribute.SIGNER_FINGERPRINT -> app.signerSha256.joinToString(" ") + " " + app.signerSha1.joinToString(" ")
                    InstalledAppAttribute.ORIGIN -> originValue(app)
                    InstalledAppAttribute.CATEGORY -> categoryValue(app.category)
                    InstalledAppAttribute.SHARED_UID -> listOfNotNull(app.sharedUid.uid?.toString(), app.sharedUid.sharedUserId, app.sharedUid.visiblePackages.joinToString(" ")).joinToString(" ")
                }
                needle.isBlank() || value.lowercase().contains(needle) || app.label.lowercase().contains(needle) || app.packageName.lowercase().contains(needle)
            }
            .sortedWith(compareBy<InstalledAppRecord, String>(String.CASE_INSENSITIVE_ORDER) { it.label }.thenBy { it.packageName })
            .take(MAX_ROWS)
            .toList()
    }
}

/** Update age is a review aid, never a malware classification. */
enum class UpdateAgeFilter(val months: Int?) {
    ALL(null),
    SIX_MONTHS(6),
    TWELVE_MONTHS(12),
    TWENTY_FOUR_MONTHS(24),
}

object InstalledAppComponents {
    const val MAX_COMPONENTS = 100

    fun from(
        activities: Array<android.content.pm.ActivityInfo>?,
        services: Array<android.content.pm.ServiceInfo>?,
        receivers: Array<android.content.pm.ActivityInfo>?,
        providers: Array<android.content.pm.ProviderInfo>?,
    ): List<ComponentEvidence> = buildList {
        activities.orEmpty().forEach { add(it.toEvidence(ComponentKind.ACTIVITY, it.permission)) }
        services.orEmpty().forEach { add(it.toEvidence(ComponentKind.SERVICE, it.permission)) }
        receivers.orEmpty().forEach { add(it.toEvidence(ComponentKind.RECEIVER, it.permission)) }
        providers.orEmpty().forEach { add(it.toEvidence(ComponentKind.PROVIDER, it.readPermission ?: it.writePermission)) }
    }.sortedWith(
        compareByDescending<ComponentEvidence> { it.exported }
            .thenBy { it.kind.ordinal }
            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name },
    ).take(MAX_COMPONENTS)

    private fun android.content.pm.ComponentInfo.toEvidence(kind: ComponentKind, requiredPermission: String?) = ComponentEvidence(
        name = name,
        kind = kind,
        exported = exported,
        requiredPermission = requiredPermission,
    )
}

class InstalledAppRepository(private val context: Context) {
    private val packageManager = context.packageManager
    private val snapshotStore = InstalledAppSnapshotStore(context)

    @Suppress("DEPRECATION")
    fun load(): InstalledAppInventory {
        val mask = PackageManager.GET_PERMISSIONS.toLong() or PackageManager.GET_SIGNING_CERTIFICATES.toLong() or
            PackageManager.GET_ACTIVITIES.toLong() or PackageManager.GET_SERVICES.toLong() or
            PackageManager.GET_RECEIVERS.toLong() or PackageManager.GET_PROVIDERS.toLong()
        val packages = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(mask))
        } else {
            packageManager.getInstalledPackages(mask.toInt())
        }
        val packagesByUid = packages.asSequence()
            .mapNotNull { info -> info.applicationInfo?.uid?.let { it to info.packageName } }
            .groupBy({ it.first }, { it.second })
        val records = packages.mapNotNull { info -> runCatching { info.toRecord(packagesByUid[info.applicationInfo?.uid].orEmpty()) }.getOrNull() }
        return InstalledAppInventory(
            apps = records,
            generatedAtMillis = System.currentTimeMillis(),
            visibilityNotice = context.getString(R.string.visibility_notice),
            snapshot = snapshotStore.compareAndSave(records),
        )
    }

    @Suppress("DEPRECATION")
    fun find(packageName: String): InstalledAppRecord? = runCatching {
        val mask = PackageManager.GET_PERMISSIONS.toLong() or PackageManager.GET_SIGNING_CERTIFICATES.toLong() or
            PackageManager.GET_ACTIVITIES.toLong() or PackageManager.GET_SERVICES.toLong() or
            PackageManager.GET_RECEIVERS.toLong() or PackageManager.GET_PROVIDERS.toLong()
        val info = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(mask))
        } else {
            packageManager.getPackageInfo(packageName, mask.toInt())
        }
        info.toRecord(visiblePackagesForUid(info.applicationInfo?.uid))
    }.getOrNull()

    @Suppress("DEPRECATION")
    fun permissionEvidence(record: InstalledAppRecord): List<PermissionEvidence> = record.requestedPermissions.map { permission ->
        val info = runCatching { packageManager.getPermissionInfo(permission, 0) }.getOrNull()
        val base = info?.protectionLevel?.and(PermissionInfo.PROTECTION_MASK_BASE)
        val protection = when (base) {
            PermissionInfo.PROTECTION_DANGEROUS -> PermissionProtection.DANGEROUS
            PermissionInfo.PROTECTION_SIGNATURE -> PermissionProtection.SIGNATURE
            PermissionInfo.PROTECTION_NORMAL -> PermissionProtection.NORMAL
            else -> PermissionProtection.UNKNOWN
        }
        PermissionEvidence(
            name = permission,
            granted = permission in record.grantedPermissions,
            protection = protection,
            group = info?.group,
        )
    }.sortedWith(compareByDescending<PermissionEvidence> { it.granted }.thenBy { it.name })

    /**
     * Bounded by visible packages and requested permissions. Missing PackageManager
     * metadata remains UNKNOWN; it is never interpreted as evidence of harmful behavior.
     */
    fun permissionAppEvidence(apps: List<InstalledAppRecord>): PermissionAppEvidenceResult {
        val rows = buildList {
        appLoop@ for (app in apps.asSequence().sortedBy { it.packageName }) {
            permissionEvidence(app).forEach { permission ->
                if (size < PermissionExplorerFilters.MAX_ROWS) {
                    add(
                    PermissionAppEvidence(permission.name, app.label, app.packageName, permission.granted, permission.protection),
                    )
                }
            }
            if (size == PermissionExplorerFilters.MAX_ROWS) break@appLoop
        }
        }
        return PermissionAppEvidenceResult(rows, apps.sumOf { it.requestedPermissionCount } > rows.size)
    }

    @Suppress("DEPRECATION")
    fun launcherActionEvidence(record: InstalledAppRecord): LauncherActionEvidence? = runCatching {
        val query = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setPackage(record.packageName)
        val resolved = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.queryIntentActivities(query, PackageManager.ResolveInfoFlags.of(0))
        } else packageManager.queryIntentActivities(query, 0)
        val target = resolved.asSequence()
            .mapNotNull { it.activityInfo }
            .firstOrNull { LauncherActionContract.isSafe(record.packageName, it.packageName, it.name, exported = it.exported, enabled = it.enabled) }
            ?: return null
        val component = ComponentName(target.packageName, target.name)
        val explicit = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setComponent(component)
        val finalTarget = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.resolveActivity(explicit, PackageManager.ResolveInfoFlags.of(0))?.activityInfo
        } else packageManager.resolveActivity(explicit, 0)?.activityInfo
        if (!LauncherActionContract.isSafe(record.packageName, finalTarget?.packageName, finalTarget?.name, target.name, finalTarget?.exported == true, finalTarget?.enabled == true)) return null
        LauncherActionEvidence(component)
    }.getOrNull()

    fun launchResolvedLauncher(action: LauncherActionEvidence): Boolean = runCatching {
        val intent = Intent(Intent.ACTION_MAIN)
            .addCategory(Intent.CATEGORY_LAUNCHER)
            .setComponent(action.component)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val target = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(0))?.activityInfo
        } else packageManager.resolveActivity(intent, 0)?.activityInfo
        check(LauncherActionContract.isSafe(action.component.packageName, target?.packageName, target?.name, action.component.className, target?.exported == true, target?.enabled == true))
        context.startActivity(intent)
        true
    }.getOrDefault(false)

    @Suppress("DEPRECATION")
    fun componentEvidence(record: InstalledAppRecord): List<ComponentEvidence> = runCatching {
        val mask = PackageManager.GET_ACTIVITIES.toLong() or PackageManager.GET_SERVICES.toLong() or
            PackageManager.GET_RECEIVERS.toLong() or PackageManager.GET_PROVIDERS.toLong()
        val info = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getPackageInfo(record.packageName, PackageManager.PackageInfoFlags.of(mask))
        } else {
            packageManager.getPackageInfo(record.packageName, mask.toInt())
        }
        InstalledAppComponents.from(info.activities, info.services, info.receivers, info.providers)
    }.getOrDefault(emptyList())

    @Suppress("DEPRECATION")
    fun providerPathPermissionEvidence(record: InstalledAppRecord): List<ProviderPathPermissionEvidence> = runCatching {
        val mask = PackageManager.GET_PROVIDERS.toLong()
        val info = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getPackageInfo(record.packageName, PackageManager.PackageInfoFlags.of(mask))
        } else packageManager.getPackageInfo(record.packageName, mask.toInt())
        ProviderPathPermissionEvidenceExtractor.from(info.providers)
    }.getOrDefault(emptyList())

    /** Last-used is deliberately not folded into the inventory unless Usage Access is granted. */
    fun lastUsedEvidence(record: InstalledAppRecord, nowMillis: Long = System.currentTimeMillis()): LastUsedEvidence {
        if (!hasUsageAccess()) return LastUsedEvidenceBuilder.unknown()
        return runCatching {
            val manager = context.getSystemService(UsageStatsManager::class.java) ?: return@runCatching LastUsedEvidenceBuilder.unknown()
            val from = (nowMillis - 30L * 24L * 60L * 60L * 1_000L).coerceAtLeast(0L)
            val lastUsed = manager.queryUsageStats(UsageStatsManager.INTERVAL_BEST, from, nowMillis)
                .orEmpty()
                .filter { it.packageName == record.packageName }
                .maxOfOrNull { it.lastTimeUsed }
            LastUsedEvidenceBuilder.fromQuery(true, lastUsed)
        }.getOrElse { LastUsedEvidenceBuilder.unknown() }
    }

    fun hasUsageAccess(): Boolean = if (Build.VERSION.SDK_INT < 23) false else runCatching {
        val appOps = context.getSystemService(AppOpsManager::class.java) ?: return@runCatching false
        appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) == AppOpsManager.MODE_ALLOWED
    }.getOrDefault(false)

    fun usageAccessSettingsIntent(): Intent = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)

    @Suppress("DEPRECATION")
    fun sdkIndicatorEvidence(record: InstalledAppRecord): List<SdkIndicatorEvidence> = runCatching {
        sdkIndicatorEvidenceResult(record).indicators
    }.getOrDefault(emptyList())

    @Suppress("DEPRECATION")
    fun sdkIndicatorEvidenceResult(record: InstalledAppRecord): SdkIndicatorEvidenceResult = runCatching {
        val appInfo = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getApplicationInfo(record.packageName, PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()))
        } else packageManager.getApplicationInfo(record.packageName, PackageManager.GET_META_DATA)
        SdkIndicatorEvidenceResult(KnownSdkIndicators.fromMetadata(appInfo.metaData?.keySet().orEmpty()), available = true)
    }.getOrElse { SdkIndicatorEvidenceResult(emptyList(), available = false) }

    fun advancedInsights(apps: List<InstalledAppRecord>): AdvancedInsights {
        val covered = apps.sortedBy { it.packageName }.take(AdvancedInsightsAggregator.MAX_APPS)
        return AdvancedInsightsAggregator.from(apps, covered.associate { it.packageName to sdkIndicatorEvidenceResult(it) })
    }

    @Suppress("DEPRECATION")
    fun hardwareFeatureEvidence(record: InstalledAppRecord): HardwareFeatureEvidenceResult = runCatching {
        val flags = PackageManager.GET_CONFIGURATIONS.toLong()
        val info = if (Build.VERSION.SDK_INT >= 33) packageManager.getPackageInfo(record.packageName, PackageManager.PackageInfoFlags.of(flags))
        else packageManager.getPackageInfo(record.packageName, flags.toInt())
        val features = info.reqFeatures.orEmpty().asSequence()
            .mapNotNull { feature -> feature.name?.takeIf { it.isNotBlank() }?.let { HardwareFeatureEvidence(it, feature.flags and FeatureInfo.FLAG_REQUIRED != 0) } }
            .distinctBy { it.name }
            .sortedBy { it.name }
            .take(MAX_HARDWARE_FEATURES)
            .toList()
        HardwareFeatureEvidenceResult(features, HardwareFeatureAvailability.AVAILABLE, info.reqFeatures.orEmpty().count { it.name?.isNotBlank() == true } > features.size)
    }.getOrElse { HardwareFeatureEvidenceResult(emptyList(), HardwareFeatureAvailability.UNKNOWN, false) }

    suspend fun exportBaseApk(packageName: String, output: OutputStream): InstalledExportResult<Long> =
        exportSafely { copyBaseApk(packageName, output) }

    suspend fun exportInstallBundle(packageName: String, output: OutputStream): InstalledExportResult<InstallBundleExport> =
        exportSafely { copyInstallBundle(packageName, output) }

    suspend fun exportIconPng(packageName: String, output: OutputStream): InstalledExportResult<IconExport> =
        exportSafely { copyIconPng(packageName, output) }

    private suspend fun <T> exportSafely(block: suspend () -> T): InstalledExportResult<T> = try {
        InstalledExportResult.Saved(block())
    } catch (error: CancellationException) {
        throw error
    } catch (_: PackageManager.NameNotFoundException) {
        InstalledExportResult.PackageUnavailable
    } catch (_: SecurityException) {
        InstalledExportResult.DestinationUnavailable
    } catch (_: InstalledExportLimitException) {
        InstalledExportResult.LimitReached
    } catch (_: Exception) {
        InstalledExportResult.Failed
    }

    suspend fun copyBaseApk(packageName: String, output: OutputStream, maxBytes: Long = 512L * 1024L * 1024L): Long {
        require(maxBytes > 0)
        val appInfo = packageManager.getApplicationInfo(packageName, 0)
        var total = 0L
        java.io.FileInputStream(appInfo.sourceDir).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                currentCoroutineContext().ensureActive()
                val read = input.read(buffer)
                if (read < 0) break
                total += read
                if (total > maxBytes) throw InstalledExportLimitException("Installed base APK exceeds the export limit.")
                output.write(buffer, 0, read)
            }
        }
        output.flush()
        return total
    }

    /**
     * Saves the installed base and every split as one local ZIP/APKS bundle.
     * The bundle is evidence/backup material; Android compatibility, signatures,
     * and device configuration still determine whether it can be reinstalled.
     */
    suspend fun copyInstallBundle(
        packageName: String,
        output: OutputStream,
        maxTotalBytes: Long = 768L * 1024L * 1024L,
        maxApkFiles: Int = 256,
    ): InstallBundleExport {
        require(maxTotalBytes > 0)
        require(maxApkFiles > 0)
        val appInfo = packageManager.getApplicationInfo(packageName, 0)
        val sources = buildList {
            add("base.apk" to appInfo.sourceDir)
            appInfo.splitSourceDirs.orEmpty().forEachIndexed { index, path -> add("split_${index + 1}.apk" to path) }
        }
        if (sources.size > maxApkFiles) throw InstalledExportLimitException("Installed package contains too many split APK files to export safely.")
        var total = 0L
        ZipOutputStream(output.buffered()).use { zip ->
            val buffer = ByteArray(64 * 1024)
            sources.forEach { (entryName, sourcePath) ->
                zip.putNextEntry(ZipEntry(entryName).apply { time = 0L })
                FileInputStream(sourcePath).use { input ->
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > maxTotalBytes) throw InstalledExportLimitException("Installed APK set exceeds the export limit.")
                        zip.write(buffer, 0, read)
                    }
                }
                zip.closeEntry()
            }
        }
        return InstallBundleExport(total, sources.size)
    }

    suspend fun copyIconPng(packageName: String, output: OutputStream, maximumDimension: Int = 512): IconExport {
        currentCoroutineContext().ensureActive()
        require(maximumDimension in 48..1_024)
        val drawable = packageManager.getApplicationIcon(packageName)
        val intrinsicWidth = drawable.intrinsicWidth.takeIf { it > 0 } ?: maximumDimension
        val intrinsicHeight = drawable.intrinsicHeight.takeIf { it > 0 } ?: maximumDimension
        val scale = minOf(1f, maximumDimension.toFloat() / maxOf(intrinsicWidth, intrinsicHeight).toFloat())
        val width = maxOf(1, (intrinsicWidth * scale).toInt())
        val height = maxOf(1, (intrinsicHeight * scale).toInt())
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        try {
            drawable.setBounds(0, 0, width, height)
            drawable.draw(Canvas(bitmap))
            check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) { "Android could not encode the app icon as PNG." }
            currentCoroutineContext().ensureActive()
            output.flush()
        } finally {
            bitmap.recycle()
        }
        return IconExport(width, height)
    }

    @Suppress("DEPRECATION")
    private fun PackageInfo.toRecord(visiblePackagesForUid: List<String>): InstalledAppRecord {
        val app = requireNotNull(applicationInfo)
        val legacyInstaller = if (Build.VERSION.SDK_INT >= 30) null else runCatching { packageManager.getInstallerPackageName(packageName) }.getOrNull()
        val installSourceInfo = if (Build.VERSION.SDK_INT >= 30) runCatching { packageManager.getInstallSourceInfo(packageName) }.getOrNull() else null
        val chain = InstallSourceChain(
            initiatingPackageName = installSourceInfo?.initiatingPackageName,
            installingPackageName = installSourceInfo?.installingPackageName ?: legacyInstaller,
            originatingPackageName = installSourceInfo?.originatingPackageName,
            packageSourceCode = if (Build.VERSION.SDK_INT >= 33) installSourceInfo?.packageSource else null,
            packageSource = packageSourceKind(if (Build.VERSION.SDK_INT >= 33) installSourceInfo?.packageSource else null),
            available = installSourceInfo != null || legacyInstaller != null,
        )
        val installer = chain.installingPackageName
        val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val permissions = requestedPermissions.orEmpty()
        val flags = requestedPermissionsFlags ?: IntArray(0)
        val signerBytes = when {
            Build.VERSION.SDK_INT >= 28 -> signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty()
            else -> signatures?.map { it.toByteArray() }.orEmpty()
        }
        val artifactEvidence = apkArtifactEvidence(app)
        val libraryEvidence = nativeLibraryEvidence(app)
        return InstalledAppRecord(
            label = SafeTextNormalizer.normalizeDisplayText(packageManager.getApplicationLabel(app).toString(), packageName),
            packageName = packageName,
            versionName = versionName,
            versionCode = if (Build.VERSION.SDK_INT >= 28) longVersionCode else versionCode.toLong(),
            firstInstallMillis = firstInstallTime,
            lastUpdateMillis = lastUpdateTime,
            minSdk = app.minSdkVersion,
            targetSdk = app.targetSdkVersion,
            enabled = app.enabled,
            isSystemApp = isSystem,
            installSourcePackage = installer,
            installSourceKind = InstallSourceClassifier.classify(installer, isSystem, chain.packageSource),
            requestedPermissionCount = permissions.size,
            grantedPermissionCount = permissions.indices.count { index -> flags.getOrNull(index)?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0 },
            requestedPermissions = permissions.sorted().take(500),
            grantedPermissions = permissions.indices
                .filter { index -> flags.getOrNull(index)?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0 }
                .map { permissions[it] }
                .sorted()
                .take(500),
            activityCount = activities.orEmpty().size,
            serviceCount = services.orEmpty().size,
            receiverCount = receivers.orEmpty().size,
            providerCount = providers.orEmpty().size,
            exportedComponentCount = activities.orEmpty().count { it.exported } +
                services.orEmpty().count { it.exported } +
                receivers.orEmpty().count { it.exported } +
                providers.orEmpty().count { it.exported },
            splitApkCount = app.splitSourceDirs?.size ?: 0,
            signerSha256 = signerBytes.map { MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { byte -> "%02x".format(byte) } },
            signerSha1 = signerBytes.map { MessageDigest.getInstance("SHA-1").digest(it).joinToString("") { byte -> "%02x".format(byte) } },
            installSourceChain = chain,
            artifactSizes = artifactEvidence.artifacts,
            artifactSizesAvailability = artifactEvidence.availability,
            artifactSizesTruncated = artifactEvidence.truncated,
            nativeLibraries = libraryEvidence.libraries,
            nativeLibrariesAvailability = libraryEvidence.availability,
            nativeLibrariesTruncated = libraryEvidence.truncated,
            sharedUid = SharedUidEvidenceBuilder.from(app.uid, sharedUserId, visiblePackagesForUid, visiblePackagesForUid.isNotEmpty()),
            securityFlags = AppSecurityFlags.from(app),
            category = appCategory(app.category),
        )
    }

    private fun apkArtifactEvidence(app: ApplicationInfo): ApkArtifactSizeResult = ApkArtifactEvidence.fromSources(
        buildList {
            add("base.apk" to fileSize(app.sourceDir))
            app.splitSourceDirs.orEmpty().forEachIndexed { index, path -> add("split_${index + 1}.apk" to fileSize(path)) }
        },
    )

    private fun nativeLibraryEvidence(app: ApplicationInfo): NativeLibraryEvidenceResult {
        val directory = app.nativeLibraryDir?.let { path -> java.io.File(path) }
        val available = directory?.isDirectory == true
        val entries = runCatching {
            directory?.listFiles().orEmpty().asSequence()
                .filter { it.isFile && it.name.endsWith(".so", ignoreCase = true) }
                // ApplicationInfo exposes the library directory, but the ABI fields
                // are hidden/non-SDK APIs. Keep ABI unknown rather than guessing it.
                .map { NativeLibraryEvidence(it.name, null) }
                .toList()
        }.getOrDefault(emptyList())
        return NativeLibraryEvidenceExtractor.fromEntries(entries, available)
    }

    private fun fileSize(path: String?): Long? = path?.let { runCatching { java.io.File(it).takeIf { file -> file.isFile }?.length() }.getOrNull() }

    @Suppress("DEPRECATION")
    private fun visiblePackagesForUid(uid: Int?): List<String> = uid?.let { targetUid -> runCatching {
        val mask = PackageManager.GET_META_DATA.toLong()
        val packages = if (Build.VERSION.SDK_INT >= 33) packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(mask))
        else packageManager.getInstalledPackages(mask.toInt())
        packages.filter { it.applicationInfo?.uid == targetUid }.map { it.packageName }
    }.getOrDefault(emptyList()) }.orEmpty()

    private fun packageSourceKind(code: Int?): InstallSourcePackageSource = when (code) {
        1 -> InstallSourcePackageSource.OTHER
        2 -> InstallSourcePackageSource.STORE
        3 -> InstallSourcePackageSource.LOCAL_FILE
        4 -> InstallSourcePackageSource.DOWNLOADED_FILE
        else -> InstallSourcePackageSource.UNKNOWN
    }

    private fun appCategory(category: Int): AppCategoryKind = when (category) {
        ApplicationInfo.CATEGORY_GAME -> AppCategoryKind.GAME
        ApplicationInfo.CATEGORY_AUDIO -> AppCategoryKind.AUDIO
        ApplicationInfo.CATEGORY_VIDEO -> AppCategoryKind.VIDEO
        ApplicationInfo.CATEGORY_IMAGE -> AppCategoryKind.IMAGE
        else -> AppCategoryKind.UNKNOWN
    }

    private companion object { const val MAX_HARDWARE_FEATURES = 64 }
}
