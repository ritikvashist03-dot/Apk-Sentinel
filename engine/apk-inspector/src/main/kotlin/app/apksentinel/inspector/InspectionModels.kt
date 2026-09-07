package app.apksentinel.inspector

import java.util.concurrent.CancellationException

/**
 * A blocking inspection is intentionally cancellable rather than owning a thread.
 * Call [ApkInspector.inspect] from an I/O dispatcher or worker.
 */
data class ApkInspectionRequest(
    val limits: InspectionLimits = InspectionLimits(),
    val cancellation: InspectionCancellation = InspectionCancellation.None,
    val progressListener: InspectionProgressListener = InspectionProgressListener { },
)

data class InspectionLimits(
    val maxInputBytes: Long = 256L * 1024L * 1024L,
    val maxArchiveEntries: Int = 20_000,
    val maxTotalUncompressedBytes: Long = 512L * 1024L * 1024L,
    val maxEntryUncompressedBytes: Long = 64L * 1024L * 1024L,
    val maxCompressionRatio: Double = 100.0,
    val maxHeuristicBytesPerEntry: Int = 512 * 1024,
    val maxTotalHeuristicBytes: Long = 8L * 1024L * 1024L,
    val maxInventoryPathsPerKind: Int = 250,
    val maxHeuristicFindings: Int = 100,
    val maxManifestPermissions: Int = 2_000,
    val maxManifestComponents: Int = 5_000,
    val maxManifestFeatures: Int = 1_000,
    /** Bounded intent-filter evidence retained across the entire manifest. */
    val maxManifestIntentFilters: Int = 512,
    /** Bounded intent-filter evidence retained for one component. */
    val maxIntentFiltersPerComponent: Int = 32,
    val maxIntentFilterActionsPerFilter: Int = 32,
    val maxIntentFilterCategoriesPerFilter: Int = 32,
    val maxIntentFilterDataPerFilter: Int = 32,
    val maxIntentFilterPathsPerData: Int = 8,
    /** Per technical attribute value, measured after UTF-8-safe normalization. */
    val maxIntentFilterValueBytes: Int = 512,
    val maxDecodedManifestBytes: Int = 2 * 1024 * 1024,
    /** Maximum number of nested APK entries examined in a bundle container. */
    val maxBundleApkCount: Int = 64,
    /** Maximum bytes copied from one nested APK entry. */
    val maxBundleApkBytes: Long = 256L * 1024L * 1024L,
    /** Maximum bytes copied from all nested APK entries together. */
    val maxBundleTotalApkBytes: Long = 512L * 1024L * 1024L,
    /** Maximum uncompressed bytes observed while scanning one nested APK. */
    val maxBundleApkExpandedBytes: Long = 512L * 1024L * 1024L,
    /** Maximum uncompressed bytes observed across all nested APKs. */
    val maxBundleTotalExpandedBytes: Long = 1L * 1024L * 1024L * 1024L,
    /** Maximum bounded UTF-8 entry-name evidence retained by bundle inspection. */
    val maxBundlePathBytes: Int = 512,
    /** Maximum bytes read from an XAPK metadata entry. */
    val maxBundleMetadataBytes: Int = 256 * 1024,
    /** Maximum UTF-8 bytes retained for one metadata value. */
    val maxBundleMetadataValueBytes: Int = 512,
    /** Maximum OBB inventory rows retained. OBB payloads are never inspected. */
    val maxBundleObbEntries: Int = 32,
    /** Maximum declared bytes represented by the bounded OBB inventory. */
    val maxBundleTotalObbBytes: Long = 2L * 1024L * 1024L * 1024L,
    /** Maximum publishing-bundle module names retained from an Android App Bundle. */
    val maxAabModules: Int = 128,
    /** Maximum bounded entry rows retained for Android App Bundle evidence. */
    val maxAabEvidenceEntries: Int = 2_000,
) {
    init {
        require(maxInputBytes > 0)
        require(maxArchiveEntries > 0)
        require(maxTotalUncompressedBytes > 0)
        require(maxEntryUncompressedBytes > 0)
        require(maxCompressionRatio >= 1.0)
        require(maxHeuristicBytesPerEntry > 0)
        require(maxTotalHeuristicBytes > 0)
        require(maxInventoryPathsPerKind > 0)
        require(maxHeuristicFindings > 0)
        require(maxManifestPermissions > 0)
        require(maxManifestComponents > 0)
        require(maxManifestFeatures > 0)
        require(maxManifestIntentFilters > 0)
        require(maxIntentFiltersPerComponent > 0)
        require(maxIntentFilterActionsPerFilter > 0)
        require(maxIntentFilterCategoriesPerFilter > 0)
        require(maxIntentFilterDataPerFilter > 0)
        require(maxIntentFilterPathsPerData > 0)
        require(maxIntentFilterValueBytes in 16..8 * 1024)
        require(maxDecodedManifestBytes in 128..8 * 1024 * 1024) {
            "maxDecodedManifestBytes must leave room for a well-formed truncated XML document."
        }
        require(maxBundleApkCount > 0)
        require(maxBundleApkBytes > 0)
        require(maxBundleTotalApkBytes >= maxBundleApkBytes)
        require(maxBundleApkExpandedBytes > 0)
        require(maxBundleTotalExpandedBytes >= maxBundleApkExpandedBytes)
        require(maxBundlePathBytes in 16..8 * 1024)
        require(maxBundleMetadataBytes in 128..8 * 1024 * 1024)
        require(maxBundleMetadataValueBytes in 16..8 * 1024)
        require(maxBundleObbEntries > 0)
        require(maxBundleTotalObbBytes > 0)
        require(maxAabModules > 0)
        require(maxAabEvidenceEntries > 0)
    }
}

fun interface InspectionCancellation {
    fun isCancelled(): Boolean

    companion object {
        val None: InspectionCancellation = InspectionCancellation { false }
    }
}

fun interface InspectionProgressListener {
    fun onProgress(progress: InspectionProgress)
}

data class InspectionProgress(
    val stage: InspectionStage,
    val code: InspectionProgressCode,
    val bytesProcessed: Long? = null,
    val bytesLimit: Long? = null,
    val entriesProcessed: Int? = null,
)

/** Stable progress identifiers. The caller supplies localized display text. */
enum class InspectionProgressCode {
    PREPARING_PRIVATE_COPY,
    COPYING_PRIVATE_ARTIFACT,
    INSPECTING_ARCHIVE,
    PARSING_MANIFEST,
    VERIFYING_SIGNATURE,
    SCORING_RISK,
    COMPLETE,
}

enum class InspectionStage {
    COPY_INPUT,
    INSPECT_ARCHIVE,
    INSPECT_MANIFEST,
    VERIFY_SIGNATURE,
    SCORE_RISK,
    COMPLETE,
}

class InspectionCancelledException : CancellationException(
    "APK inspection was cancelled by the caller.",
)

data class ApkInspectionResult(
    val source: SourceArtifact? = null,
    val archive: ArchiveMetadata? = null,
    val manifest: ManifestSummary? = null,
    val signing: SigningSummary? = null,
    val decodedManifest: DecodedManifestText? = null,
    val inventory: ArchiveInventory? = null,
    val findings: List<HeuristicFinding> = emptyList(),
    val risk: RiskAssessment? = null,
    val failures: List<InspectionFailure> = emptyList(),
    val stoppedForSafety: Boolean = false,
    /** Present only when bounded evidence proves this artifact contains APKs. */
    val bundle: BundleInspection? = null,
) {
    /**
     * A complete result means the engine reached every applicable inspection phase.
     * A verified signature is not required for completion; it is a result, not a
     * scanner error.
     */
    val isComplete: Boolean
        get() = source != null && archive != null && !stoppedForSafety && failures.isEmpty() &&
            (bundle == null || bundle.isComplete)
}

/** A split/APKS, XAPK, or publishing AAB container. This is evidence, not an installability claim. */
data class BundleInspection(
    val format: BundleFormat,
    val nestedApks: List<BundleApkEntry>,
    val obbFiles: List<BundleObbEntry>,
    val metadata: BundleMetadata?,
    val limitations: List<BundleLimitationCode> = emptyList(),
    val nestedApkBytes: Long,
    val nestedExpandedBytes: Long,
    val isComplete: Boolean,
    /** Whether one base APK is trustworthy enough to represent the bundle. */
    val identityStatus: BundleIdentityStatus = BundleIdentityStatus.UNAVAILABLE,
    /** Publishing-bundle evidence is present only for an Android App Bundle (.aab). */
    val publishingEvidence: AabPublishingEvidence? = null,
) {
    init {
        require(nestedApkBytes >= 0)
        require(nestedExpandedBytes >= 0)
    }
}

/** Typed identity state for bundle-level evidence. It is not an installability claim. */
enum class BundleIdentityStatus {
    VERIFIED,
    INCOMPLETE,
    INCONSISTENT,
    UNAVAILABLE,
}

enum class BundleFormat {
    APKS,
    XAPK,
    /** Google Play publishing input; it is not directly installable. */
    AAB,
}

/**
 * Bounded, name-and-size-only evidence from an Android App Bundle.
 *
 * An AAB contains module manifests and publishing metadata, not installable
 * APKs. APK Sentinel intentionally does not turn this evidence into an APK,
 * run bundletool, or claim that the publishing input can be installed.
 */
data class AabPublishingEvidence(
    val modules: List<AabModuleEvidence>,
    val bundleConfigPresent: Boolean,
    val metadataPaths: List<String>,
    val entryCount: Int,
    val declaredBytes: Long,
    val isComplete: Boolean,
)

data class AabModuleEvidence(
    val name: String,
    val entryCount: Int,
    val declaredBytes: Long,
    val hasManifest: Boolean,
    val hasDex: Boolean,
    val hasResources: Boolean,
)

enum class BundleApkRole {
    BASE,
    FEATURE,
    CONFIG,
    UNKNOWN,
}

data class BundleApkEntry(
    val path: String,
    val role: BundleApkRole,
    val byteCount: Long,
    val expandedBytes: Long?,
    val sha256: String?,
    val archive: ArchiveMetadata?,
    val inventory: ArchiveInventory?,
    val manifest: ManifestSummary?,
    val decodedManifest: DecodedManifestText?,
    val signing: SigningSummary?,
    val findings: List<HeuristicFinding> = emptyList(),
    val failures: List<InspectionFailureCode> = emptyList(),
)

/** OBB names and declared sizes only; OBB contents are intentionally not inspected. */
data class BundleObbEntry(
    val path: String,
    val byteCount: Long?,
)

data class BundleMetadata(
    val packageName: String?,
    val versionCode: Long?,
    val versionName: String?,
    val declaredApkPaths: List<String> = emptyList(),
    val declaredBaseApkPaths: List<String> = emptyList(),
    val declaredObbPaths: List<String> = emptyList(),
    val isTrusted: Boolean,
)

enum class BundleLimitationCode {
    MISSING_BASE,
    DUPLICATE_BASE,
    IDENTITY_UNAVAILABLE,
    NESTED_EVIDENCE_INCOMPLETE,
    NESTED_APK_UNREADABLE,
    NESTED_EVIDENCE_BOUNDED,
    NESTED_APK_LIMIT_REACHED,
    NESTED_EXPANSION_LIMIT_REACHED,
    METADATA_LIMIT_REACHED,
    CONTAINER_LIMIT_REACHED,
    UNSAFE_PATH,
    METADATA_UNTRUSTED,
    IDENTITY_MISMATCH,
    SIGNER_MISMATCH,
    SIGNER_UNAVAILABLE,
    OBB_INVENTORY_TRUNCATED,
    BUNDLE_NOT_INSTALLABILITY_VERIFIED,
    /** An AAB is a publishing input; no installable APK was produced. */
    AAB_PUBLISHING_BUNDLE_ONLY,
    /** The bounded AAB module/entry inventory was capped. */
    AAB_EVIDENCE_BOUNDED,
}

data class SourceArtifact(
    val byteCount: Long,
    val sha256: String,
)

data class ArchiveMetadata(
    val format: ArchiveFormat,
    val entryCount: Int,
    val declaredCompressedBytes: Long,
    val declaredUncompressedBytes: Long,
    val observedUncompressedBytes: Long,
    val entriesWithUnknownCompressedSize: Int,
    val entriesWithUnknownUncompressedSize: Int,
    val maximumObservedCompressionRatio: Double?,
    val containsAndroidManifest: Boolean,
    val pathTraversalEntryCount: Int,
    val isComplete: Boolean,
)

enum class ArchiveFormat {
    ZIP,
}

data class ArchiveInventory(
    val dexFiles: PathInventory,
    val nativeLibraries: NativeLibraryInventory,
    val assets: PathInventory,
)

data class PathInventory(
    val count: Int,
    val samplePaths: List<String>,
    val isTruncated: Boolean,
)

data class NativeLibraryInventory(
    val count: Int,
    val samplePaths: List<String>,
    val abiCounts: Map<String, Int>,
    val isTruncated: Boolean,
)

data class ManifestSummary(
    val packageName: String,
    val versionName: String?,
    val versionCode: Long?,
    val sdk: AndroidSdkSummary,
    val permissions: List<String>,
    val permissionsTruncated: Boolean,
    val components: List<ManifestComponent>,
    val componentsTruncated: Boolean,
    val debugBuild: Boolean?,
    val hardwareFeatures: List<HardwareFeatureSummary> = emptyList(),
    val hardwareFeaturesTruncated: Boolean = false,
    /** True when the global bounded intent-filter collection stopped early. */
    val intentFiltersTruncated: Boolean = false,
)

data class HardwareFeatureSummary(
    val name: String?,
    val openGlEsVersion: Int?,
    val required: Boolean,
)

data class DecodedManifestText(
    val xml: String,
    val unresolvedResourceReferenceCount: Int,
    val isTruncated: Boolean,
)

data class AndroidSdkSummary(
    val minSdk: Int?,
    val targetSdk: Int?,
)

data class ManifestComponent(
    val type: ComponentType,
    val className: String,
    val exported: Boolean?,
    val enabled: Boolean?,
    val requiredPermission: String?,
    /** Bounded declarative routing evidence from this selected APK only. */
    val intentFilters: List<IntentFilterEvidence> = emptyList(),
    /** True when filters for this component exceeded a configured limit. */
    val intentFiltersTruncated: Boolean = false,
)

enum class ComponentType {
    ACTIVITY,
    SERVICE,
    RECEIVER,
    PROVIDER,
}

/**
 * A declarative Android intent filter. Values are technical manifest evidence,
 * not a claim that a component will run, receive traffic, or expose data.
 */
data class IntentFilterEvidence(
    val actions: List<String>,
    val categories: List<String>,
    val data: List<IntentFilterDataEvidence>,
    val actionsTruncated: Boolean = false,
    val categoriesTruncated: Boolean = false,
    val dataTruncated: Boolean = false,
    val manifestTruncated: Boolean = false,
) {
    val isTruncated: Boolean
        get() = manifestTruncated || actionsTruncated || categoriesTruncated || dataTruncated || data.any { it.isTruncated }
}

/** One bounded `<data>` declaration from an intent filter. */
data class IntentFilterDataEvidence(
    val scheme: String? = null,
    val host: String? = null,
    val port: String? = null,
    val paths: List<IntentFilterPathEvidence> = emptyList(),
    val mimeType: String? = null,
    val pathsTruncated: Boolean = false,
    val valuesTruncated: Boolean = false,
) {
    val isTruncated: Boolean
        get() = pathsTruncated || valuesTruncated
}

data class IntentFilterPathEvidence(
    val kind: IntentFilterPathKind,
    val value: String,
)

enum class IntentFilterPathKind {
    LITERAL,
    PREFIX,
    PATTERN,
    ADVANCED_PATTERN,
    SUFFIX,
}

data class SigningSummary(
    val status: SignatureVerificationStatus,
    val certificates: List<SigningCertificateSummary>,
    val verifiedSchemes: List<String>,
    val diagnostics: List<SigningDiagnosticCode>,
)

/** Stable signing diagnostic identifiers with no verifier/provider prose. */
enum class SigningDiagnosticCode {
    SIGNATURE_NOT_VALID,
    SIGNATURE_VERIFICATION_UNAVAILABLE,
}

enum class SignatureVerificationStatus {
    VERIFIED,
    NOT_VERIFIED,
    UNAVAILABLE,
}

data class SigningCertificateSummary(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val sha256: String,
    val sha1: String = "",
)

data class HeuristicFinding(
    /**
     * A stable, exhaustive identifier for the literal signal. Callers own all
     * wording and must not infer execution, collection, or transmission from it.
     */
    val code: HeuristicFindingCode,
    val severity: FindingSeverity,
    val confidence: FindingConfidence,
    /** Bounded, structured technical values rather than preformatted prose. */
    val evidence: List<ApkTechnicalEvidence>,
) {
    /** Retained category for filtering; it is derived so it cannot disagree with [code]. */
    val kind: FindingKind
        get() = code.kind
}

enum class FindingKind {
    UNSAFE_ARCHIVE_PATH,
    TRACKER_NAMESPACE,
    EMBEDDED_ENDPOINT,
}

/**
 * Do not replace these values with provider labels or translated strings. They
 * are a stable local-analysis contract for UI and export adapters to map.
 */
enum class HeuristicFindingCode(
    val kind: FindingKind,
) {
    UNSAFE_ARCHIVE_PATH(FindingKind.UNSAFE_ARCHIVE_PATH),
    TRACKER_FIREBASE_ANALYTICS(FindingKind.TRACKER_NAMESPACE),
    TRACKER_GOOGLE_MEASUREMENT(FindingKind.TRACKER_NAMESPACE),
    TRACKER_FACEBOOK(FindingKind.TRACKER_NAMESPACE),
    TRACKER_APPSFLYER(FindingKind.TRACKER_NAMESPACE),
    TRACKER_ADJUST(FindingKind.TRACKER_NAMESPACE),
    TRACKER_MIXPANEL(FindingKind.TRACKER_NAMESPACE),
    TRACKER_AMPLITUDE(FindingKind.TRACKER_NAMESPACE),
    TRACKER_SENTRY(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_GOOGLE_MOBILE_ADS(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_UNITY_ADS(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_APPLOVIN(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_IRONSOURCE(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_VUNGLE(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_CHARTBOOST(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_INMOBI(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_PANGLE(FindingKind.TRACKER_NAMESPACE),
    AD_NETWORK_MINTEGRAL(FindingKind.TRACKER_NAMESPACE),
    EMBEDDED_HTTP_ENDPOINT(FindingKind.EMBEDDED_ENDPOINT),
}

/** Stable catalog IDs. These are identifiers, not assertions about a vendor's behaviour. */
enum class TrackerNamespaceCode {
    FIREBASE_ANALYTICS,
    GOOGLE_MEASUREMENT,
    FACEBOOK,
    APPSFLYER,
    ADJUST,
    MIXPANEL,
    AMPLITUDE,
    SENTRY,
    // Advertising networks. Kept distinct from the analytics/telemetry namespaces above:
    // the archive scanner previously matched com/google/android/gms/measurement but not
    // com/google/android/gms/ads, so an ad-supported APK produced no ad-network evidence
    // at all when analysed as a file.
    GOOGLE_MOBILE_ADS,
    UNITY_ADS,
    APPLOVIN,
    IRONSOURCE,
    VUNGLE,
    CHARTBOOST,
    INMOBI,
    PANGLE,
    MINTEGRAL,
}

/**
 * Raw values are bounded at their collection point and intentionally remain
 * structured. A renderer must HTML/CSV/JSON-encode them as data and provide its
 * own localized labels; this engine never constructs a user-facing sentence
 * from an archive path, endpoint, provider, or exception.
 */
sealed interface ApkTechnicalEvidence {
    data class ArchiveEntryPath(val value: String) : ApkTechnicalEvidence
    data class TrackerNamespaceMatch(
        val tracker: TrackerNamespaceCode,
        val marker: String,
    ) : ApkTechnicalEvidence
    data class EndpointLiteral(val value: String) : ApkTechnicalEvidence
    data class PathTraversalCount(val value: Int) : ApkTechnicalEvidence
    data class ArchiveLimitObservation(
        val limit: ArchiveLimit,
        val observed: Double,
        val maximum: Double,
    ) : ApkTechnicalEvidence
    data class RequestedPermission(val value: String) : ApkTechnicalEvidence
    data object DebuggableManifest : ApkTechnicalEvidence
    data class ExportedComponent(
        val type: ComponentType,
        val className: String,
    ) : ApkTechnicalEvidence
    data class FindingCount(
        val retained: Int,
        val maximum: Int,
    ) : ApkTechnicalEvidence
    data class ByteLimitObservation(
        val observed: Long,
        val maximum: Long,
    ) : ApkTechnicalEvidence
    data class UnresolvedResourceReferenceCount(val value: Int) : ApkTechnicalEvidence
}

enum class FindingSeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
}

enum class FindingConfidence {
    LOW,
    MEDIUM,
    HIGH,
}

data class RiskAssessment(
    val score: Int,
    val level: RiskLevel,
    val explanations: List<RiskExplanation>,
    val limitations: List<RiskLimitation>,
) {
    init {
        require(score in 0..100)
    }
}

enum class RiskLevel {
    LOW,
    MODERATE,
    HIGH,
    CRITICAL,
}

data class RiskExplanation(
    val code: RiskExplanationCode,
    val points: Int,
    val evidence: List<ApkTechnicalEvidence>,
)

/** Stable rule IDs for all point-bearing risk explanations. */
enum class RiskExplanationCode {
    UNSAFE_ARCHIVE_PATH,
    ARCHIVE_SAFETY_LIMIT,
    SIGNATURE_NOT_VERIFIED,
    SENSITIVE_PERMISSIONS,
    DEBUGGABLE_BUILD,
    EXPORTED_COMPONENTS,
    BUNDLED_TRACKER_OR_TELEMETRY,
    EMBEDDED_NETWORK_ENDPOINTS,
}

data class RiskLimitation(
    val code: RiskLimitationCode,
    val evidence: List<ApkTechnicalEvidence> = emptyList(),
)

/** Stable reason IDs for non-complete or bounded inspection output. */
enum class RiskLimitationCode {
    ARCHIVE_ENUMERATION_INCOMPLETE,
    MANIFEST_PERMISSION_OUTPUT_TRUNCATED,
    MANIFEST_COMPONENT_OUTPUT_TRUNCATED,
    SIGNATURE_VERIFICATION_UNAVAILABLE,
    READABLE_MANIFEST_TRUNCATED,
    READABLE_MANIFEST_UNRESOLVED_RESOURCE_REFERENCES,
    SOURCE_COPY_INCOMPLETE,
    ARCHIVE_UNREADABLE,
    ARCHIVE_SAFETY_LIMIT_REACHED,
    ANDROID_MANIFEST_UNAVAILABLE,
    HEURISTIC_SCAN_BOUNDED,
    HEURISTIC_FINDINGS_TRUNCATED,
    TEMPORARY_FILE_CLEANUP_FAILED,
}
