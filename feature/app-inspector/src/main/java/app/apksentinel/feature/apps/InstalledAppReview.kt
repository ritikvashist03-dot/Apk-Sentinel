package app.apksentinel.feature.apps

import app.apksentinel.core.security.SafeTextNormalizer

/** Confidence is about the local evidence collected, never about a malware verdict. */
enum class LocalEvidenceConfidence { HIGH, MEDIUM, LOW, UNKNOWN }

enum class LocalContextStatus { SUPPORTING_EVIDENCE, LOCAL_SIGNALS_ONLY, UNKNOWN }

data class LocalContextAssessment(
    val status: LocalContextStatus,
    val confidence: LocalEvidenceConfidence,
    val evidence: List<String>,
    val limitations: List<String>,
)

/**
 * Beginner-facing synthesis for an installed app. The two assessments are
 * deliberately contextual: neither can declare an app authentic, malware, or
 * adware without an external authoritative reference and runtime evidence.
 */
data class InstalledAppReviewSummary(
    val authenticityContext: LocalContextAssessment,
    val adwareContext: LocalContextAssessment,
    val evidenceCoverage: List<String>,
    val localFactualSummary: String = "",
)

/**
 * Deterministic local wording for the equivalent outcome of a short summary.
 * It is intentionally factual and does not imply a model, network, or verdict.
 */
object LocalFactualSummaryBuilder {
    const val MAX_CODE_POINTS = 1_200

    fun build(
        app: InstalledAppRecord,
        permissionEvidence: List<PermissionEvidence>,
        components: List<ComponentEvidence>,
    ): String {
        val source = app.installSourceKind.name.lowercase().replace('_', ' ')
        val fields = listOf(
            "Package ${SafeTextNormalizer.normalizeDisplayText(app.packageName, "unknown package", 200)}",
            "target SDK ${app.targetSdk.takeIf { it > 0 } ?: "unknown"}",
            "origin ${source.take(80)}",
            "${permissionEvidence.size} permission rows",
            "${components.size} manifest component rows",
            "${app.artifactSizes.size} APK artifact size rows",
            "${app.nativeLibraries.size} native library rows",
        )
        return fields.joinToString("; ").take(MAX_CODE_POINTS)
    }
}

object InstalledAppReviewSynthesizer {
    private val adwareAdjacentPermissions = setOf(
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.PACKAGE_USAGE_STATS",
    )

    fun summarize(
        app: InstalledAppRecord,
        permissionEvidence: List<PermissionEvidence>,
        components: List<ComponentEvidence>,
        sdkIndicators: List<SdkIndicatorEvidence>,
        hardware: HardwareFeatureEvidenceResult,
    ): InstalledAppReviewSummary {
        val authenticityEvidence = buildList {
            when (app.installSourceKind) {
                InstallSourceKind.PLAY_STORE -> add("Installer evidence: Google Play package")
                InstallSourceKind.SYSTEM_IMAGE -> add("Installer evidence: system image")
                InstallSourceKind.OTHER_STORE -> add(
                    "Installer evidence: ${SafeTextNormalizer.normalizeDisplayText(app.installSourcePackage, "other store", 120)}",
                )
                InstallSourceKind.SIDELOADED_OR_ADB -> add("Installer evidence: package installer or ADB-like path")
                InstallSourceKind.UNKNOWN -> Unit
            }
            if (app.signerSha256.isNotEmpty()) add("A signing certificate fingerprint is present for this installed artifact")
            if (app.firstInstallMillis > 0L) add("First-install time is available locally")
            if (app.lastUpdateMillis > 0L) add("Last-update time is available locally")
        }.take(MAX_EVIDENCE)
        val authenticityStatus = when {
            app.installSourceKind == InstallSourceKind.PLAY_STORE || app.installSourceKind == InstallSourceKind.SYSTEM_IMAGE -> LocalContextStatus.SUPPORTING_EVIDENCE
            authenticityEvidence.isNotEmpty() -> LocalContextStatus.LOCAL_SIGNALS_ONLY
            else -> LocalContextStatus.UNKNOWN
        }
        val authenticityConfidence = when (authenticityStatus) {
            LocalContextStatus.SUPPORTING_EVIDENCE -> LocalEvidenceConfidence.MEDIUM
            LocalContextStatus.LOCAL_SIGNALS_ONLY -> LocalEvidenceConfidence.LOW
            LocalContextStatus.UNKNOWN -> LocalEvidenceConfidence.UNKNOWN
        }

        val adwareEvidence = buildList {
            sdkIndicators.forEach { add("SDK marker: ${it.name}") }
            permissionEvidence.filter { it.name in adwareAdjacentPermissions }.forEach {
                add("Capability requested: ${it.name}${if (it.granted) " (granted)" else " (not granted)"}")
            }
            if (components.any { it.exported }) add("${components.count { it.exported }} exported component(s) are declared")
        }.distinct().take(MAX_EVIDENCE)
        val adwareStatus = if (adwareEvidence.isEmpty()) LocalContextStatus.UNKNOWN else LocalContextStatus.LOCAL_SIGNALS_ONLY
        val adwareConfidence = if (adwareEvidence.isEmpty()) LocalEvidenceConfidence.UNKNOWN else LocalEvidenceConfidence.LOW
        val commonLimitations = listOf(
            "No external official or reputation source was consulted",
            "Local declarations do not prove runtime behavior, advertising, or harmful intent",
            "This is not a malware or adware verdict",
        )

        return InstalledAppReviewSummary(
            authenticityContext = LocalContextAssessment(
                status = authenticityStatus,
                confidence = authenticityConfidence,
                evidence = authenticityEvidence,
                limitations = commonLimitations,
            ),
            adwareContext = LocalContextAssessment(
                status = adwareStatus,
                confidence = adwareConfidence,
                evidence = adwareEvidence,
                limitations = commonLimitations,
            ),
            evidenceCoverage = listOf(
                "Installer, lifecycle, SDK, permissions, signing, components, and hardware declarations were read from Android PackageManager",
                "${permissionEvidence.size} permission rows and ${components.size} component rows are available",
                "Hardware evidence is ${hardware.availability.name.lowercase()}",
            ).take(MAX_EVIDENCE),
            localFactualSummary = LocalFactualSummaryBuilder.build(app, permissionEvidence, components),
        )
    }

    private const val MAX_EVIDENCE = 8
}
