package app.apksentinel.inspector

import android.content.Context
import android.net.Uri
import app.apksentinel.inspector.internal.AndroidManifestInspector
import app.apksentinel.inspector.internal.ApkSigningInspector
import app.apksentinel.inspector.internal.ArchiveScanner
import app.apksentinel.inspector.internal.BundleInspector
import app.apksentinel.inspector.internal.InspectionControl
import app.apksentinel.inspector.internal.RiskScorer
import app.apksentinel.inspector.internal.TempCopyOutcome
import app.apksentinel.inspector.internal.TemporaryArtifactCopier
import java.io.File

/**
 * Local-only APK/ZIP inspection engine.
 *
 * [inspect] performs blocking I/O by design. Invoke it from a worker or I/O
 * dispatcher. It accepts a caller-owned cancellation signal and emits bounded
 * progress updates; it never opens a network connection or extracts archive
 * entries to a user-visible location.
 */
class ApkInspector(context: Context) {
    private val appContext = context.applicationContext
    private val artifactCopier = TemporaryArtifactCopier(
        contentResolver = appContext.contentResolver,
        cacheDirectory = appContext.cacheDir,
    )
    private val archiveScanner = ArchiveScanner()
    private val manifestInspector = AndroidManifestInspector(appContext.packageManager)
    private val signingInspector = ApkSigningInspector()
    private val bundleInspector = BundleInspector(
        cacheDirectory = appContext.cacheDir,
        archiveScanner = archiveScanner,
        manifestInspector = manifestInspector,
        signingInspector = signingInspector,
    )

    /** Inspects the installed base APK through the same bounded private-copy path. */
    fun inspectInstalledPackage(
        packageName: String,
        request: ApkInspectionRequest = ApkInspectionRequest(),
    ): ApkInspectionResult {
        if (!ANDROID_PACKAGE_NAME.matches(packageName)) {
            return ApkInspectionResult(failures = listOf(SourceUnavailable(InspectionFailureCode.PACKAGE_NAME_INVALID)))
        }
        val sourcePath = runCatching { appContext.packageManager.getApplicationInfo(packageName, 0).sourceDir }.getOrNull()
            ?: return ApkInspectionResult(failures = listOf(SourceUnavailable(InspectionFailureCode.INSTALLED_PACKAGE_UNAVAILABLE)))
        return inspect(Uri.fromFile(File(sourcePath)), request)
    }

    fun inspect(
        uri: Uri,
        request: ApkInspectionRequest = ApkInspectionRequest(),
    ): ApkInspectionResult {
        val control = InspectionControl(
            cancellation = request.cancellation,
            progressListener = request.progressListener,
        )
        control.report(
            stage = InspectionStage.COPY_INPUT,
            code = InspectionProgressCode.PREPARING_PRIVATE_COPY,
            bytesLimit = request.limits.maxInputBytes,
        )

        val copyOutcome = artifactCopier.copy(uri, request.limits, control)
        if (copyOutcome is TempCopyOutcome.Failure) {
            return ApkInspectionResult(failures = listOf(copyOutcome.failure))
        }
        val copiedArtifact = copyOutcome as TempCopyOutcome.Success

        val failures = mutableListOf<InspectionFailure>()
        var archive: ArchiveMetadata? = null
        var inventory: ArchiveInventory? = null
        var manifest: ManifestSummary? = null
        var decodedManifest: DecodedManifestText? = null
        var signing: SigningSummary? = null
        var findings: List<HeuristicFinding> = emptyList()
        var stoppedForSafety = false

        try {
            control.report(
                stage = InspectionStage.INSPECT_ARCHIVE,
                code = InspectionProgressCode.INSPECTING_ARCHIVE,
                bytesLimit = request.limits.maxTotalUncompressedBytes,
            )
            val bundleOutcome = bundleInspector.inspect(
                input = copiedArtifact.file,
                limits = request.limits,
                control = control,
            )
            // Keep bounded nested-member failures even when the container is
            // not strong enough to become bundle evidence. A later outer
            // archive pass may still recover ordinary APK evidence, but it
            // must not erase the nested failure that was already observed.
            failures += bundleOutcome.failures
            val detectedBundle = bundleOutcome.bundle
            if (detectedBundle != null) {
                // A bundle result is deliberately bundle-only unless the
                // inspector identified exactly one coherent, verified base.
                // Never treat an arbitrary readable split as the application.
                val selected = bundleOutcome.primary
                archive = selected?.archive
                inventory = selected?.inventory
                manifest = selected?.manifest
                signing = selected?.signing
                decodedManifest = selected?.decodedManifest
                findings = if (selected != null) bundleOutcome.findings else emptyList()
                stoppedForSafety = bundleOutcome.stoppedForSafety
                control.report(
                    stage = InspectionStage.COMPLETE,
                    code = InspectionProgressCode.COMPLETE,
                )
                val risk = selected?.let {
                    RiskScorer.score(
                        archive = archive,
                        manifest = manifest,
                        decodedManifest = decodedManifest,
                        signing = signing,
                        findings = findings,
                        failures = failures,
                    )
                }
                return ApkInspectionResult(
                    source = copiedArtifact.source,
                    archive = archive,
                    manifest = manifest,
                    signing = signing,
                    decodedManifest = decodedManifest,
                    inventory = inventory,
                    findings = findings,
                    risk = risk,
                    failures = failures.toList(),
                    stoppedForSafety = stoppedForSafety,
                    bundle = detectedBundle,
                )
            }
            control.report(
                stage = InspectionStage.INSPECT_ARCHIVE,
                code = InspectionProgressCode.INSPECTING_ARCHIVE,
                bytesLimit = request.limits.maxTotalUncompressedBytes,
            )
            val archiveOutcome = archiveScanner.inspect(
                input = copiedArtifact.file,
                limits = request.limits,
                control = control,
            )
            archive = archiveOutcome.archive
            inventory = archiveOutcome.inventory
            findings = archiveOutcome.findings
            failures += archiveOutcome.failures
            stoppedForSafety = archiveOutcome.stoppedForSafety

            if (!stoppedForSafety && archive?.isComplete == true) {
                if (archive.containsAndroidManifest) {
                    control.report(
                        stage = InspectionStage.INSPECT_MANIFEST,
                        code = InspectionProgressCode.PARSING_MANIFEST,
                    )
                    control.ensureActive()
                    val manifestOutcome = manifestInspector.inspect(copiedArtifact.file, request.limits)
                    manifest = manifestOutcome.manifest
                    decodedManifest = manifestOutcome.decodedManifest
                    manifestOutcome.failure?.let { failure -> failures += failure }

                    control.report(
                        stage = InspectionStage.VERIFY_SIGNATURE,
                        code = InspectionProgressCode.VERIFYING_SIGNATURE,
                    )
                    control.ensureActive()
                    val signingOutcome = signingInspector.inspect(copiedArtifact.file)
                    signing = signingOutcome.signing
                    signingOutcome.failure?.let { failure -> failures += failure }
                    control.ensureActive()
                } else {
                    failures += AndroidManifestUnavailable(
                        code = InspectionFailureCode.MANIFEST_ENTRY_MISSING,
                    )
                }
            }
        } finally {
            if (copiedArtifact.file.exists() && !copiedArtifact.file.delete()) {
                failures += TemporaryFileCleanupFailed(
                    code = InspectionFailureCode.TEMP_FILE_DELETE_FAILED,
                )
            }
        }

        control.report(
            stage = InspectionStage.SCORE_RISK,
            code = InspectionProgressCode.SCORING_RISK,
        )
        val risk = RiskScorer.score(
            archive = archive,
            manifest = manifest,
            decodedManifest = decodedManifest,
            signing = signing,
            findings = findings,
            failures = failures,
        )
        control.report(
            stage = InspectionStage.COMPLETE,
            code = InspectionProgressCode.COMPLETE,
        )
        return ApkInspectionResult(
            source = copiedArtifact.source,
            archive = archive,
            manifest = manifest,
            signing = signing,
            decodedManifest = decodedManifest,
            inventory = inventory,
            findings = findings,
            risk = risk,
            failures = failures.toList(),
            stoppedForSafety = stoppedForSafety,
        )
    }

    private companion object {
        val ANDROID_PACKAGE_NAME = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")
    }
}
