package app.apksentinel.inspector.internal

import app.apksentinel.inspector.BundleApkEntry
import app.apksentinel.inspector.BundleApkRole
import app.apksentinel.inspector.BundleFormat
import app.apksentinel.inspector.BundleIdentityStatus
import app.apksentinel.inspector.BundleInspection
import app.apksentinel.inspector.BundleLimitationCode
import app.apksentinel.inspector.BundleMetadata
import app.apksentinel.inspector.BundleObbEntry
import app.apksentinel.inspector.AabModuleEvidence
import app.apksentinel.inspector.AabPublishingEvidence
import app.apksentinel.inspector.ArchiveLimit
import app.apksentinel.inspector.ArchiveUnreadable
import app.apksentinel.inspector.HeuristicFinding
import app.apksentinel.inspector.InspectionFailure
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.InspectionProgressCode
import app.apksentinel.inspector.InspectionStage
import app.apksentinel.inspector.NestedMemberInspectionFailure
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import java.io.InputStream
import java.util.zip.ZipFile

internal data class BundleInspectionOutcome(
    val bundle: BundleInspection?,
    val primary: BundleApkEntry?,
    val findings: List<HeuristicFinding>,
    val failures: List<InspectionFailure>,
    val stoppedForSafety: Boolean,
)

/**
 * Bounded reader for split APK/APKS, XAPK, and publishing AAB containers.
 *
 * It uses the already-private outer copy. Nested APKs are written only to
 * randomly named files in the private cache and are passed directly to the
 * existing archive, manifest, and signing inspectors; no nested public URI
 * copy or user-visible extraction is performed.
 */
internal class BundleInspector(
    private val cacheDirectory: File,
    private val archiveScanner: ArchiveScanner = ArchiveScanner(),
    private val manifestInspector: AndroidManifestInspector? = null,
    private val signingInspector: ApkSigningInspector = ApkSigningInspector(),
) {
    fun inspect(
        input: File,
        limits: InspectionLimits,
        control: InspectionControl,
    ): BundleInspectionOutcome {
        val nested = mutableListOf<BundleApkEntry>()
        val obb = mutableListOf<BundleObbEntry>()
        val findings = mutableListOf<HeuristicFinding>()
        val failures = mutableListOf<InspectionFailure>()
        val limitations = linkedSetOf<BundleLimitationCode>()
        var metadataText: String? = null
        var metadataLimitReached = false
        var outerEntryCount = 0
        var nestedBytes = 0L
        var nestedExpandedBytes = 0L
        var obbBytes = 0L
        var outerReadFailed = false
        var outerLimitReached = false
        var aabMarker = false
        var aabEvidenceEntries = 0
        var aabDeclaredBytes = 0L
        var aabLimitReached = false
        var bundleConfigPresent = false
        val aabMetadataPaths = mutableListOf<String>()
        val aabModules = linkedMapOf<String, AabModuleAccumulator>()

        try {
            ZipFile(input).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    control.ensureActive()
                    val entry = entries.nextElement()
                    outerEntryCount += 1
                    if (outerEntryCount > limits.maxArchiveEntries) {
                        outerLimitReached = true
                        limitations += BundleLimitationCode.CONTAINER_LIMIT_REACHED
                        break
                    }
                    zip.getInputStream(entry).use { stream ->
                        val rawName = entry.name.orEmpty()
                        val boundedPath = boundedUtf8(rawName, limits.maxBundlePathBytes)
                        if (isUnsafePath(rawName)) limitations += BundleLimitationCode.UNSAFE_PATH
                        val lowerName = rawName.lowercase(Locale.ROOT)
                        val aabPath = parseAabPath(rawName)
                        if (aabPath != null) {
                            if (aabPath.isBundleConfig) {
                                aabMarker = true
                                bundleConfigPresent = true
                            }
                            if (aabPath.isMetadata) {
                                aabMarker = true
                                if (aabMetadataPaths.size < limits.maxAabEvidenceEntries) {
                                    aabMetadataPaths += boundedPath
                                } else {
                                    aabLimitReached = true
                                }
                            }
                            if (aabPath.moduleName != null) {
                                aabMarker = aabMarker || aabPath.isModuleManifest
                                val moduleAlreadyRetained = aabModules.containsKey(aabPath.moduleName)
                                if (!moduleAlreadyRetained && aabModules.size >= limits.maxAabModules) {
                                    aabLimitReached = true
                                } else if (aabEvidenceEntries < limits.maxAabEvidenceEntries) {
                                    val module = aabModules.getOrPut(aabPath.moduleName) { AabModuleAccumulator() }
                                    module.entryCount += 1
                                    module.declaredBytes = module.declaredBytes.saturatedAdd(entry.size.takeIf { it >= 0L } ?: 0L)
                                    module.hasManifest = module.hasManifest || aabPath.isModuleManifest
                                    module.hasDex = module.hasDex || aabPath.isDex
                                    module.hasResources = module.hasResources || aabPath.isResources
                                    aabEvidenceEntries += 1
                                    aabDeclaredBytes = aabDeclaredBytes.saturatedAdd(entry.size.takeIf { it >= 0L } ?: 0L)
                                } else {
                                    aabLimitReached = true
                                }
                            }
                        }
                        val isMetadata = lowerName == XAPK_METADATA_NAME
                        val isObb = lowerName.endsWith(".obb")
                        val candidateByName = lowerName.endsWith(".apk")
                        // OBB entries are inventory-only: do not read any payload bytes.
                        val firstBytes = if (isObb) ByteArray(0) else readPrefix(stream, 4, control)
                        val hasZipSignature = firstBytes.contentEquals(APK_ZIP_SIGNATURE)
                        if (isMetadata) {
                            val metadata = readBoundedText(stream, firstBytes, limits.maxBundleMetadataBytes, control)
                            if (metadata.limitReached) {
                                metadataLimitReached = true
                                limitations += BundleLimitationCode.METADATA_LIMIT_REACHED
                            } else {
                                metadataText = metadata.text
                            }
                        } else if (isObb) {
                            val declared = entry.size.takeIf { it >= 0L }
                            if (obb.size < limits.maxBundleObbEntries && obbBytes <= limits.maxBundleTotalObbBytes) {
                                if (declared != null && obbBytes.saturatedAdd(declared) <= limits.maxBundleTotalObbBytes) {
                                    obb += BundleObbEntry(boundedPath, declared)
                                    obbBytes = obbBytes.saturatedAdd(declared)
                                } else {
                                    limitations += BundleLimitationCode.CONTAINER_LIMIT_REACHED
                                }
                            } else {
                                limitations += BundleLimitationCode.OBB_INVENTORY_TRUNCATED
                            }
                        } else if ((candidateByName || hasZipSignature) && !entry.isDirectory) {
                            if (nested.size >= limits.maxBundleApkCount) {
                                limitations += BundleLimitationCode.NESTED_APK_LIMIT_REACHED
                                outerLimitReached = true
                            } else {
                                val copied = copyNestedApk(stream, firstBytes, entry.size, limits, nestedBytes, control)
                                if (copied.limitReached) {
                                    limitations += BundleLimitationCode.NESTED_APK_LIMIT_REACHED
                                    outerLimitReached = true
                                } else if (copied.file == null) {
                                    if (hasZipSignature || candidateByName) {
                                        limitations += BundleLimitationCode.NESTED_APK_UNREADABLE
                                        failures += NestedMemberInspectionFailure(
                                            memberPath = boundedPath,
                                            stage = InspectionStage.INSPECT_ARCHIVE,
                                            code = InspectionFailureCode.ZIP_READ_FAILED,
                                        )
                                    }
                                } else {
                                    nestedBytes = nestedBytes.saturatedAdd(copied.byteCount)
                                    val nestedResult = inspectNested(
                                        file = copied.file,
                                        path = boundedPath,
                                        role = roleForPath(boundedPath),
                                        byteCount = copied.byteCount,
                                        sha256 = copied.sha256,
                                        limits = limits,
                                        alreadyExpandedBytes = nestedExpandedBytes,
                                        control = control,
                                    )
                                    nested += nestedResult.entry
                                    findings += nestedResult.entry.findings
                                    failures += nestedResult.failures
                                    nestedResult.limitations.forEach { limitations += it }
                                    nestedExpandedBytes = nestedExpandedBytes.saturatedAdd(nestedResult.expandedBytes ?: 0L)
                                }
                            }
                        }
                    }
                    if (outerLimitReached) break
                }
            }
        } catch (_: IOException) {
            outerReadFailed = true
            failures += ArchiveUnreadable(InspectionFailureCode.ZIP_READ_FAILED)
        }

        // A suffix or selected-file MIME type must not create a split-bundle
        // result. APK sets require nested AndroidManifest evidence; AABs use
        // their bounded publishing-structure markers instead.
        if (nested.none { it.archive?.containsAndroidManifest == true }) {
            if (aabMarker) {
                val aabLimitations = linkedSetOf<BundleLimitationCode>()
                aabLimitations += limitations
                aabLimitations += BundleLimitationCode.AAB_PUBLISHING_BUNDLE_ONLY
                if (aabLimitReached) {
                    aabLimitations += BundleLimitationCode.AAB_EVIDENCE_BOUNDED
                }
                if (outerReadFailed || outerLimitReached) {
                    aabLimitations += BundleLimitationCode.CONTAINER_LIMIT_REACHED
                }
                val publishingEvidence = AabPublishingEvidence(
                    modules = aabModules.entries
                        .take(limits.maxAabModules)
                        .map { (name, module) ->
                            AabModuleEvidence(
                                name = boundedUtf8(name, limits.maxBundlePathBytes),
                                entryCount = module.entryCount,
                                declaredBytes = module.declaredBytes,
                                hasManifest = module.hasManifest,
                                hasDex = module.hasDex,
                                hasResources = module.hasResources,
                            )
                        },
                    bundleConfigPresent = bundleConfigPresent,
                    metadataPaths = aabMetadataPaths.take(limits.maxAabEvidenceEntries),
                    entryCount = aabEvidenceEntries,
                    declaredBytes = aabDeclaredBytes,
                    isComplete = !aabLimitReached && !outerReadFailed && !outerLimitReached,
                )
                return BundleInspectionOutcome(
                    bundle = BundleInspection(
                        format = BundleFormat.AAB,
                        nestedApks = emptyList(),
                        obbFiles = obb,
                        metadata = null,
                        limitations = aabLimitations.toList(),
                        nestedApkBytes = 0L,
                        nestedExpandedBytes = 0L,
                        isComplete = publishingEvidence.isComplete,
                        identityStatus = app.apksentinel.inspector.BundleIdentityStatus.UNAVAILABLE,
                        publishingEvidence = publishingEvidence,
                    ),
                    primary = null,
                    findings = emptyList(),
                    failures = failures.toList(),
                    stoppedForSafety = aabLimitReached || outerReadFailed || outerLimitReached,
                )
            }
            return BundleInspectionOutcome(
                bundle = null,
                primary = null,
                findings = emptyList(),
                failures = failures.toList(),
                stoppedForSafety = false,
            )
        }

        val metadata = parseMetadata(metadataText, limits)
        metadata?.declaredBaseApkPaths.orEmpty().forEach { basePath ->
            val index = nested.indexOfFirst { it.path == basePath }
            if (index >= 0) nested[index] = nested[index].copy(role = BundleApkRole.BASE)
        }
        val validNested = nested.filter { it.archive?.containsAndroidManifest == true }
        if (metadata?.isTrusted == false || metadataLimitReached) {
            limitations += BundleLimitationCode.METADATA_UNTRUSTED
        }
        if (metadata != null) {
            val actualNames = nested.map { it.path }.toSet()
            if (metadata.declaredApkPaths.any { it !in actualNames } ||
                metadata.declaredObbPaths.any { it !in obb.map(BundleObbEntry::path).toSet() }
            ) {
                limitations += BundleLimitationCode.METADATA_UNTRUSTED
            }
        }

        val baseEntries = validNested.filter { it.role == BundleApkRole.BASE }
        val primary = baseEntries.firstOrNull()
        val identityBase = primary?.manifest
        limitations += bundleIdentityAndSignerLimitations(validNested)
        if (metadata != null && identityBase != null && (
            metadata.packageName?.let { it != identityBase.packageName } == true ||
                metadata.versionCode?.let { identityBase.versionCode != null && it != identityBase.versionCode } == true ||
                metadata.versionName?.let { identityBase.versionName != null && it != identityBase.versionName } == true
            )
        ) {
            limitations += BundleLimitationCode.METADATA_UNTRUSTED
            limitations += BundleLimitationCode.IDENTITY_MISMATCH
        }
        if (outerReadFailed) limitations += BundleLimitationCode.NESTED_APK_UNREADABLE
        if (outerLimitReached) limitations += BundleLimitationCode.CONTAINER_LIMIT_REACHED
        if (failures.any { it.code == InspectionFailureCode.ZIP_READ_FAILED } ||
            nested.any { it.failures.contains(InspectionFailureCode.ZIP_READ_FAILED) }
        ) {
            limitations += BundleLimitationCode.NESTED_APK_UNREADABLE
        }
        limitations += BundleLimitationCode.BUNDLE_NOT_INSTALLABILITY_VERIFIED

        val identityAssessment = assessBundleIdentity(nested, metadata, identityBase, limitations)
        limitations += identityAssessment.limitations
        val complete = limitations.none {
            it != BundleLimitationCode.BUNDLE_NOT_INSTALLABILITY_VERIFIED
        }
        val format = if (metadataText != null) BundleFormat.XAPK else BundleFormat.APKS
        return BundleInspectionOutcome(
            bundle = BundleInspection(
                format = format,
                nestedApks = nested,
                obbFiles = obb,
                metadata = metadata,
                limitations = limitations.toList(),
                nestedApkBytes = nestedBytes,
                nestedExpandedBytes = nestedExpandedBytes,
                isComplete = complete,
                identityStatus = identityAssessment.status,
            ),
            primary = primary.takeIf { identityAssessment.status == BundleIdentityStatus.VERIFIED },
            findings = findings,
            failures = failures.toList(),
            stoppedForSafety = limitations.any {
                it == BundleLimitationCode.NESTED_APK_LIMIT_REACHED ||
                    it == BundleLimitationCode.NESTED_EXPANSION_LIMIT_REACHED ||
                    it == BundleLimitationCode.METADATA_LIMIT_REACHED ||
                    it == BundleLimitationCode.CONTAINER_LIMIT_REACHED
            },
        )
    }

    private fun inspectNested(
        file: File,
        path: String,
        role: BundleApkRole,
        byteCount: Long,
        sha256: String,
        limits: InspectionLimits,
        alreadyExpandedBytes: Long,
        control: InspectionControl,
    ): NestedInspection {
        try {
            val remainingExpanded = limits.maxBundleTotalExpandedBytes - alreadyExpandedBytes
            if (remainingExpanded <= 0L) {
                return NestedInspection(
                    entry = BundleApkEntry(path, role, byteCount, null, sha256, null, null, null, null, null, failures = emptyList()),
                    expandedBytes = null,
                    limitations = listOf(BundleLimitationCode.NESTED_EXPANSION_LIMIT_REACHED),
                    failures = emptyList(),
                )
            }
            val nestedLimits = limits.copy(
                maxInputBytes = minOf(limits.maxInputBytes, limits.maxBundleApkBytes),
                maxTotalUncompressedBytes = minOf(limits.maxTotalUncompressedBytes, limits.maxBundleApkExpandedBytes, remainingExpanded),
            )
            val archiveOutcome = archiveScanner.inspect(file, nestedLimits, control)
            val childFailures = archiveOutcome.failures.toMutableList()
            var manifest = null as app.apksentinel.inspector.ManifestSummary?
            var decoded = null as app.apksentinel.inspector.DecodedManifestText?
            var signing = null as app.apksentinel.inspector.SigningSummary?
            if (manifestInspector != null && archiveOutcome.archive?.isComplete == true && archiveOutcome.archive.containsAndroidManifest) {
                control.report(InspectionStage.INSPECT_MANIFEST, InspectionProgressCode.PARSING_MANIFEST)
                val manifestOutcome = manifestInspector.inspect(file, nestedLimits)
                manifest = manifestOutcome.manifest
                decoded = manifestOutcome.decodedManifest
                manifestOutcome.failure?.let { childFailures += it }
                control.report(InspectionStage.VERIFY_SIGNATURE, InspectionProgressCode.VERIFYING_SIGNATURE)
                val signingOutcome = signingInspector.inspect(file)
                signing = signingOutcome.signing
                signingOutcome.failure?.let { childFailures += it }
            }
            val limitations = buildList {
                if (archiveOutcome.stoppedForSafety) add(BundleLimitationCode.NESTED_APK_LIMIT_REACHED)
                if (archiveOutcome.archive?.isComplete == false) add(BundleLimitationCode.NESTED_APK_UNREADABLE)
                if (archiveOutcome.archive?.containsAndroidManifest != true) add(BundleLimitationCode.NESTED_APK_UNREADABLE)
                if (manifestInspector != null && manifest == null) add(BundleLimitationCode.NESTED_APK_UNREADABLE)
                if (archiveOutcome.failures.any {
                    it is app.apksentinel.inspector.HeuristicScanTruncated ||
                        it is app.apksentinel.inspector.HeuristicFindingsTruncated
                }) add(BundleLimitationCode.NESTED_EVIDENCE_BOUNDED)
                if (decoded?.isTruncated == true || manifest?.permissionsTruncated == true ||
                    manifest?.componentsTruncated == true || manifest?.hardwareFeaturesTruncated == true ||
                    manifest?.intentFiltersTruncated == true
                ) add(BundleLimitationCode.NESTED_EVIDENCE_BOUNDED)
                if (archiveOutcome.failures.any {
                    it is app.apksentinel.inspector.ArchiveLimitExceeded &&
                        (it.limit == ArchiveLimit.TOTAL_UNCOMPRESSED_BYTES || it.limit == ArchiveLimit.ENTRY_UNCOMPRESSED_BYTES)
                }) {
                    add(BundleLimitationCode.NESTED_EXPANSION_LIMIT_REACHED)
                }
            }
            return NestedInspection(
                entry = BundleApkEntry(
                    path = path,
                    role = role,
                    byteCount = byteCount,
                    expandedBytes = archiveOutcome.archive?.observedUncompressedBytes,
                    sha256 = sha256,
                    archive = archiveOutcome.archive,
                    inventory = archiveOutcome.inventory,
                    manifest = manifest,
                    decodedManifest = decoded,
                    signing = signing,
                    findings = archiveOutcome.findings,
                    failures = childFailures.map { it.code }.distinct(),
                ),
                expandedBytes = archiveOutcome.archive?.observedUncompressedBytes,
                limitations = limitations,
                failures = childFailures.map { failure ->
                    NestedMemberInspectionFailure(
                        memberPath = path,
                        stage = failure.stage,
                        code = failure.code,
                    )
                },
            )
        } finally {
            if (file.exists()) file.delete()
        }
    }

    private fun copyNestedApk(
        stream: InputStream,
        prefix: ByteArray,
        declaredBytes: Long,
        limits: InspectionLimits,
        alreadyCopiedBytes: Long,
        control: InspectionControl,
    ): NestedCopy {
        if (declaredBytes > limits.maxBundleApkBytes ||
            alreadyCopiedBytes.saturatedAdd(declaredBytes.coerceAtLeast(0L)) > limits.maxBundleTotalApkBytes
        ) {
            return NestedCopy(null, 0L, "", limitReached = true)
        }
        val temp = runCatching { File.createTempFile("apk-bundle-", ".apk", cacheDirectory) }.getOrNull()
            ?: return NestedCopy(null, 0L, "", limitReached = false)
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        var limitReached = false
        try {
            BufferedOutputStream(FileOutputStream(temp)).use { output ->
                fun writeChunk(bytes: ByteArray, count: Int) {
                    if (count <= 0) return
                    total = total.saturatedAdd(count.toLong())
                    if (total > limits.maxBundleApkBytes ||
                        alreadyCopiedBytes.saturatedAdd(total) > limits.maxBundleTotalApkBytes
                    ) {
                        limitReached = true
                        return
                    }
                    output.write(bytes, 0, count)
                    digest.update(bytes, 0, count)
                }
                writeChunk(prefix, prefix.size)
                val buffer = ByteArray(32 * 1024)
                while (!limitReached) {
                    control.ensureActive()
                    val read = stream.read(buffer)
                    if (read < 0) break
                    if (read > 0) writeChunk(buffer, read)
                }
            }
            if (limitReached) return NestedCopy(null, total, "", limitReached = true)
            return NestedCopy(temp, total, digest.digest().toHex(), limitReached = false)
        } catch (_: IOException) {
            return NestedCopy(null, total, "", limitReached = false)
        } finally {
            if (limitReached && temp.exists()) temp.delete()
        }
    }

    private data class NestedInspection(
        val entry: BundleApkEntry,
        val expandedBytes: Long?,
        val limitations: List<BundleLimitationCode>,
        val failures: List<InspectionFailure>,
    )

    private data class NestedCopy(
        val file: File?,
        val byteCount: Long,
        val sha256: String,
        val limitReached: Boolean,
    )

    private data class BoundedText(val text: String?, val limitReached: Boolean)

    private fun readBoundedText(
        stream: InputStream,
        prefix: ByteArray,
        maximumBytes: Int,
        control: InspectionControl,
    ): BoundedText {
        val output = ByteArrayOutputStream(minOf(maximumBytes, 4096))
        output.write(prefix)
        val buffer = ByteArray(8 * 1024)
        var exceeded = output.size() > maximumBytes
        while (true) {
            control.ensureActive()
            val read = stream.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            if (output.size() + read > maximumBytes) {
                exceeded = true
                break
            }
            output.write(buffer, 0, read)
        }
        if (exceeded) return BoundedText(null, true)
        return BoundedText(String(output.toByteArray(), StandardCharsets.UTF_8), false)
    }
}

private data class BundleIdentityAssessment(
    val status: BundleIdentityStatus,
    val limitations: Set<BundleLimitationCode>,
)

/**
 * Selects a primary only when all identity evidence needed to represent the
 * bundle is present and coherent. A readable split is never an implicit base.
 */
private fun assessBundleIdentity(
    entries: List<BundleApkEntry>,
    metadata: BundleMetadata?,
    baseManifest: app.apksentinel.inspector.ManifestSummary?,
    existingLimitations: Set<BundleLimitationCode>,
): BundleIdentityAssessment {
    val limitations = linkedSetOf<BundleLimitationCode>()
    val readableMembers = entries.filter { it.archive?.containsAndroidManifest == true }
    val bases = readableMembers.filter { it.role == BundleApkRole.BASE }
    if (bases.isEmpty()) limitations += BundleLimitationCode.MISSING_BASE
    if (bases.size > 1) limitations += BundleLimitationCode.DUPLICATE_BASE
    if (bases.size != 1) {
        limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
        return BundleIdentityAssessment(BundleIdentityStatus.UNAVAILABLE, limitations)
    }

    val base = bases.single()
    val manifest = base.manifest ?: baseManifest
    val baseSignerSet = base.signing?.certificates.orEmpty().map(::normalizedSigner).toSet()
    val baseTrusted = base.archive?.isComplete == true &&
        manifest != null &&
        base.signing?.status == app.apksentinel.inspector.SignatureVerificationStatus.VERIFIED &&
        baseSignerSet.isNotEmpty()
    var incomplete = !baseTrusted
    var inconsistent = false
    if (manifest == null) limitations += BundleLimitationCode.NESTED_EVIDENCE_INCOMPLETE
    if (base.signing == null || base.signing.status != app.apksentinel.inspector.SignatureVerificationStatus.VERIFIED || baseSignerSet.isEmpty()) {
        limitations += BundleLimitationCode.SIGNER_UNAVAILABLE
    }

    entries.forEach { member ->
        if (member.archive?.containsAndroidManifest != true || member.manifest == null) {
            incomplete = true
            limitations += BundleLimitationCode.NESTED_EVIDENCE_INCOMPLETE
            return@forEach
        }
        val signerSet = member.signing?.certificates.orEmpty().map(::normalizedSigner).toSet()
        if (member.signing?.status != app.apksentinel.inspector.SignatureVerificationStatus.VERIFIED || signerSet.isEmpty()) {
            incomplete = true
            limitations += BundleLimitationCode.SIGNER_UNAVAILABLE
        }
        if (manifest != null && (
            member.manifest.packageName != manifest.packageName ||
                (member.manifest.versionCode != null && manifest.versionCode != null && member.manifest.versionCode != manifest.versionCode) ||
                (member.manifest.versionName != null && manifest.versionName != null && member.manifest.versionName != manifest.versionName)
            )
        ) {
            inconsistent = true
            limitations += BundleLimitationCode.IDENTITY_MISMATCH
        }
        if (baseSignerSet.isNotEmpty() && signerSet.isNotEmpty() && signerSet != baseSignerSet) {
            inconsistent = true
            limitations += BundleLimitationCode.SIGNER_MISMATCH
        }
    }
    if (metadata != null && manifest != null && (
        metadata.packageName?.let { it != manifest.packageName } == true ||
            metadata.versionCode?.let { manifest.versionCode != null && it != manifest.versionCode } == true ||
            metadata.versionName?.let { manifest.versionName != null && it != manifest.versionName } == true
        )
    ) {
        inconsistent = true
        limitations += BundleLimitationCode.IDENTITY_MISMATCH
    }
    if (incomplete || inconsistent || existingLimitations.any {
        it == BundleLimitationCode.NESTED_APK_UNREADABLE ||
            it == BundleLimitationCode.NESTED_EVIDENCE_BOUNDED ||
            it == BundleLimitationCode.NESTED_APK_LIMIT_REACHED ||
            it == BundleLimitationCode.NESTED_EXPANSION_LIMIT_REACHED ||
            it == BundleLimitationCode.CONTAINER_LIMIT_REACHED ||
            it == BundleLimitationCode.METADATA_LIMIT_REACHED
    }) limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
    val status = when {
        inconsistent -> BundleIdentityStatus.INCONSISTENT
        incomplete || limitations.contains(BundleLimitationCode.IDENTITY_UNAVAILABLE) -> BundleIdentityStatus.INCOMPLETE
        else -> BundleIdentityStatus.VERIFIED
    }
    return BundleIdentityAssessment(status, limitations)
}

private fun normalizedSigner(value: app.apksentinel.inspector.SigningCertificateSummary): String =
    value.sha256.filter(Char::isLetterOrDigit).lowercase(Locale.ROOT)

private fun parseMetadata(raw: String?, limits: InspectionLimits): BundleMetadata? {
    if (raw == null) return null
    val trimmed = raw.trim()
    if (!isLikelyJsonObject(trimmed)) {
        return BundleMetadata(null, null, null, isTrusted = false)
    }
    val packageName = jsonString(trimmed, "package_name", limits.maxBundleMetadataValueBytes)
        ?: jsonString(trimmed, "packageName", limits.maxBundleMetadataValueBytes)
    val versionCode = jsonLong(trimmed, "version_code") ?: jsonLong(trimmed, "versionCode")
    val versionName = jsonString(trimmed, "version_name", limits.maxBundleMetadataValueBytes)
        ?: jsonString(trimmed, "versionName", limits.maxBundleMetadataValueBytes)
    val declaredFiles = Regex("\\\"file\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"")
        .findAll(trimmed)
        .mapNotNull { it.groupValues.getOrNull(1) }
        .map { boundedUtf8(it, limits.maxBundlePathBytes) }
        .filter { it.isNotBlank() }
        .distinct()
        .take(128)
        .toList()
    val declaredObb = declaredFiles.filter { it.lowercase(Locale.ROOT).endsWith(".obb") }
    val declaredApks = declaredFiles.filter { it.lowercase(Locale.ROOT).endsWith(".apk") }
    val declaredBaseApks = Regex("\\{[^{}]{0,2048}\\}")
        .findAll(trimmed)
        .map { it.value }
        .filter { objectText ->
            objectText.contains(Regex("\\\"(?:id|type|split_id)\\\"\\s*:\\s*\\\"base\\\"", RegexOption.IGNORE_CASE))
        }
        .mapNotNull { objectText -> jsonString(objectText, "file", limits.maxBundlePathBytes) }
        .filter { it.lowercase(Locale.ROOT).endsWith(".apk") }
        .distinct()
        .take(16)
        .toList()
    val rawFileValues = rawJsonStrings(trimmed, "file")
    val valueOverflow = listOf("package_name", "packageName", "version_name", "versionName")
        .any { key -> rawJsonString(trimmed, key)?.toByteArray(StandardCharsets.UTF_8)?.size?.let { it > limits.maxBundleMetadataValueBytes } == true } ||
        rawFileValues.any { it.toByteArray(StandardCharsets.UTF_8).size > limits.maxBundlePathBytes }
    val trusted = !valueOverflow && (packageName != null || versionCode != null || versionName != null || declaredFiles.isNotEmpty())
    return BundleMetadata(packageName, versionCode, versionName, declaredApks, declaredBaseApks, declaredObb, trusted)
}

private fun jsonString(json: String, key: String, maximumBytes: Int): String? {
    val raw = rawJsonString(json, key) ?: return null
    return boundedUtf8(raw.replace("\\\\\\\"", "\\\""), maximumBytes)
}

private fun isLikelyJsonObject(value: String): Boolean {
    if (!value.startsWith("{") || !value.endsWith("}") || value.contains('\u0000')) return false
    var depth = 0
    var quoted = false
    var escaped = false
    value.forEach { character ->
        if (quoted) {
            if (escaped) escaped = false
            else if (character == '\\') escaped = true
            else if (character == '"') quoted = false
        } else when (character) {
            '"' -> quoted = true
            '{' -> depth += 1
            '}' -> depth -= 1
            ']' -> if (depth < 0) return false
        }
        if (depth < 0) return false
    }
    return depth == 0 && !quoted && !escaped && !value.contains(Regex(",\\s*[}\\]]"))
}

private fun rawJsonString(json: String, key: String): String? = Regex(
    "\\\"${Regex.escape(key)}\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\"",
).find(json)?.groupValues?.getOrNull(1)

private fun rawJsonStrings(json: String, key: String): List<String> = Regex(
    "\\\"${Regex.escape(key)}\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\"",
).findAll(json).mapNotNull { it.groupValues.getOrNull(1) }.take(128).toList()

private fun jsonLong(json: String, key: String): Long? = Regex(
    "\\\"${Regex.escape(key)}\\\"\\s*:\\s*(-?\\d+)"
).find(json)?.groupValues?.getOrNull(1)?.toLongOrNull()

private fun roleForPath(path: String): BundleApkRole {
    val name = path.substringAfterLast('/').lowercase(Locale.ROOT)
    return when {
        name == "base.apk" || name == "base-master.apk" || name == "base-master_2.apk" || name == "universal.apk" -> BundleApkRole.BASE
        name.startsWith("split_config") || name.contains("config.") || name.contains("config_") -> BundleApkRole.CONFIG
        name.startsWith("split_") || name.contains("feature") || name.contains("dynamic") -> BundleApkRole.FEATURE
        else -> BundleApkRole.UNKNOWN
    }
}

private fun readPrefix(stream: InputStream, maximumBytes: Int, control: InspectionControl): ByteArray {
    val output = ByteArray(maximumBytes)
    var offset = 0
    while (offset < maximumBytes) {
        control.ensureActive()
        val read = stream.read(output, offset, maximumBytes - offset)
        if (read <= 0) break
        offset += read
    }
    return output.copyOf(offset)
}

private fun isUnsafePath(value: String): Boolean {
    val normalized = value.replace('\\', '/')
    return normalized.indexOf('\u0000') >= 0 ||
        normalized.startsWith('/') ||
        normalized.startsWith("//") ||
        Regex("^[A-Za-z]:.*").matches(normalized) ||
        normalized.split('/').any { it == ".." }
}

private fun boundedUtf8(value: String, maximumBytes: Int): String {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    if (bytes.size <= maximumBytes) return value
    var end = maximumBytes
    while (end > 0 && (bytes[end - 1].toInt() and 0xC0) == 0x80) end -= 1
    return String(bytes, 0, end, StandardCharsets.UTF_8)
}

private fun Long.saturatedAdd(value: Long): Long =
    if (value > 0L && this > Long.MAX_VALUE - value) Long.MAX_VALUE else this + value

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

private const val XAPK_METADATA_NAME = "manifest.json"

private data class AabModuleAccumulator(
    var entryCount: Int = 0,
    var declaredBytes: Long = 0L,
    var hasManifest: Boolean = false,
    var hasDex: Boolean = false,
    var hasResources: Boolean = false,
)

private data class AabPath(
    val moduleName: String?,
    val isModuleManifest: Boolean,
    val isDex: Boolean,
    val isResources: Boolean,
    val isBundleConfig: Boolean,
    val isMetadata: Boolean,
)

/** Recognizes only structural Android App Bundle paths; it never opens payloads. */
private fun parseAabPath(rawPath: String): AabPath? {
    val path = rawPath.replace('\\', '/').trimStart('/')
    if (path == "BundleConfig.pb") {
        return AabPath(null, false, false, false, isBundleConfig = true, isMetadata = false)
    }
    if (path.startsWith("BUNDLE-METADATA/")) {
        return AabPath(null, false, false, false, isBundleConfig = false, isMetadata = true)
    }
    val parts = path.split('/')
    if (parts.size < 2 || parts.first().isBlank() || parts.first() in setOf("META-INF", "BUNDLE-METADATA")) return null
    val module = parts.first()
    val remainder = parts.drop(1).joinToString("/")
    val isManifest = remainder == "manifest/AndroidManifest.xml"
    val isDex = remainder.startsWith("dex/") && remainder.endsWith(".dex")
    val isResources = remainder == "resources.pb" || remainder.startsWith("res/")
    if (!isManifest && !isDex && !isResources && remainder !in setOf("assets.pb", "native.pb", "root.pb")) return null
    return AabPath(module, isManifest, isDex, isResources, isBundleConfig = false, isMetadata = false)
}
private val APK_ZIP_SIGNATURE = byteArrayOf('P'.code.toByte(), 'K'.code.toByte(), 3, 4)
