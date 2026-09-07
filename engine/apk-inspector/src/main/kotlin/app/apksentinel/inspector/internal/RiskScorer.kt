package app.apksentinel.inspector.internal

import app.apksentinel.inspector.AndroidManifestUnavailable
import app.apksentinel.inspector.ArchiveLimitExceeded
import app.apksentinel.inspector.ArchiveMetadata
import app.apksentinel.inspector.ArchiveUnreadable
import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.FindingKind
import app.apksentinel.inspector.HeuristicFinding
import app.apksentinel.inspector.HeuristicFindingsTruncated
import app.apksentinel.inspector.HeuristicScanTruncated
import app.apksentinel.inspector.InspectionFailure
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.ManifestSummary
import app.apksentinel.inspector.NestedMemberInspectionFailure
import app.apksentinel.inspector.RiskAssessment
import app.apksentinel.inspector.RiskExplanation
import app.apksentinel.inspector.RiskExplanationCode
import app.apksentinel.inspector.RiskLimitation
import app.apksentinel.inspector.RiskLimitationCode
import app.apksentinel.inspector.RiskLevel
import app.apksentinel.inspector.SignatureVerificationStatus
import app.apksentinel.inspector.SigningSummary
import app.apksentinel.inspector.SigningUnavailable
import app.apksentinel.inspector.SourceSizeLimitExceeded
import app.apksentinel.inspector.SourceUnavailable
import app.apksentinel.inspector.TemporaryFileCleanupFailed
import app.apksentinel.inspector.DecodedManifestText

/**
 * A transparent triage score, not a malware verdict. Every point has a rule and
 * evidence so a caller can render the reasoning instead of a black-box label.
 */
internal object RiskScorer {
    fun score(
        archive: ArchiveMetadata?,
        manifest: ManifestSummary?,
        signing: SigningSummary?,
        findings: List<HeuristicFinding>,
        failures: List<InspectionFailure>,
        decodedManifest: DecodedManifestText? = null,
    ): RiskAssessment? {
        val hasEvidence = archive != null || manifest != null || signing != null || findings.isNotEmpty()
        if (!hasEvidence) {
            return null
        }

        val explanations = mutableListOf<RiskExplanation>()
        var score = 0
        fun add(
            code: RiskExplanationCode,
            points: Int,
            evidence: List<ApkTechnicalEvidence>,
        ) {
            score += points
            explanations += RiskExplanation(
                code = code,
                points = points,
                evidence = evidence,
            )
        }

        if ((archive?.pathTraversalEntryCount ?: 0) > 0) {
            add(
                code = RiskExplanationCode.UNSAFE_ARCHIVE_PATH,
                points = 35,
                evidence = listOf(
                    ApkTechnicalEvidence.PathTraversalCount(archive?.pathTraversalEntryCount ?: 0),
                ),
            )
        }

        failures.filterIsInstance<ArchiveLimitExceeded>().firstOrNull()?.let { limit ->
            add(
                code = RiskExplanationCode.ARCHIVE_SAFETY_LIMIT,
                points = 30,
                evidence = listOf(
                    ApkTechnicalEvidence.ArchiveLimitObservation(
                        limit = limit.limit,
                        observed = limit.observed,
                        maximum = limit.maximum,
                    ),
                ),
            )
        }

        when (signing?.status) {
            SignatureVerificationStatus.NOT_VERIFIED -> add(
                code = RiskExplanationCode.SIGNATURE_NOT_VERIFIED,
                points = 35,
                evidence = emptyList(),
            )

            else -> Unit
        }

        val sensitivePermissions = manifest
            ?.permissions
            ?.filter { permission -> permission in SENSITIVE_PERMISSIONS }
            ?.distinct()
            .orEmpty()
        if (sensitivePermissions.isNotEmpty()) {
            add(
                code = RiskExplanationCode.SENSITIVE_PERMISSIONS,
                points = minOf(24, sensitivePermissions.size * 4),
                evidence = sensitivePermissions.take(MAX_EVIDENCE_ITEMS).map { permission ->
                    ApkTechnicalEvidence.RequestedPermission(permission)
                },
            )
        }

        if (manifest?.debugBuild == true) {
            add(
                code = RiskExplanationCode.DEBUGGABLE_BUILD,
                points = 10,
                evidence = listOf(ApkTechnicalEvidence.DebuggableManifest),
            )
        }

        val exportedComponents = manifest
            ?.components
            ?.filter { component -> component.exported == true }
            .orEmpty()
        if (exportedComponents.isNotEmpty()) {
            add(
                code = RiskExplanationCode.EXPORTED_COMPONENTS,
                points = if (exportedComponents.size >= 5) 10 else 4,
                evidence = exportedComponents.take(MAX_EVIDENCE_ITEMS).map { component ->
                    ApkTechnicalEvidence.ExportedComponent(component.type, component.className)
                },
            )
        }

        val trackerFindings = findings
            .filter { finding -> finding.kind == FindingKind.TRACKER_NAMESPACE }
            .distinctBy { finding -> finding.code }
        if (trackerFindings.isNotEmpty()) {
            add(
                code = RiskExplanationCode.BUNDLED_TRACKER_OR_TELEMETRY,
                points = minOf(15, trackerFindings.size * 3),
                evidence = trackerFindings.take(MAX_EVIDENCE_ITEMS).mapNotNull { finding ->
                    finding.evidence.filterIsInstance<ApkTechnicalEvidence.TrackerNamespaceMatch>().firstOrNull()
                },
            )
        }

        val endpointFindings = findings
            .filter { finding -> finding.kind == FindingKind.EMBEDDED_ENDPOINT }
            .distinctBy { finding ->
                finding.evidence.filterIsInstance<ApkTechnicalEvidence.EndpointLiteral>().firstOrNull()?.value
            }
        if (endpointFindings.isNotEmpty()) {
            add(
                code = RiskExplanationCode.EMBEDDED_NETWORK_ENDPOINTS,
                points = minOf(6, endpointFindings.size),
                evidence = endpointFindings.take(MAX_EVIDENCE_ITEMS).flatMap { finding ->
                    finding.evidence.filterIsInstance<ApkTechnicalEvidence.EndpointLiteral>()
                },
            )
        }

        val boundedScore = score.coerceIn(0, 100)
        return RiskAssessment(
            score = boundedScore,
            level = riskLevelFor(boundedScore),
            explanations = explanations.toList(),
            limitations = buildLimitations(archive, manifest, signing, failures, decodedManifest),
        )
    }
}

private fun riskLevelFor(score: Int): RiskLevel = when (score) {
    in 0..19 -> RiskLevel.LOW
    in 20..49 -> RiskLevel.MODERATE
    in 50..74 -> RiskLevel.HIGH
    else -> RiskLevel.CRITICAL
}

private fun buildLimitations(
    archive: ArchiveMetadata?,
    manifest: ManifestSummary?,
    signing: SigningSummary?,
    failures: List<InspectionFailure>,
    decodedManifest: DecodedManifestText?,
): List<RiskLimitation> {
    val limitations = linkedSetOf<RiskLimitation>()
    if (archive?.isComplete == false) {
        limitations += RiskLimitation(RiskLimitationCode.ARCHIVE_ENUMERATION_INCOMPLETE)
    }
    if (manifest?.permissionsTruncated == true) {
        limitations += RiskLimitation(RiskLimitationCode.MANIFEST_PERMISSION_OUTPUT_TRUNCATED)
    }
    if (manifest?.componentsTruncated == true) {
        limitations += RiskLimitation(RiskLimitationCode.MANIFEST_COMPONENT_OUTPUT_TRUNCATED)
    }
    if (signing?.status == SignatureVerificationStatus.UNAVAILABLE) {
        limitations += RiskLimitation(RiskLimitationCode.SIGNATURE_VERIFICATION_UNAVAILABLE)
    }
    if (decodedManifest?.isTruncated == true) {
        limitations += RiskLimitation(RiskLimitationCode.READABLE_MANIFEST_TRUNCATED)
    }
    if ((decodedManifest?.unresolvedResourceReferenceCount ?: 0) > 0) {
        limitations += RiskLimitation(
            RiskLimitationCode.READABLE_MANIFEST_UNRESOLVED_RESOURCE_REFERENCES,
            listOf(
                ApkTechnicalEvidence.UnresolvedResourceReferenceCount(
                    decodedManifest?.unresolvedResourceReferenceCount ?: 0,
                ),
            ),
        )
    }

    failures.forEach { failure ->
        limitations += when (failure) {
            is SourceUnavailable,
            is SourceSizeLimitExceeded -> RiskLimitation(RiskLimitationCode.SOURCE_COPY_INCOMPLETE)

            is ArchiveUnreadable -> RiskLimitation(RiskLimitationCode.ARCHIVE_UNREADABLE)
            is ArchiveLimitExceeded -> RiskLimitation(
                RiskLimitationCode.ARCHIVE_SAFETY_LIMIT_REACHED,
                listOf(
                    ApkTechnicalEvidence.ArchiveLimitObservation(
                        failure.limit,
                        failure.observed,
                        failure.maximum,
                    ),
                ),
            )
            is AndroidManifestUnavailable -> RiskLimitation(RiskLimitationCode.ANDROID_MANIFEST_UNAVAILABLE)
            is SigningUnavailable -> RiskLimitation(RiskLimitationCode.SIGNATURE_VERIFICATION_UNAVAILABLE)
            is HeuristicScanTruncated -> RiskLimitation(
                RiskLimitationCode.HEURISTIC_SCAN_BOUNDED,
                listOf(ApkTechnicalEvidence.ByteLimitObservation(failure.scannedBytes, failure.maximumBytes)),
            )
            is HeuristicFindingsTruncated -> RiskLimitation(
                RiskLimitationCode.HEURISTIC_FINDINGS_TRUNCATED,
                listOf(ApkTechnicalEvidence.FindingCount(failure.retainedFindings, failure.maximumFindings)),
            )
            is TemporaryFileCleanupFailed -> RiskLimitation(RiskLimitationCode.TEMPORARY_FILE_CLEANUP_FAILED)
            is NestedMemberInspectionFailure -> when (failure.code) {
                InspectionFailureCode.ZIP_OPEN_FAILED,
                InspectionFailureCode.ZIP_SIGNATURE_MISSING,
                InspectionFailureCode.ZIP_READ_FAILED,
                InspectionFailureCode.MANIFEST_ENTRY_MISSING,
                InspectionFailureCode.MANIFEST_PARSE_FAILED,
                InspectionFailureCode.MANIFEST_NOT_PARSEABLE,
                InspectionFailureCode.MANIFEST_TEXT_DECODE_FAILED -> RiskLimitation(RiskLimitationCode.ARCHIVE_UNREADABLE)

                InspectionFailureCode.ARCHIVE_LIMIT_EXCEEDED -> RiskLimitation(RiskLimitationCode.ARCHIVE_SAFETY_LIMIT_REACHED)
                InspectionFailureCode.SIGNATURE_VERIFICATION_FAILED -> RiskLimitation(RiskLimitationCode.SIGNATURE_VERIFICATION_UNAVAILABLE)
                InspectionFailureCode.HEURISTIC_SCAN_TRUNCATED -> RiskLimitation(RiskLimitationCode.HEURISTIC_SCAN_BOUNDED)
                InspectionFailureCode.HEURISTIC_FINDINGS_TRUNCATED -> RiskLimitation(RiskLimitationCode.HEURISTIC_FINDINGS_TRUNCATED)
                else -> RiskLimitation(RiskLimitationCode.ARCHIVE_ENUMERATION_INCOMPLETE)
            }
        }
    }
    return limitations.toList()
}

private const val MAX_EVIDENCE_ITEMS = 10

private val SENSITIVE_PERMISSIONS = setOf(
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.CAMERA",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.REQUEST_DELETE_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
)
