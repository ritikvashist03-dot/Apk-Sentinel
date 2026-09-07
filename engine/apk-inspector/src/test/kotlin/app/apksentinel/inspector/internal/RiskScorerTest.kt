package app.apksentinel.inspector.internal

import app.apksentinel.inspector.AndroidSdkSummary
import app.apksentinel.inspector.ArchiveFormat
import app.apksentinel.inspector.ArchiveLimit
import app.apksentinel.inspector.ArchiveLimitExceeded
import app.apksentinel.inspector.ArchiveMetadata
import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.ApkInspectionResult
import app.apksentinel.inspector.ComponentType
import app.apksentinel.inspector.FindingConfidence
import app.apksentinel.inspector.FindingKind
import app.apksentinel.inspector.FindingSeverity
import app.apksentinel.inspector.HeuristicFinding
import app.apksentinel.inspector.HeuristicFindingCode
import app.apksentinel.inspector.HeuristicFindingsTruncated
import app.apksentinel.inspector.ManifestComponent
import app.apksentinel.inspector.ManifestSummary
import app.apksentinel.inspector.RiskLevel
import app.apksentinel.inspector.RiskExplanationCode
import app.apksentinel.inspector.RiskLimitationCode
import app.apksentinel.inspector.SignatureVerificationStatus
import app.apksentinel.inspector.SigningDiagnosticCode
import app.apksentinel.inspector.SigningSummary
import app.apksentinel.inspector.SourceArtifact
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskScorerTest {
    @Test
    fun reportsEveryPointForUnsafePathsAndAnUnverifiedSignature() {
        val risk = RiskScorer.score(
            archive = archive(pathTraversalEntryCount = 1),
            manifest = null,
            signing = signing(SignatureVerificationStatus.NOT_VERIFIED),
            findings = emptyList(),
            failures = emptyList(),
        )

        requireNotNull(risk)
        assertEquals(70, risk.score)
        assertEquals(RiskLevel.HIGH, risk.level)
        assertEquals(
            setOf(
                RiskExplanationCode.UNSAFE_ARCHIVE_PATH,
                RiskExplanationCode.SIGNATURE_NOT_VERIFIED,
            ),
            risk.explanations.map { it.code }.toSet(),
        )
    }

    @Test
    fun capsAStackedScoreAndKeepsTheEvidenceVisible() {
        val risk = RiskScorer.score(
            archive = archive(pathTraversalEntryCount = 1),
            manifest = ManifestSummary(
                packageName = "example.test",
                versionName = "1",
                versionCode = 1,
                sdk = AndroidSdkSummary(minSdk = 26, targetSdk = 35),
                permissions = listOf(
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.QUERY_ALL_PACKAGES",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.ACCESS_FINE_LOCATION",
                ),
                permissionsTruncated = false,
                components = List(5) { index ->
                    ManifestComponent(
                        type = ComponentType.SERVICE,
                        className = "example.test.Service" + index,
                        exported = true,
                        enabled = true,
                        requiredPermission = null,
                    )
                },
                componentsTruncated = false,
                debugBuild = true,
            ),
            signing = signing(SignatureVerificationStatus.NOT_VERIFIED),
            findings = listOf(
                finding(FindingKind.TRACKER_NAMESPACE, "Tracker A"),
                finding(FindingKind.TRACKER_NAMESPACE, "Tracker B"),
                finding(FindingKind.TRACKER_NAMESPACE, "Tracker C"),
                finding(FindingKind.TRACKER_NAMESPACE, "Tracker D"),
                finding(FindingKind.TRACKER_NAMESPACE, "Tracker E"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint A"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint B"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint C"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint D"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint E"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint F"),
                finding(FindingKind.EMBEDDED_ENDPOINT, "Endpoint G"),
            ),
            failures = listOf(
                ArchiveLimitExceeded(
                    limit = ArchiveLimit.COMPRESSION_RATIO,
                    observed = 150.0,
                    maximum = 100.0,
                ),
            ),
        )

        requireNotNull(risk)
        assertEquals(100, risk.score)
        assertEquals(RiskLevel.CRITICAL, risk.level)
        assertTrue(risk.explanations.any { it.code == RiskExplanationCode.SENSITIVE_PERMISSIONS })
        assertTrue(risk.explanations.any { it.code == RiskExplanationCode.ARCHIVE_SAFETY_LIMIT })
        assertEquals(
            15,
            risk.explanations.single { it.code == RiskExplanationCode.BUNDLED_TRACKER_OR_TELEMETRY }.points,
        )
        assertTrue(
            risk.limitations.any { it.code == RiskLimitationCode.ARCHIVE_SAFETY_LIMIT_REACHED },
        )
    }

    @Test
    fun returnsNoRiskVerdictWhenNoInspectionEvidenceExists() {
        assertNull(
            RiskScorer.score(
                archive = null,
                manifest = null,
                signing = null,
                findings = emptyList(),
                failures = emptyList(),
            ),
        )
    }

    @Test
    fun exposesFindingLimitAsARiskLimitationAndPartialInspection() {
        val failure = HeuristicFindingsTruncated(retainedFindings = 1, maximumFindings = 1)
        val risk = requireNotNull(
            RiskScorer.score(
                archive = archive(pathTraversalEntryCount = 0),
                manifest = null,
                signing = null,
                findings = emptyList(),
                failures = listOf(failure),
            ),
        )

        assertTrue(
            risk.limitations.any { it.code == RiskLimitationCode.HEURISTIC_FINDINGS_TRUNCATED },
        )
        assertFalse(
            ApkInspectionResult(
                source = SourceArtifact(byteCount = 1, sha256 = "00"),
                archive = archive(pathTraversalEntryCount = 0),
                failures = listOf(failure),
            ).isComplete,
        )
    }

    private fun archive(pathTraversalEntryCount: Int): ArchiveMetadata = ArchiveMetadata(
        format = ArchiveFormat.ZIP,
        entryCount = 1,
        declaredCompressedBytes = 10,
        declaredUncompressedBytes = 10,
        observedUncompressedBytes = 10,
        entriesWithUnknownCompressedSize = 0,
        entriesWithUnknownUncompressedSize = 0,
        maximumObservedCompressionRatio = 1.0,
        containsAndroidManifest = true,
        pathTraversalEntryCount = pathTraversalEntryCount,
        isComplete = true,
    )

    private fun signing(status: SignatureVerificationStatus): SigningSummary = SigningSummary(
        status = status,
        certificates = emptyList(),
        verifiedSchemes = emptyList(),
        diagnostics = listOf(SigningDiagnosticCode.SIGNATURE_NOT_VALID),
    )

    private fun finding(kind: FindingKind, title: String): HeuristicFinding = HeuristicFinding(
        code = when (kind) {
            FindingKind.TRACKER_NAMESPACE -> trackerCodeFor(title)
            FindingKind.EMBEDDED_ENDPOINT -> HeuristicFindingCode.EMBEDDED_HTTP_ENDPOINT
            FindingKind.UNSAFE_ARCHIVE_PATH -> HeuristicFindingCode.UNSAFE_ARCHIVE_PATH
        },
        severity = FindingSeverity.INFO,
        confidence = FindingConfidence.MEDIUM,
        evidence = when (kind) {
            FindingKind.EMBEDDED_ENDPOINT -> listOf(
                ApkTechnicalEvidence.EndpointLiteral("https://example.test/" + title),
            )
            FindingKind.TRACKER_NAMESPACE -> listOf(
                ApkTechnicalEvidence.TrackerNamespaceMatch(
                    app.apksentinel.inspector.TrackerNamespaceCode.FACEBOOK,
                    "com/facebook/",
                ),
            )
            FindingKind.UNSAFE_ARCHIVE_PATH -> listOf(
                ApkTechnicalEvidence.ArchiveEntryPath("../" + title),
            )
        },
    )

    private fun trackerCodeFor(title: String): HeuristicFindingCode = when (title.lastOrNull()) {
        'A' -> HeuristicFindingCode.TRACKER_FIREBASE_ANALYTICS
        'B' -> HeuristicFindingCode.TRACKER_GOOGLE_MEASUREMENT
        'C' -> HeuristicFindingCode.TRACKER_FACEBOOK
        'D' -> HeuristicFindingCode.TRACKER_APPSFLYER
        'E' -> HeuristicFindingCode.TRACKER_ADJUST
        else -> HeuristicFindingCode.TRACKER_FACEBOOK
    }
}
