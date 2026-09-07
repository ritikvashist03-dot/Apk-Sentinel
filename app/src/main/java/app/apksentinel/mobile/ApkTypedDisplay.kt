package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.ArchiveLimit
import app.apksentinel.inspector.BundleApkRole
import app.apksentinel.inspector.BundleFormat
import app.apksentinel.inspector.BundleIdentityStatus
import app.apksentinel.inspector.BundleLimitationCode
import app.apksentinel.inspector.ComponentType
import app.apksentinel.inspector.FindingConfidence
import app.apksentinel.inspector.FindingSeverity
import app.apksentinel.inspector.HeuristicFindingCode
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.InspectionProgressCode
import app.apksentinel.inspector.IntentFilterPathKind
import app.apksentinel.inspector.RiskExplanationCode
import app.apksentinel.inspector.RiskLevel
import app.apksentinel.inspector.RiskLimitationCode
import app.apksentinel.inspector.SignatureVerificationStatus
import app.apksentinel.inspector.SigningDiagnosticCode
import app.apksentinel.inspector.TrackerNamespaceCode

/** Presentation-only mappings for the APK-inspector's stable, non-prose contracts. */
internal fun Context.apkFindingTitle(code: HeuristicFindingCode): String = getString(when (code) {
    HeuristicFindingCode.UNSAFE_ARCHIVE_PATH -> R.string.apk_finding_unsafe_archive_path_title
    HeuristicFindingCode.TRACKER_FIREBASE_ANALYTICS -> R.string.apk_finding_tracker_firebase_analytics_title
    HeuristicFindingCode.TRACKER_GOOGLE_MEASUREMENT -> R.string.apk_finding_tracker_google_measurement_title
    HeuristicFindingCode.TRACKER_FACEBOOK -> R.string.apk_finding_tracker_facebook_title
    HeuristicFindingCode.TRACKER_APPSFLYER -> R.string.apk_finding_tracker_appsflyer_title
    HeuristicFindingCode.TRACKER_ADJUST -> R.string.apk_finding_tracker_adjust_title
    HeuristicFindingCode.TRACKER_MIXPANEL -> R.string.apk_finding_tracker_mixpanel_title
    HeuristicFindingCode.TRACKER_AMPLITUDE -> R.string.apk_finding_tracker_amplitude_title
    HeuristicFindingCode.TRACKER_SENTRY -> R.string.apk_finding_tracker_sentry_title
    HeuristicFindingCode.AD_NETWORK_GOOGLE_MOBILE_ADS -> R.string.apk_finding_ad_google_mobile_ads_title
    HeuristicFindingCode.AD_NETWORK_UNITY_ADS -> R.string.apk_finding_ad_unity_ads_title
    HeuristicFindingCode.AD_NETWORK_APPLOVIN -> R.string.apk_finding_ad_applovin_title
    HeuristicFindingCode.AD_NETWORK_IRONSOURCE -> R.string.apk_finding_ad_ironsource_title
    HeuristicFindingCode.AD_NETWORK_VUNGLE -> R.string.apk_finding_ad_vungle_title
    HeuristicFindingCode.AD_NETWORK_CHARTBOOST -> R.string.apk_finding_ad_chartboost_title
    HeuristicFindingCode.AD_NETWORK_INMOBI -> R.string.apk_finding_ad_inmobi_title
    HeuristicFindingCode.AD_NETWORK_PANGLE -> R.string.apk_finding_ad_pangle_title
    HeuristicFindingCode.AD_NETWORK_MINTEGRAL -> R.string.apk_finding_ad_mintegral_title
    HeuristicFindingCode.EMBEDDED_HTTP_ENDPOINT -> R.string.apk_finding_embedded_http_endpoint_title
})

internal fun Context.apkFindingDescription(code: HeuristicFindingCode): String = getString(when (code) {
    HeuristicFindingCode.UNSAFE_ARCHIVE_PATH -> R.string.apk_finding_unsafe_archive_path_body
    HeuristicFindingCode.TRACKER_FIREBASE_ANALYTICS,
    HeuristicFindingCode.TRACKER_GOOGLE_MEASUREMENT,
    HeuristicFindingCode.TRACKER_FACEBOOK,
    HeuristicFindingCode.TRACKER_APPSFLYER,
    HeuristicFindingCode.TRACKER_ADJUST,
    HeuristicFindingCode.TRACKER_MIXPANEL,
    HeuristicFindingCode.TRACKER_AMPLITUDE,
    HeuristicFindingCode.TRACKER_SENTRY -> R.string.apk_finding_tracker_body
    HeuristicFindingCode.AD_NETWORK_GOOGLE_MOBILE_ADS,
    HeuristicFindingCode.AD_NETWORK_UNITY_ADS,
    HeuristicFindingCode.AD_NETWORK_APPLOVIN,
    HeuristicFindingCode.AD_NETWORK_IRONSOURCE,
    HeuristicFindingCode.AD_NETWORK_VUNGLE,
    HeuristicFindingCode.AD_NETWORK_CHARTBOOST,
    HeuristicFindingCode.AD_NETWORK_INMOBI,
    HeuristicFindingCode.AD_NETWORK_PANGLE,
    HeuristicFindingCode.AD_NETWORK_MINTEGRAL -> R.string.apk_finding_ad_network_body
    HeuristicFindingCode.EMBEDDED_HTTP_ENDPOINT -> R.string.apk_finding_embedded_http_endpoint_body
})

internal fun Context.apkRiskExplanation(code: RiskExplanationCode): String = getString(when (code) {
    RiskExplanationCode.UNSAFE_ARCHIVE_PATH -> R.string.apk_risk_unsafe_archive_path
    RiskExplanationCode.ARCHIVE_SAFETY_LIMIT -> R.string.apk_risk_archive_safety_limit
    RiskExplanationCode.SIGNATURE_NOT_VERIFIED -> R.string.apk_risk_signature_not_verified
    RiskExplanationCode.SENSITIVE_PERMISSIONS -> R.string.apk_risk_sensitive_permissions
    RiskExplanationCode.DEBUGGABLE_BUILD -> R.string.apk_risk_debuggable_build
    RiskExplanationCode.EXPORTED_COMPONENTS -> R.string.apk_risk_exported_components
    RiskExplanationCode.BUNDLED_TRACKER_OR_TELEMETRY -> R.string.apk_risk_tracker_or_telemetry
    RiskExplanationCode.EMBEDDED_NETWORK_ENDPOINTS -> R.string.apk_risk_embedded_network_endpoints
})

internal fun Context.apkRiskLimitation(code: RiskLimitationCode): String = getString(when (code) {
    RiskLimitationCode.ARCHIVE_ENUMERATION_INCOMPLETE -> R.string.apk_limitation_archive_enumeration_incomplete
    RiskLimitationCode.MANIFEST_PERMISSION_OUTPUT_TRUNCATED -> R.string.apk_limitation_manifest_permission_output_truncated
    RiskLimitationCode.MANIFEST_COMPONENT_OUTPUT_TRUNCATED -> R.string.apk_limitation_manifest_component_output_truncated
    RiskLimitationCode.SIGNATURE_VERIFICATION_UNAVAILABLE -> R.string.apk_limitation_signature_verification_unavailable
    RiskLimitationCode.READABLE_MANIFEST_TRUNCATED -> R.string.apk_limitation_readable_manifest_truncated
    RiskLimitationCode.READABLE_MANIFEST_UNRESOLVED_RESOURCE_REFERENCES -> R.string.apk_limitation_readable_manifest_unresolved_references
    RiskLimitationCode.SOURCE_COPY_INCOMPLETE -> R.string.apk_limitation_source_copy_incomplete
    RiskLimitationCode.ARCHIVE_UNREADABLE -> R.string.apk_limitation_archive_unreadable
    RiskLimitationCode.ARCHIVE_SAFETY_LIMIT_REACHED -> R.string.apk_limitation_archive_safety_limit_reached
    RiskLimitationCode.ANDROID_MANIFEST_UNAVAILABLE -> R.string.apk_limitation_android_manifest_unavailable
    RiskLimitationCode.HEURISTIC_SCAN_BOUNDED -> R.string.apk_limitation_heuristic_scan_bounded
    RiskLimitationCode.HEURISTIC_FINDINGS_TRUNCATED -> R.string.apk_limitation_heuristic_findings_truncated
    RiskLimitationCode.TEMPORARY_FILE_CLEANUP_FAILED -> R.string.apk_limitation_temporary_file_cleanup_failed
})

internal fun Context.apkInspectionFailure(code: InspectionFailureCode): String = getString(when (code) {
    InspectionFailureCode.TEMP_FILE_CREATION_FAILED -> R.string.apk_failure_temp_file_creation_failed
    InspectionFailureCode.SOURCE_PERMISSION_DENIED -> R.string.apk_failure_source_permission_denied
    InspectionFailureCode.SOURCE_OPEN_FAILED -> R.string.apk_failure_source_open_failed
    InspectionFailureCode.SOURCE_NOT_FOUND -> R.string.apk_failure_source_not_found
    InspectionFailureCode.SOURCE_COPY_FAILED -> R.string.apk_failure_source_copy_failed
    InspectionFailureCode.PACKAGE_NAME_INVALID -> R.string.apk_failure_package_name_invalid
    InspectionFailureCode.INSTALLED_PACKAGE_UNAVAILABLE -> R.string.apk_failure_installed_package_unavailable
    InspectionFailureCode.SOURCE_SIZE_LIMIT_EXCEEDED -> R.string.apk_failure_source_size_limit_exceeded
    InspectionFailureCode.ZIP_OPEN_FAILED -> R.string.apk_failure_zip_open_failed
    InspectionFailureCode.ZIP_SIGNATURE_MISSING -> R.string.apk_failure_zip_signature_missing
    InspectionFailureCode.ZIP_READ_FAILED -> R.string.apk_failure_zip_read_failed
    InspectionFailureCode.ARCHIVE_LIMIT_EXCEEDED -> R.string.apk_failure_archive_limit_exceeded
    InspectionFailureCode.MANIFEST_PARSE_FAILED -> R.string.apk_failure_manifest_parse_failed
    InspectionFailureCode.MANIFEST_NOT_PARSEABLE -> R.string.apk_failure_manifest_not_parseable
    InspectionFailureCode.MANIFEST_TEXT_DECODE_FAILED -> R.string.apk_failure_manifest_text_decode_failed
    InspectionFailureCode.MANIFEST_ENTRY_MISSING -> R.string.apk_failure_manifest_entry_missing
    InspectionFailureCode.SIGNATURE_VERIFICATION_FAILED -> R.string.apk_failure_signature_verification_failed
    InspectionFailureCode.HEURISTIC_SCAN_TRUNCATED -> R.string.apk_failure_heuristic_scan_truncated
    InspectionFailureCode.HEURISTIC_FINDINGS_TRUNCATED -> R.string.apk_failure_heuristic_findings_truncated
    InspectionFailureCode.TEMP_FILE_DELETE_FAILED -> R.string.apk_failure_temp_file_delete_failed
})

internal fun Context.apkSigningDiagnostic(code: SigningDiagnosticCode): String = getString(when (code) {
    SigningDiagnosticCode.SIGNATURE_NOT_VALID -> R.string.apk_signing_diagnostic_not_valid
    SigningDiagnosticCode.SIGNATURE_VERIFICATION_UNAVAILABLE -> R.string.apk_signing_diagnostic_unavailable
})

internal fun Context.apkInspectionProgress(code: InspectionProgressCode): String = getString(when (code) {
    InspectionProgressCode.PREPARING_PRIVATE_COPY -> R.string.apk_progress_preparing_private_copy
    InspectionProgressCode.COPYING_PRIVATE_ARTIFACT -> R.string.apk_progress_copying_private_artifact
    InspectionProgressCode.INSPECTING_ARCHIVE -> R.string.apk_progress_inspecting_archive
    InspectionProgressCode.PARSING_MANIFEST -> R.string.apk_progress_parsing_manifest
    InspectionProgressCode.VERIFYING_SIGNATURE -> R.string.apk_progress_verifying_signature
    InspectionProgressCode.SCORING_RISK -> R.string.apk_progress_scoring_risk
    InspectionProgressCode.COMPLETE -> R.string.apk_progress_complete
})

internal fun Context.apkTechnicalEvidence(evidence: ApkTechnicalEvidence): String = when (evidence) {
    is ApkTechnicalEvidence.ArchiveEntryPath -> getString(R.string.apk_evidence_archive_entry_path, evidence.value.safeTechnicalDisplay())
    is ApkTechnicalEvidence.TrackerNamespaceMatch -> getString(R.string.apk_evidence_tracker_namespace, apkTrackerNamespace(evidence.tracker), evidence.marker.safeTechnicalDisplay())
    is ApkTechnicalEvidence.EndpointLiteral -> getString(R.string.apk_evidence_endpoint_literal, evidence.value.safeTechnicalDisplay())
    is ApkTechnicalEvidence.PathTraversalCount -> getString(R.string.apk_evidence_path_traversal_count, evidence.value)
    is ApkTechnicalEvidence.ArchiveLimitObservation -> getString(R.string.apk_evidence_archive_limit, apkArchiveLimit(evidence.limit), evidence.observed, evidence.maximum)
    is ApkTechnicalEvidence.RequestedPermission -> getString(R.string.apk_evidence_requested_permission, evidence.value.safeTechnicalDisplay())
    ApkTechnicalEvidence.DebuggableManifest -> getString(R.string.apk_evidence_debuggable_manifest)
    is ApkTechnicalEvidence.ExportedComponent -> getString(R.string.apk_evidence_exported_component, apkComponentType(evidence.type), evidence.className.safeTechnicalDisplay())
    is ApkTechnicalEvidence.FindingCount -> getString(R.string.apk_evidence_finding_count, evidence.retained, evidence.maximum)
    is ApkTechnicalEvidence.ByteLimitObservation -> getString(R.string.apk_evidence_byte_limit, evidence.observed, evidence.maximum)
    is ApkTechnicalEvidence.UnresolvedResourceReferenceCount -> getString(R.string.apk_evidence_unresolved_resource_reference_count, evidence.value)
}

internal fun Context.apkSeverity(value: FindingSeverity): String = getString(when (value) {
    FindingSeverity.INFO -> R.string.apk_severity_info
    FindingSeverity.LOW -> R.string.apk_severity_low
    FindingSeverity.MEDIUM -> R.string.apk_severity_medium
    FindingSeverity.HIGH -> R.string.apk_severity_high
})

internal fun Context.apkConfidence(value: FindingConfidence): String = getString(when (value) {
    FindingConfidence.LOW -> R.string.apk_confidence_low
    FindingConfidence.MEDIUM -> R.string.apk_confidence_medium
    FindingConfidence.HIGH -> R.string.apk_confidence_high
})

internal fun Context.apkRiskLevel(value: RiskLevel): String = getString(when (value) {
    RiskLevel.LOW -> R.string.apk_risk_level_low
    RiskLevel.MODERATE -> R.string.apk_risk_level_moderate
    RiskLevel.HIGH -> R.string.apk_risk_level_high
    RiskLevel.CRITICAL -> R.string.apk_risk_level_critical
})

internal fun Context.apkSigningStatus(value: SignatureVerificationStatus): String = getString(when (value) {
    SignatureVerificationStatus.VERIFIED -> R.string.apk_signing_status_verified
    SignatureVerificationStatus.NOT_VERIFIED -> R.string.apk_signing_status_not_verified
    SignatureVerificationStatus.UNAVAILABLE -> R.string.apk_signing_status_unavailable
})

internal fun Context.apkComponentType(value: ComponentType): String = getString(when (value) {
    ComponentType.ACTIVITY -> R.string.apk_component_activity
    ComponentType.SERVICE -> R.string.apk_component_service
    ComponentType.RECEIVER -> R.string.apk_component_receiver
    ComponentType.PROVIDER -> R.string.apk_component_provider
})

internal fun Context.apkBundleFormat(value: BundleFormat): String = getString(when (value) {
    BundleFormat.APKS -> R.string.bundle_format_apks
    BundleFormat.XAPK -> R.string.bundle_format_xapk
    BundleFormat.AAB -> R.string.bundle_format_aab
})

internal fun Context.apkBundleRole(value: BundleApkRole): String = getString(when (value) {
    BundleApkRole.BASE -> R.string.bundle_role_base
    BundleApkRole.FEATURE -> R.string.bundle_role_feature
    BundleApkRole.CONFIG -> R.string.bundle_role_config
    BundleApkRole.UNKNOWN -> R.string.bundle_role_unknown
})

internal fun Context.apkBundleIdentityStatus(value: BundleIdentityStatus): String = getString(when (value) {
    BundleIdentityStatus.VERIFIED -> R.string.bundle_identity_verified
    BundleIdentityStatus.INCOMPLETE -> R.string.bundle_identity_incomplete
    BundleIdentityStatus.INCONSISTENT -> R.string.bundle_identity_inconsistent
    BundleIdentityStatus.UNAVAILABLE -> R.string.bundle_identity_unavailable
})

internal fun Context.apkBundleLimitation(value: BundleLimitationCode): String = getString(when (value) {
    BundleLimitationCode.MISSING_BASE -> R.string.bundle_limitation_missing_base
    BundleLimitationCode.DUPLICATE_BASE -> R.string.bundle_limitation_duplicate_base
    BundleLimitationCode.IDENTITY_UNAVAILABLE -> R.string.bundle_limitation_identity_unavailable
    BundleLimitationCode.NESTED_EVIDENCE_INCOMPLETE -> R.string.bundle_limitation_nested_incomplete
    BundleLimitationCode.NESTED_APK_UNREADABLE -> R.string.bundle_limitation_nested_unreadable
    BundleLimitationCode.NESTED_EVIDENCE_BOUNDED -> R.string.bundle_limitation_nested_bounded
    BundleLimitationCode.NESTED_APK_LIMIT_REACHED -> R.string.bundle_limitation_nested_limit
    BundleLimitationCode.NESTED_EXPANSION_LIMIT_REACHED -> R.string.bundle_limitation_expansion_limit
    BundleLimitationCode.METADATA_LIMIT_REACHED -> R.string.bundle_limitation_metadata_limit
    BundleLimitationCode.CONTAINER_LIMIT_REACHED -> R.string.bundle_limitation_container_limit
    BundleLimitationCode.UNSAFE_PATH -> R.string.bundle_limitation_unsafe_path
    BundleLimitationCode.METADATA_UNTRUSTED -> R.string.bundle_limitation_metadata_untrusted
    BundleLimitationCode.IDENTITY_MISMATCH -> R.string.bundle_limitation_identity_mismatch
    BundleLimitationCode.SIGNER_MISMATCH -> R.string.bundle_limitation_signer_mismatch
    BundleLimitationCode.SIGNER_UNAVAILABLE -> R.string.bundle_limitation_signer_unavailable
    BundleLimitationCode.OBB_INVENTORY_TRUNCATED -> R.string.bundle_limitation_obb_truncated
    BundleLimitationCode.BUNDLE_NOT_INSTALLABILITY_VERIFIED -> R.string.bundle_limitation_not_installability_verified
    BundleLimitationCode.AAB_PUBLISHING_BUNDLE_ONLY -> R.string.bundle_limitation_aab_publishing_only
    BundleLimitationCode.AAB_EVIDENCE_BOUNDED -> R.string.bundle_limitation_aab_evidence_bounded
})

/** Localized label for the manifest's typed Android path matcher. */
internal fun Context.apkIntentFilterPathKind(value: IntentFilterPathKind): String = getString(when (value) {
    IntentFilterPathKind.LITERAL -> R.string.apk_intent_filter_path_literal
    IntentFilterPathKind.PREFIX -> R.string.apk_intent_filter_path_prefix
    IntentFilterPathKind.PATTERN -> R.string.apk_intent_filter_path_pattern
    IntentFilterPathKind.ADVANCED_PATTERN -> R.string.apk_intent_filter_path_advanced_pattern
    IntentFilterPathKind.SUFFIX -> R.string.apk_intent_filter_path_suffix
})

/** Removes control and bidi characters before bounded manifest evidence is rendered. */
internal fun String.safeApkTechnicalDisplay(fallback: String, maximumCodePoints: Int = 300): String =
    SafeTextNormalizer.normalizeDisplayText(this, fallback, maximumCodePoints)

private fun Context.apkArchiveLimit(value: ArchiveLimit): String = getString(when (value) {
    ArchiveLimit.ENTRY_COUNT -> R.string.apk_archive_limit_entry_count
    ArchiveLimit.TOTAL_UNCOMPRESSED_BYTES -> R.string.apk_archive_limit_total_uncompressed_bytes
    ArchiveLimit.ENTRY_UNCOMPRESSED_BYTES -> R.string.apk_archive_limit_entry_uncompressed_bytes
    ArchiveLimit.COMPRESSION_RATIO -> R.string.apk_archive_limit_compression_ratio
})

private fun Context.apkTrackerNamespace(value: TrackerNamespaceCode): String = getString(when (value) {
    TrackerNamespaceCode.FIREBASE_ANALYTICS -> R.string.apk_tracker_namespace_firebase_analytics
    TrackerNamespaceCode.GOOGLE_MEASUREMENT -> R.string.apk_tracker_namespace_google_measurement
    TrackerNamespaceCode.FACEBOOK -> R.string.apk_tracker_namespace_facebook
    TrackerNamespaceCode.APPSFLYER -> R.string.apk_tracker_namespace_appsflyer
    TrackerNamespaceCode.ADJUST -> R.string.apk_tracker_namespace_adjust
    TrackerNamespaceCode.MIXPANEL -> R.string.apk_tracker_namespace_mixpanel
    TrackerNamespaceCode.AMPLITUDE -> R.string.apk_tracker_namespace_amplitude
    TrackerNamespaceCode.SENTRY -> R.string.apk_tracker_namespace_sentry
    TrackerNamespaceCode.GOOGLE_MOBILE_ADS -> R.string.apk_ad_namespace_google_mobile_ads
    TrackerNamespaceCode.UNITY_ADS -> R.string.apk_ad_namespace_unity_ads
    TrackerNamespaceCode.APPLOVIN -> R.string.apk_ad_namespace_applovin
    TrackerNamespaceCode.IRONSOURCE -> R.string.apk_ad_namespace_ironsource
    TrackerNamespaceCode.VUNGLE -> R.string.apk_ad_namespace_vungle
    TrackerNamespaceCode.CHARTBOOST -> R.string.apk_ad_namespace_chartboost
    TrackerNamespaceCode.INMOBI -> R.string.apk_ad_namespace_inmobi
    TrackerNamespaceCode.PANGLE -> R.string.apk_ad_namespace_pangle
    TrackerNamespaceCode.MINTEGRAL -> R.string.apk_ad_namespace_mintegral
})

private fun String.safeTechnicalDisplay(): String = safeApkTechnicalDisplay("?")
