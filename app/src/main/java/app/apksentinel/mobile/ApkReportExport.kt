package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.reporting.LocalReport
import app.apksentinel.core.reporting.ReportField
import app.apksentinel.core.reporting.ReportSection
import app.apksentinel.core.reporting.ReportSensitivity
import app.apksentinel.engine.threatintel.ThreatIndicator
import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.ApkInspectionResult
import app.apksentinel.inspector.HeuristicFindingCode
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.ManifestComponent
import app.apksentinel.inspector.RiskExplanationCode
import app.apksentinel.inspector.RiskLimitationCode
import app.apksentinel.inspector.SigningDiagnosticCode

/** Localized presentation text for an APK JSON report; report keys and evidence stay engine-defined. */
internal class ApkReportText private constructor(private val context: Context) {
    private fun text(id: Int) = context.getString(id)

    val unknown = text(R.string.apk_report_unknown)
    val unavailable = text(R.string.apk_report_unavailable)
    val none = text(R.string.apk_report_none)
    val notApplicable = text(R.string.apk_report_not_applicable)
    val readableManifestExportNote = text(R.string.apk_report_readable_manifest_export_note)

    fun section(key: String): String = text(when (key) {
        "summary" -> R.string.apk_report_section_summary
        "artifact" -> R.string.apk_report_section_artifact
        "archive" -> R.string.apk_report_section_archive
        "manifest" -> R.string.apk_report_section_manifest
        "decoded_manifest" -> R.string.apk_report_section_decoded_manifest
        "signing" -> R.string.apk_report_section_signing
        "inventory" -> R.string.apk_report_section_inventory
        "findings" -> R.string.apk_report_section_findings
        "bundle" -> R.string.bundle_export_section
        else -> R.string.apk_report_section_threat_matches
    })

    fun field(key: String): String = text(when (key) {
        "code" -> R.string.apk_report_field_code
        "risk_score" -> R.string.apk_report_field_risk_score
        "risk_level" -> R.string.apk_report_field_risk_level
        "complete" -> R.string.apk_report_field_complete
        "stopped_for_safety" -> R.string.apk_report_field_stopped_for_safety
        "bytes" -> R.string.apk_report_field_bytes
        "sha256" -> R.string.apk_report_field_sha256
        "entry_count" -> R.string.apk_report_field_entry_count
        "declared_compressed_bytes" -> R.string.apk_report_field_declared_compressed_bytes
        "declared_uncompressed_bytes" -> R.string.apk_report_field_declared_uncompressed_bytes
        "observed_uncompressed_bytes" -> R.string.apk_report_field_observed_uncompressed_bytes
        "maximum_compression_ratio" -> R.string.apk_report_field_maximum_compression_ratio
        "unsafe_paths" -> R.string.apk_report_field_unsafe_paths
        "inventory_complete" -> R.string.apk_report_field_inventory_complete
        "package" -> R.string.apk_report_field_package
        "version_name" -> R.string.apk_report_field_version_name
        "version_code" -> R.string.apk_report_field_version_code
        "min_sdk" -> R.string.apk_report_field_min_sdk
        "target_sdk" -> R.string.apk_report_field_target_sdk
        "debuggable" -> R.string.apk_report_field_debuggable
        "permission" -> R.string.apk_report_field_requested_permission
        "hardware_feature" -> R.string.apk_report_field_hardware_feature
        "declared_intent_filter" -> R.string.apk_report_field_declared_intent_filter
        "declared_intent_filter_count" -> R.string.apk_report_field_declared_intent_filter_count
        "intent_filter_truncated" -> R.string.apk_report_field_intent_filter_truncated
        "intent_filter_actions" -> R.string.apk_report_field_intent_filter_actions
        "intent_filter_categories" -> R.string.apk_report_field_intent_filter_categories
        "intent_filter_data" -> R.string.apk_report_field_intent_filter_data
        "intent_filter_paths" -> R.string.apk_report_field_intent_filter_paths
        "intent_filter_scheme" -> R.string.apk_report_field_intent_filter_scheme
        "intent_filter_host" -> R.string.apk_report_field_intent_filter_host
        "intent_filter_port" -> R.string.apk_report_field_intent_filter_port
        "intent_filter_mime_type" -> R.string.apk_report_field_intent_filter_mime_type
        "intent_filter_path" -> R.string.apk_report_field_intent_filter_path
        "available" -> R.string.apk_report_field_readable_xml_available
        "unresolved_references" -> R.string.apk_report_field_unresolved_references
        "truncated" -> R.string.apk_report_field_readable_xml_truncated
        "export_note" -> R.string.apk_report_field_readable_xml_export
        "status" -> R.string.apk_report_field_verification_status
        "schemes" -> R.string.apk_report_field_verified_schemes
        "certificate_sha256" -> R.string.apk_report_field_certificate_sha256
        "certificate_sha1" -> R.string.apk_report_field_certificate_sha1
        "certificate_subject" -> R.string.apk_report_field_certificate_subject
        "certificate_issuer" -> R.string.apk_report_field_certificate_issuer
        "certificate_serial" -> R.string.apk_report_field_certificate_serial
        "diagnostic" -> R.string.apk_report_field_signing_diagnostic
        "dex_count" -> R.string.apk_report_field_dex_files
        "native_count" -> R.string.apk_report_field_native_libraries
        "asset_count" -> R.string.apk_report_field_assets
        "abis" -> R.string.apk_report_field_native_abis
        "sample_path" -> R.string.apk_report_field_sample_package_path
        "finding" -> R.string.apk_report_field_finding
        "explanation" -> R.string.apk_report_field_explanation
        "evidence" -> R.string.apk_report_field_evidence
        "indicator_type" -> R.string.apk_report_field_indicator_type
        "category" -> R.string.apk_report_field_category
        "confidence" -> R.string.apk_report_field_confidence
        "bundle_format" -> R.string.bundle_export_field_format
        "bundle_apk_count" -> R.string.bundle_export_field_apk_count
        "bundle_apk_bytes" -> R.string.bundle_export_field_apk_bytes
        "bundle_expanded_bytes" -> R.string.bundle_export_field_expanded_bytes
        "bundle_complete" -> R.string.bundle_export_field_complete
        "bundle_identity_status" -> R.string.bundle_export_field_identity_status
        "bundle_metadata_trusted" -> R.string.bundle_export_field_metadata_trusted
        "bundle_metadata_package" -> R.string.bundle_export_field_metadata_package
        "bundle_metadata_version_code" -> R.string.bundle_export_field_metadata_version_code
        "bundle_metadata_version_name" -> R.string.bundle_export_field_metadata_version_name
        "bundle_entry" -> R.string.bundle_export_field_entry
        "bundle_role" -> R.string.bundle_export_field_role
        "bundle_entry_bytes" -> R.string.bundle_export_field_entry_bytes
        "bundle_entry_expanded" -> R.string.bundle_export_field_entry_expanded
        "bundle_entry_sha256" -> R.string.bundle_export_field_entry_sha256
        "bundle_entry_package" -> R.string.bundle_export_field_entry_package
        "bundle_entry_version_code" -> R.string.bundle_export_field_entry_version_code
        "bundle_entry_signing" -> R.string.bundle_export_field_entry_signing
        "bundle_entry_failure" -> R.string.bundle_export_field_entry_failure
        "bundle_obb_count" -> R.string.bundle_export_field_obb_count
        "bundle_obb_entry" -> R.string.bundle_export_field_obb_entry
        "bundle_obb_bytes" -> R.string.bundle_export_field_obb_bytes
        "bundle_limitation" -> R.string.bundle_export_field_limitation
        "bundle_limitation_code" -> R.string.bundle_export_field_limitation_code
        "bundle_aab_module_count" -> R.string.bundle_export_field_aab_module_count
        "bundle_aab_entry_count" -> R.string.bundle_export_field_aab_entry_count
        "bundle_aab_declared_bytes" -> R.string.bundle_export_field_aab_declared_bytes
        "bundle_aab_config" -> R.string.bundle_export_field_aab_config
        "bundle_aab_metadata_paths" -> R.string.bundle_export_field_aab_metadata_paths
        else -> R.string.apk_report_field_evidence_id
    })

    fun findingTitle(code: HeuristicFindingCode): String = context.apkFindingTitle(code)
    fun findingDescription(code: HeuristicFindingCode): String = context.apkFindingDescription(code)
    fun riskExplanation(code: RiskExplanationCode): String = context.apkRiskExplanation(code)
    fun limitation(code: RiskLimitationCode): String = context.apkRiskLimitation(code)
    fun failure(code: InspectionFailureCode): String = context.apkInspectionFailure(code)
    fun signingDiagnostic(code: SigningDiagnosticCode): String = context.apkSigningDiagnostic(code)
    fun evidence(value: ApkTechnicalEvidence): String = context.apkTechnicalEvidence(value)
    fun riskLevel(value: app.apksentinel.inspector.RiskLevel): String = context.apkRiskLevel(value)
    fun signingStatus(value: app.apksentinel.inspector.SignatureVerificationStatus): String = context.apkSigningStatus(value)
    fun severity(value: app.apksentinel.inspector.FindingSeverity): String = context.apkSeverity(value)
    fun confidence(value: app.apksentinel.inspector.FindingConfidence): String = context.apkConfidence(value)
    fun bundleLimitation(value: app.apksentinel.inspector.BundleLimitationCode): String = context.apkBundleLimitation(value)
    fun contextBundleFormat(value: app.apksentinel.inspector.BundleFormat): String = context.apkBundleFormat(value)
    fun contextBundleRole(value: app.apksentinel.inspector.BundleApkRole): String = context.apkBundleRole(value)
    fun contextBundleIdentityStatus(value: app.apksentinel.inspector.BundleIdentityStatus): String = context.apkBundleIdentityStatus(value)

    companion object {
        fun from(context: Context): ApkReportText = ApkReportText(context)
    }
}

internal fun ApkInspectionResult.toLocalReport(
    text: ApkReportText,
    threatIndicators: List<ThreatIndicator> = emptyList(),
    nowMillis: Long = System.currentTimeMillis(),
    redacted: Boolean = false,
): LocalReport {
    val sections = buildList {
        add(ReportSection("summary", text.section("summary"), buildList {
            risk?.let { risk ->
                add(ReportField("risk_score", text.field("risk_score"), risk.score.toString()))
                add(ReportField("risk_level", text.field("risk_level"), text.riskLevel(risk.level)))
                risk.explanations.forEachIndexed { index, explanation ->
                    add(ReportField("risk_explanation_${index}_code", text.field("code"), explanation.code.name, ReportSensitivity.TECHNICAL))
                    add(ReportField("risk_explanation_${index}_title", text.field("explanation"), text.riskExplanation(explanation.code)))
                    explanation.evidence.forEachIndexed { evidenceIndex, evidence ->
                        add(ReportField("risk_explanation_${index}_evidence_$evidenceIndex", text.field("evidence"), text.evidence(evidence), ReportSensitivity.TECHNICAL))
                    }
                }
            }
            add(ReportField("complete", text.field("complete"), isComplete.toString()))
            add(ReportField("stopped_for_safety", text.field("stopped_for_safety"), stoppedForSafety.toString()))
        }))
        bundle?.let { bundle -> add(ReportSection("bundle", text.section("bundle"), buildList {
            add(ReportField("format_code", text.field("code"), bundle.format.name, ReportSensitivity.TECHNICAL))
            add(ReportField("format", text.field("bundle_format"), text.contextBundleFormat(bundle.format)))
            add(ReportField("apk_count", text.field("bundle_apk_count"), bundle.nestedApks.size.toString()))
            add(ReportField("apk_bytes", text.field("bundle_apk_bytes"), bundle.nestedApkBytes.toString(), ReportSensitivity.TECHNICAL))
            add(ReportField("expanded_bytes", text.field("bundle_expanded_bytes"), bundle.nestedExpandedBytes.toString(), ReportSensitivity.TECHNICAL))
            add(ReportField("complete", text.field("bundle_complete"), bundle.isComplete.toString()))
            add(ReportField("identity_status_code", text.field("code"), bundle.identityStatus.name, ReportSensitivity.TECHNICAL))
            add(ReportField("identity_status", text.field("bundle_identity_status"), text.contextBundleIdentityStatus(bundle.identityStatus)))
            bundle.publishingEvidence?.let { aab ->
                add(ReportField("aab_module_count", text.field("bundle_aab_module_count"), aab.modules.size.toString()))
                add(ReportField("aab_entry_count", text.field("bundle_aab_entry_count"), aab.entryCount.toString()))
                add(ReportField("aab_declared_bytes", text.field("bundle_aab_declared_bytes"), aab.declaredBytes.toString(), ReportSensitivity.TECHNICAL))
                add(ReportField("aab_bundle_config", text.field("bundle_aab_config"), aab.bundleConfigPresent.toString()))
                add(ReportField("aab_metadata_paths", text.field("bundle_aab_metadata_paths"), aab.metadataPaths.size.toString()))
                if (!redacted) {
                    aab.modules.take(128).forEachIndexed { index, module ->
                        add(ReportField("aab_module_${index}_name", text.field("bundle_entry"), module.name.safeApkTechnicalDisplay(text.unknown, 512), ReportSensitivity.TECHNICAL))
                        add(ReportField("aab_module_${index}_entry_count", text.field("bundle_aab_entry_count"), module.entryCount.toString()))
                        add(ReportField("aab_module_${index}_bytes", text.field("bundle_aab_declared_bytes"), module.declaredBytes.toString(), ReportSensitivity.TECHNICAL))
                    }
                }
            }
            bundle.metadata?.let { metadata ->
                add(ReportField("metadata_trusted", text.field("bundle_metadata_trusted"), metadata.isTrusted.toString()))
                metadata.packageName?.let { add(ReportField("metadata_package", text.field("bundle_metadata_package"), it.safeApkTechnicalDisplay(text.unknown, 512), ReportSensitivity.TECHNICAL)) }
                metadata.versionCode?.let { add(ReportField("metadata_version_code", text.field("bundle_metadata_version_code"), it.toString(), ReportSensitivity.TECHNICAL)) }
                metadata.versionName?.let { add(ReportField("metadata_version_name", text.field("bundle_metadata_version_name"), it.safeApkTechnicalDisplay(text.unknown, 512), ReportSensitivity.TECHNICAL)) }
            }
            bundle.nestedApks.take(64).forEachIndexed { index, entry ->
                val prefix = "apk_$index"
                add(ReportField("${prefix}_role_code", text.field("code"), entry.role.name, ReportSensitivity.TECHNICAL))
                add(ReportField("${prefix}_role", text.field("bundle_role"), text.contextBundleRole(entry.role)))
                add(ReportField("${prefix}_bytes", text.field("bundle_entry_bytes"), entry.byteCount.toString(), ReportSensitivity.TECHNICAL))
                add(ReportField("${prefix}_expanded", text.field("bundle_entry_expanded"), entry.expandedBytes?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL))
                entry.failures.forEachIndexed { failureIndex, failure ->
                    add(ReportField("${prefix}_failure_${failureIndex}_code", text.field("code"), failure.name, ReportSensitivity.TECHNICAL))
                    add(ReportField("${prefix}_failure_$failureIndex", text.field("bundle_entry_failure"), text.failure(failure)))
                }
                if (!redacted) {
                    add(ReportField("${prefix}_path", text.field("bundle_entry"), entry.path.safeApkTechnicalDisplay(text.unknown, 512), ReportSensitivity.TECHNICAL))
                    entry.sha256?.let { add(ReportField("${prefix}_sha256", text.field("bundle_entry_sha256"), it, ReportSensitivity.TECHNICAL)) }
                    entry.manifest?.let { manifest ->
                        add(ReportField("${prefix}_package", text.field("bundle_entry_package"), manifest.packageName, ReportSensitivity.TECHNICAL))
                        add(ReportField("${prefix}_version_code", text.field("bundle_entry_version_code"), manifest.versionCode?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL))
                    }
                    entry.signing?.let { signing ->
                        add(ReportField("${prefix}_signing", text.field("bundle_entry_signing"), text.signingStatus(signing.status)))
                    }
                }
            }
            add(ReportField("obb_count", text.field("bundle_obb_count"), bundle.obbFiles.size.toString()))
            add(ReportField("obb_bytes", text.field("bundle_obb_bytes"), bundle.obbFiles.mapNotNull { it.byteCount }.sum().toString(), ReportSensitivity.TECHNICAL))
            if (!redacted) {
                bundle.obbFiles.take(32).forEachIndexed { index, entry ->
                    add(ReportField("obb_$index", text.field("bundle_obb_entry"), "${entry.path.safeApkTechnicalDisplay(text.unknown, 512)}; bytes=${entry.byteCount ?: text.unknown}", ReportSensitivity.TECHNICAL))
                }
            }
            bundle.limitations.take(32).forEachIndexed { index, limitation ->
                add(ReportField("limitation_${index}_code", text.field("bundle_limitation_code"), limitation.name, ReportSensitivity.TECHNICAL))
                add(ReportField("limitation_$index", text.field("bundle_limitation"), text.bundleLimitation(limitation)))
            }
        })) }
        source?.let { source -> add(ReportSection("artifact", text.section("artifact"), listOf(
            ReportField("bytes", text.field("bytes"), source.byteCount.toString(), ReportSensitivity.TECHNICAL),
            ReportField("sha256", text.field("sha256"), source.sha256, ReportSensitivity.TECHNICAL),
        ))) }
        archive?.let { archive -> add(ReportSection("archive", text.section("archive"), listOf(
            ReportField("entry_count", text.field("entry_count"), archive.entryCount.toString(), ReportSensitivity.TECHNICAL),
            ReportField("declared_compressed_bytes", text.field("declared_compressed_bytes"), archive.declaredCompressedBytes.toString(), ReportSensitivity.TECHNICAL),
            ReportField("declared_uncompressed_bytes", text.field("declared_uncompressed_bytes"), archive.declaredUncompressedBytes.toString(), ReportSensitivity.TECHNICAL),
            ReportField("observed_uncompressed_bytes", text.field("observed_uncompressed_bytes"), archive.observedUncompressedBytes.toString(), ReportSensitivity.TECHNICAL),
            ReportField("maximum_compression_ratio", text.field("maximum_compression_ratio"), archive.maximumObservedCompressionRatio?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL),
            ReportField("unsafe_paths", text.field("unsafe_paths"), archive.pathTraversalEntryCount.toString(), ReportSensitivity.TECHNICAL),
            ReportField("inventory_complete", text.field("inventory_complete"), archive.isComplete.toString()),
        ))) }
        manifest?.let { manifest -> add(ReportSection("manifest", text.section("manifest"), buildList {
            add(ReportField("package", text.field("package"), manifest.packageName, ReportSensitivity.TECHNICAL))
            add(ReportField("version_name", text.field("version_name"), manifest.versionName ?: text.unknown, ReportSensitivity.TECHNICAL))
            add(ReportField("version_code", text.field("version_code"), manifest.versionCode?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL))
            add(ReportField("min_sdk", text.field("min_sdk"), manifest.sdk.minSdk?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL))
            add(ReportField("target_sdk", text.field("target_sdk"), manifest.sdk.targetSdk?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL))
            add(ReportField("debuggable", text.field("debuggable"), manifest.debugBuild?.toString() ?: text.unknown, ReportSensitivity.TECHNICAL))
            manifest.permissions.forEachIndexed { index, permission -> add(ReportField("permission_$index", text.field("permission"), permission, ReportSensitivity.TECHNICAL)) }
            add(ReportField(
                "declared_intent_filter_count",
                text.field("declared_intent_filter_count"),
                manifest.components.sumOf { it.intentFilters.size }.toString(),
            ))
            add(ReportField(
                "intent_filters_truncated",
                text.field("intent_filter_truncated"),
                manifest.intentFiltersTruncated.toString(),
            ))
            manifest.components.forEachIndexed { index, component ->
                add(ReportField("component_$index", component.type.name, "${component.className}; exported=${component.exported}; enabled=${component.enabled}; permission=${component.requiredPermission ?: text.none}", ReportSensitivity.TECHNICAL))
                addAll(component.intentFilterReportFields(index, text::field, redacted))
            }
            manifest.hardwareFeatures.forEachIndexed { index, feature ->
                add(ReportField("hardware_feature_$index", text.field("hardware_feature"), "name=${feature.name ?: "OpenGL ES"}; glEs=${feature.openGlEsVersion ?: text.notApplicable}; required=${feature.required}", ReportSensitivity.TECHNICAL))
            }
        })) }
        decodedManifest?.let { decoded -> add(ReportSection("decoded_manifest", text.section("decoded_manifest"), listOf(
            ReportField("available", text.field("available"), "true"),
            ReportField("unresolved_references", text.field("unresolved_references"), decoded.unresolvedResourceReferenceCount.toString(), ReportSensitivity.TECHNICAL),
            ReportField("truncated", text.field("truncated"), decoded.isTruncated.toString(), ReportSensitivity.TECHNICAL),
            ReportField("export_note", text.field("export_note"), text.readableManifestExportNote),
        ))) }
        signing?.let { signing -> add(ReportSection("signing", text.section("signing"), buildList {
            add(ReportField("status", text.field("status"), text.signingStatus(signing.status)))
            add(ReportField("schemes", text.field("schemes"), signing.verifiedSchemes.joinToString(", "), ReportSensitivity.TECHNICAL))
            signing.certificates.forEachIndexed { index, certificate ->
                add(ReportField("certificate_${index}_sha256", text.field("certificate_sha256"), certificate.sha256, ReportSensitivity.TECHNICAL))
                add(ReportField("certificate_${index}_sha1", text.field("certificate_sha1"), certificate.sha1.ifBlank { text.unavailable }, ReportSensitivity.TECHNICAL))
                add(ReportField("certificate_${index}_subject", text.field("certificate_subject"), certificate.subject, ReportSensitivity.TECHNICAL))
                add(ReportField("certificate_${index}_issuer", text.field("certificate_issuer"), certificate.issuer, ReportSensitivity.TECHNICAL))
                add(ReportField("certificate_${index}_serial", text.field("certificate_serial"), certificate.serialNumber, ReportSensitivity.TECHNICAL))
            }
            signing.diagnostics.forEachIndexed { index, diagnostic ->
                add(ReportField("diagnostic_${index}_code", text.field("code"), diagnostic.name, ReportSensitivity.TECHNICAL))
                add(ReportField("diagnostic_$index", text.field("diagnostic"), text.signingDiagnostic(diagnostic)))
            }
        })) }
        inventory?.let { inventory -> add(ReportSection("inventory", text.section("inventory"), buildList {
            add(ReportField("dex_count", text.field("dex_count"), inventory.dexFiles.count.toString()))
            add(ReportField("native_count", text.field("native_count"), inventory.nativeLibraries.count.toString()))
            add(ReportField("asset_count", text.field("asset_count"), inventory.assets.count.toString()))
            add(ReportField("abis", text.field("abis"), inventory.nativeLibraries.abiCounts.entries.joinToString { "${it.key}:${it.value}" }, ReportSensitivity.TECHNICAL))
            (inventory.dexFiles.samplePaths + inventory.nativeLibraries.samplePaths + inventory.assets.samplePaths).distinct().forEachIndexed { index, path ->
                add(ReportField("sample_path_$index", text.field("sample_path"), path, ReportSensitivity.TECHNICAL))
            }
        })) }
        if (findings.isNotEmpty()) add(ReportSection("findings", text.section("findings"), findings.flatMapIndexed { index, finding -> buildList {
            add(ReportField("finding_${index}_code", text.field("code"), finding.code.name, ReportSensitivity.TECHNICAL))
            add(ReportField("finding_${index}_title", text.field("finding"), "${text.severity(finding.severity)}: ${text.findingTitle(finding.code)}"))
            add(ReportField("finding_${index}_explanation", text.field("explanation"), text.findingDescription(finding.code)))
            add(ReportField("finding_${index}_confidence", text.field("confidence"), text.confidence(finding.confidence)))
            finding.evidence.forEachIndexed { evidenceIndex, evidence ->
                add(ReportField("finding_${index}_evidence_$evidenceIndex", text.field("evidence"), text.evidence(evidence), ReportSensitivity.TECHNICAL))
            }
        } }))
        if (threatIndicators.isNotEmpty()) add(ReportSection("signed_threat_matches", text.section("signed_threat_matches"), threatIndicators.flatMapIndexed { index, indicator -> listOf(
            ReportField("threat_${index}_type", text.field("indicator_type"), indicator.type.name),
            ReportField("threat_${index}_category", text.field("category"), indicator.category),
            ReportField("threat_${index}_confidence", text.field("confidence"), indicator.confidence.name),
            ReportField("threat_${index}_evidence", text.field("evidence_id"), indicator.evidenceId, ReportSensitivity.TECHNICAL),
        ) }))
    }
    return LocalReport(
        reportType = "apk-inspection",
        generatedAtMillis = nowMillis,
        sections = sections,
        limitations = (
            risk?.limitations.orEmpty().map { text.limitation(it.code) } +
                bundle?.limitations.orEmpty().map { text.bundleLimitation(it) } +
                failures.map { text.failure(it.code) }
            ).distinct(),
    )
}

/**
 * Stable, bounded manifest intent-filter schema. Raw declarations stay technical; redacted
 * reports retain only counts and truncation state so their shape is useful without revealing
 * routing values.
 */
internal fun ManifestComponent.intentFilterReportFields(
    componentIndex: Int,
    label: (String) -> String,
    redacted: Boolean,
): List<ReportField> = buildList {
    val prefix = "component_${componentIndex}_intent_filter"
    add(ReportField("${prefix}_count", label("declared_intent_filter_count"), intentFilters.size.toString()))
    add(ReportField("${prefix}s_truncated", label("intent_filter_truncated"), intentFiltersTruncated.toString()))
    intentFilters.forEachIndexed { filterIndex, filter ->
        val filterPrefix = "${prefix}_$filterIndex"
        add(ReportField("${filterPrefix}_action_count", label("intent_filter_actions"), filter.actions.size.toString()))
        add(ReportField("${filterPrefix}_actions_truncated", label("intent_filter_truncated"), filter.actionsTruncated.toString()))
        add(ReportField("${filterPrefix}_category_count", label("intent_filter_categories"), filter.categories.size.toString()))
        add(ReportField("${filterPrefix}_categories_truncated", label("intent_filter_truncated"), filter.categoriesTruncated.toString()))
        add(ReportField("${filterPrefix}_data_count", label("intent_filter_data"), filter.data.size.toString()))
        add(ReportField("${filterPrefix}_data_truncated", label("intent_filter_truncated"), filter.dataTruncated.toString()))
        if (!redacted) {
            add(ReportField("${filterPrefix}_code", label("declared_intent_filter"), "DECLARED_INTENT_FILTER", ReportSensitivity.TECHNICAL))
            filter.actions.forEachIndexed { actionIndex, action ->
                add(ReportField("${filterPrefix}_action_$actionIndex", label("intent_filter_actions"), action, ReportSensitivity.TECHNICAL))
            }
            filter.categories.forEachIndexed { categoryIndex, category ->
                add(ReportField("${filterPrefix}_category_$categoryIndex", label("intent_filter_categories"), category, ReportSensitivity.TECHNICAL))
            }
        }
        filter.data.forEachIndexed { dataIndex, data ->
            val dataPrefix = "${filterPrefix}_data_$dataIndex"
            add(ReportField("${dataPrefix}_path_count", label("intent_filter_paths"), data.paths.size.toString()))
            add(ReportField("${dataPrefix}_paths_truncated", label("intent_filter_truncated"), data.pathsTruncated.toString()))
            add(ReportField("${dataPrefix}_values_truncated", label("intent_filter_truncated"), data.valuesTruncated.toString()))
            if (!redacted) {
                add(ReportField("${dataPrefix}_code", label("intent_filter_data"), "DECLARED_INTENT_FILTER_DATA", ReportSensitivity.TECHNICAL))
                data.scheme?.let { add(ReportField("${dataPrefix}_scheme", label("intent_filter_scheme"), it, ReportSensitivity.TECHNICAL)) }
                data.host?.let { add(ReportField("${dataPrefix}_host", label("intent_filter_host"), it, ReportSensitivity.TECHNICAL)) }
                data.port?.let { add(ReportField("${dataPrefix}_port", label("intent_filter_port"), it, ReportSensitivity.TECHNICAL)) }
                data.mimeType?.let { add(ReportField("${dataPrefix}_mime_type", label("intent_filter_mime_type"), it, ReportSensitivity.TECHNICAL)) }
                data.paths.forEachIndexed { pathIndex, path ->
                    add(ReportField("${dataPrefix}_path_${pathIndex}_kind_code", label("code"), path.kind.name, ReportSensitivity.TECHNICAL))
                    add(ReportField("${dataPrefix}_path_$pathIndex", label("intent_filter_path"), path.value, ReportSensitivity.TECHNICAL))
                }
            }
        }
    }
}
