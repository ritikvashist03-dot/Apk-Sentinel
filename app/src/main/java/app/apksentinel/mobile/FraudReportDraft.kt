package app.apksentinel.mobile

import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.engine.url.UrlFindingMessage
import app.apksentinel.engine.url.UrlInspection
import java.net.URI

/** The only recipient APK Sentinel can hand off to: the user-selected official portal. */
internal data object OfficialFraudPortal {
    const val name = "India National Cyber Crime Reporting Portal"
    const val host = "cybercrime.gov.in"
    const val url = "https://cybercrime.gov.in/webform/cyber_suspect.aspx"
}

internal enum class FraudReportFieldKind { URL, HOST, FINDINGS, LIMITATION }

internal data class FraudReportField(
    val kind: FraudReportFieldKind,
    val preview: String,
    val redacted: Boolean,
)

internal data class FraudReportDraft(
    val recipient: String,
    val recipientHost: String,
    val fields: List<FraudReportField>,
    val instructions: String,
) {
    val containsRedactedPrivateData: Boolean = fields.any { it.redacted }
}

internal enum class FraudPortalHandoffOutcome { OPENED, CANCELLED, UNAVAILABLE }

/**
 * Creates a bounded, user-reviewable draft without storing or uploading the
 * original link. The portal form remains the user's responsibility.
 */
internal object FraudReportDraftBuilder {
    private const val MAX_PREVIEW_CODE_POINTS = 240

    fun build(inspection: UrlInspection): FraudReportDraft? {
        val normalized = inspection.normalizedUrl ?: return null
        if (inspection.findings.isEmpty() && inspection.verdict == app.apksentinel.engine.url.UrlVerdict.NO_KNOWN_WARNING) return null
        val redaction = redactUrl(normalized)
        val host = inspection.displayHost?.let { SafeTextNormalizer.normalizeDisplayText(it, "unknown host", 120) }
            ?: "unknown host"
        val findings = inspection.findings
            .map { finding -> finding.message.name }
            .joinToString(", ")
            .ifBlank { "No typed local finding" }
            .bounded()
        return FraudReportDraft(
            recipient = OfficialFraudPortal.name,
            recipientHost = OfficialFraudPortal.host,
            fields = listOf(
                FraudReportField(FraudReportFieldKind.URL, redaction.preview, redaction.redacted),
                FraudReportField(FraudReportFieldKind.HOST, host, redacted = false),
                FraudReportField(FraudReportFieldKind.FINDINGS, findings, redacted = false),
                FraudReportField(
                    FraudReportFieldKind.LIMITATION,
                    "APK Sentinel local-only evidence; no reputation verdict or portal submission",
                    redacted = false,
                ),
            ),
            instructions = "Review the portal recipient and enter any original evidence yourself. APK Sentinel does not submit this draft.",
        )
    }

    private data class RedactedUrl(val preview: String, val redacted: Boolean)

    private fun redactUrl(value: String): RedactedUrl {
        val uri = runCatching { URI(value) }.getOrNull()
        if (uri == null || uri.host.isNullOrBlank()) return RedactedUrl("[URL redacted; enter it in the official portal]", true)
        val scheme = uri.scheme?.lowercase()?.takeIf { it == "http" || it == "https" } ?: "https"
        val host = requireNotNull(uri.host).safeHost()
        val port = uri.port.takeIf { it in 1..65_535 }?.let { ":$it" }.orEmpty()
        val hasPrivateParts = !uri.userInfo.isNullOrBlank() || !uri.rawQuery.isNullOrBlank() || !uri.rawFragment.isNullOrBlank()
        val path = uri.rawPath.takeIf { !it.isNullOrBlank() && it != "/" }
            ?.let { "/[path redacted]" }
            .orEmpty()
        val preview = "$scheme://$host$port$path".bounded()
        return RedactedUrl(preview = preview, redacted = hasPrivateParts || path.isNotEmpty())
    }

    private fun String.safeHost(): String = SafeTextNormalizer.normalizeDisplayText(this, "unknown host", 120)

    private fun String.bounded(): String = SafeTextNormalizer.normalizeDisplayText(this, "[unavailable]", MAX_PREVIEW_CODE_POINTS)
}

internal fun fraudHandoffOutcome(
    portalConfirmed: Boolean,
    openPortal: () -> Boolean,
): FraudPortalHandoffOutcome {
    if (!portalConfirmed) return FraudPortalHandoffOutcome.CANCELLED
    return if (runCatching { openPortal() }.getOrDefault(false)) {
        FraudPortalHandoffOutcome.OPENED
    } else {
        FraudPortalHandoffOutcome.UNAVAILABLE
    }
}
