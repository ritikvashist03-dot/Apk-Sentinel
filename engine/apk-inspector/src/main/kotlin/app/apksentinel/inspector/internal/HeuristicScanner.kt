package app.apksentinel.inspector.internal

import app.apksentinel.inspector.ApkTechnicalEvidence
import app.apksentinel.inspector.FindingConfidence
import app.apksentinel.inspector.FindingSeverity
import app.apksentinel.inspector.HeuristicFinding
import app.apksentinel.inspector.HeuristicFindingCode
import app.apksentinel.inspector.TrackerNamespaceCode
import java.net.URI
import java.nio.charset.StandardCharsets

/**
 * Literal-only heuristics. A finding records a bundled namespace or URL string;
 * it deliberately does not claim that code executes or traffic is sent.
 */
internal class HeuristicScanner {
    fun findByEntryName(entryName: String): List<HeuristicFinding> =
        TrackerCatalog.signatures.mapNotNull { signature ->
            signature.markers.firstOrNull { marker ->
                entryName.contains(marker, ignoreCase = true)
            }?.let { marker ->
                trackerFinding(signature, entryName, marker)
            }
        }

    fun scanEntryContent(
        entryName: String,
        content: ByteArray,
        findingConsumer: (key: String, finding: HeuristicFinding) -> Unit,
    ) {
        if (content.isEmpty()) {
            return
        }
        val text = content.toString(StandardCharsets.ISO_8859_1)

        TrackerCatalog.signatures.forEach { signature ->
            val marker = signature.markers.firstOrNull { candidate ->
                text.contains(candidate, ignoreCase = true)
            }
            if (marker != null) {
                findingConsumer(
                    "tracker:" + signature.findingCode.name,
                    trackerFinding(signature, entryName, marker),
                )
            }
        }

        var emittedEndpoints = 0
        ENDPOINT_REGEX.findAll(text).forEach { match ->
            if (emittedEndpoints >= MAX_ENDPOINTS_PER_ENTRY) {
                return@forEach
            }
            val endpoint = canonicalEndpoint(match.value) ?: return@forEach
            emittedEndpoints += 1
            findingConsumer(
                "endpoint:" + endpoint.lowercase(),
                HeuristicFinding(
                    code = HeuristicFindingCode.EMBEDDED_HTTP_ENDPOINT,
                    severity = FindingSeverity.INFO,
                    confidence = if (entryName.endsWith(".dex")) {
                        FindingConfidence.LOW
                    } else {
                        FindingConfidence.MEDIUM
                    },
                    evidence = listOf(
                        ApkTechnicalEvidence.ArchiveEntryPath(entryName.take(MAX_EVIDENCE_LENGTH)),
                        ApkTechnicalEvidence.EndpointLiteral(endpoint),
                    ),
                ),
            )
        }
    }

    private fun trackerFinding(
        signature: TrackerSignature,
        entryName: String,
        marker: String,
    ): HeuristicFinding = HeuristicFinding(
        code = signature.findingCode,
        severity = FindingSeverity.LOW,
        confidence = FindingConfidence.HIGH,
        evidence = listOf(
            ApkTechnicalEvidence.ArchiveEntryPath(entryName.take(MAX_EVIDENCE_LENGTH)),
            ApkTechnicalEvidence.TrackerNamespaceMatch(signature.namespaceCode, marker),
        ),
    )
}

private fun canonicalEndpoint(raw: String): String? {
    val candidate = raw.trimEnd('.', ',', ';', ':', ')', ']', '}', '\'')
    if (candidate.isBlank() || candidate.length > MAX_ENDPOINT_LENGTH) {
        return null
    }
    val uri = runCatching { URI(candidate) }.getOrNull() ?: return null
    if (uri.scheme !in setOf("http", "https") || uri.host.isNullOrBlank()) {
        return null
    }
    return candidate
}

private data class TrackerSignature(
    val findingCode: HeuristicFindingCode,
    val namespaceCode: TrackerNamespaceCode,
    val markers: List<String>,
)

private object TrackerCatalog {
    val signatures = listOf(
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_FIREBASE_ANALYTICS,
            namespaceCode = TrackerNamespaceCode.FIREBASE_ANALYTICS,
            markers = listOf(
                "com/google/firebase/analytics",
                "Lcom/google/firebase/analytics",
            ),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_GOOGLE_MEASUREMENT,
            namespaceCode = TrackerNamespaceCode.GOOGLE_MEASUREMENT,
            markers = listOf(
                "com/google/android/gms/measurement",
                "Lcom/google/android/gms/measurement",
            ),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_FACEBOOK,
            namespaceCode = TrackerNamespaceCode.FACEBOOK,
            markers = listOf("com/facebook/", "Lcom/facebook/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_APPSFLYER,
            namespaceCode = TrackerNamespaceCode.APPSFLYER,
            markers = listOf("com/appsflyer/", "Lcom/appsflyer/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_ADJUST,
            namespaceCode = TrackerNamespaceCode.ADJUST,
            markers = listOf("com/adjust/", "Lcom/adjust/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_MIXPANEL,
            namespaceCode = TrackerNamespaceCode.MIXPANEL,
            markers = listOf("com/mixpanel/", "Lcom/mixpanel/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_AMPLITUDE,
            namespaceCode = TrackerNamespaceCode.AMPLITUDE,
            markers = listOf("com/amplitude/", "Lcom/amplitude/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.TRACKER_SENTRY,
            namespaceCode = TrackerNamespaceCode.SENTRY,
            markers = listOf("io/sentry/", "Lio/sentry/"),
        ),
        // Advertising networks. These are the namespaces an ad-supported build actually
        // ships; without them a file-analysed APK reported analytics SDKs only.
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_GOOGLE_MOBILE_ADS,
            namespaceCode = TrackerNamespaceCode.GOOGLE_MOBILE_ADS,
            markers = listOf("com/google/android/gms/ads/", "Lcom/google/android/gms/ads/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_UNITY_ADS,
            namespaceCode = TrackerNamespaceCode.UNITY_ADS,
            markers = listOf("com/unity3d/ads/", "Lcom/unity3d/ads/", "com/unity3d/services/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_APPLOVIN,
            namespaceCode = TrackerNamespaceCode.APPLOVIN,
            markers = listOf("com/applovin/", "Lcom/applovin/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_IRONSOURCE,
            namespaceCode = TrackerNamespaceCode.IRONSOURCE,
            markers = listOf("com/ironsource/", "Lcom/ironsource/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_VUNGLE,
            namespaceCode = TrackerNamespaceCode.VUNGLE,
            markers = listOf("com/vungle/", "Lcom/vungle/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_CHARTBOOST,
            namespaceCode = TrackerNamespaceCode.CHARTBOOST,
            markers = listOf("com/chartboost/", "Lcom/chartboost/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_INMOBI,
            namespaceCode = TrackerNamespaceCode.INMOBI,
            markers = listOf("com/inmobi/", "Lcom/inmobi/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_PANGLE,
            namespaceCode = TrackerNamespaceCode.PANGLE,
            markers = listOf("com/bytedance/sdk/openadsdk/", "Lcom/bytedance/sdk/openadsdk/"),
        ),
        TrackerSignature(
            findingCode = HeuristicFindingCode.AD_NETWORK_MINTEGRAL,
            namespaceCode = TrackerNamespaceCode.MINTEGRAL,
            markers = listOf("com/mbridge/msdk/", "Lcom/mbridge/msdk/"),
        ),
    )
}

private const val MAX_ENDPOINTS_PER_ENTRY = 20
private const val MAX_ENDPOINT_LENGTH = 512
private const val MAX_EVIDENCE_LENGTH = 512
private val ENDPOINT_REGEX = Regex(
    """https?://[^\s"'<>\\]+""",
    RegexOption.IGNORE_CASE,
)
