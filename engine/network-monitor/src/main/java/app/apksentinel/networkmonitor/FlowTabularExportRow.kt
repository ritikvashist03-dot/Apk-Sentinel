package app.apksentinel.networkmonitor

/**
 * Column definitions shared by [SafeFlowCsvExporter] and [SafeFlowXlsxExporter].
 *
 * Both exporters must show the same field for the same column, or a user
 * comparing the CSV and the xlsx of the same session would see two different
 * "truths". Keeping one row builder is also how this repo avoids the drift
 * documented for its several independent domain/package validators: two
 * writers that each reimplement "what a flow row looks like" are exactly the
 * kind of duplicated logic that goes stale in only one place.
 *
 * Unlike [SafeFlowMetadataExporter] (a redacted technical preview meant to be
 * safe to attach anywhere), this export is the full local record of what the
 * device already observed, written only to a document the user explicitly
 * picked with the SAF document picker. It is allowed to include the
 * attributed app and the remote address/port because nothing here leaves the
 * device except by the user's own later action.
 */
internal object FlowTabularExportRow {
    /** Every column here is a real [NetworkFlow] (or nested [NetworkFlowKey]) field. None are invented. */
    val HEADER: List<String> = listOf(
        "flow_id",
        "started_at_millis",
        "last_seen_at_millis",
        "direction",
        "ip_version",
        "protocol",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "app_package",
        "app_uid",
        "attribution",
        "attribution_detail",
        "packet_count",
        "bytes",
        "dns_name",
        "dns_name_status",
    )

    fun cellsFor(flow: NetworkFlow): List<String> {
        val attribution = flow.attribution
        val (attributionState, attributionDetail, appPackage, appUid) = when (attribution) {
            is AppAttribution.Known -> AttributionCells(
                "KNOWN",
                attribution.confidence.name,
                attribution.packageName,
                attribution.uid?.toString() ?: "",
            )
            is AppAttribution.Unknown -> AttributionCells("UNKNOWN", attribution.reason.name, "", "")
        }
        return listOf(
            flow.id,
            flow.startedAtMillis.toString(),
            flow.lastSeenAtMillis.toString(),
            flow.direction.name,
            flow.key.ipVersion.name,
            flow.key.protocol.name,
            flow.key.source.address,
            flow.key.source.port?.toString() ?: "",
            flow.key.destination.address,
            flow.key.destination.port?.toString() ?: "",
            appPackage,
            appUid,
            attributionState,
            attributionDetail,
            flow.packetCount.toString(),
            flow.observedBytes.toString(),
            dnsNameCell(flow.latestDnsName),
            dnsNameStatusCell(flow.latestDnsName),
        )
    }

    fun containsPlaintextDnsName(flow: NetworkFlow): Boolean =
        flow.latestDnsName is SafeDnsName.PlaintextAfterExplicitConsent

    private data class AttributionCells(
        val state: String,
        val detail: String,
        val appPackage: String,
        val appUid: String,
    )

    /**
     * The hashed prefix is designed to be shown: it is a per-session salted digest that
     * cannot be reversed to the original name, so surfacing it here still lets a user
     * group rows by destination without this export leaking a plaintext hostname the
     * session never consented to reveal.
     */
    private fun dnsNameCell(name: SafeDnsName?): String = when (name) {
        null, SafeDnsName.NotCaptured -> ""
        is SafeDnsName.Hashed -> name.sha256Prefix
        is SafeDnsName.PlaintextAfterExplicitConsent -> name.normalizedName
    }

    private fun dnsNameStatusCell(name: SafeDnsName?): String = when (name) {
        null, SafeDnsName.NotCaptured -> "NOT_CAPTURED"
        is SafeDnsName.Hashed -> "HASHED_PER_SESSION"
        is SafeDnsName.PlaintextAfterExplicitConsent -> "PLAINTEXT_EXPLICIT_CONSENT"
    }
}
