package app.apksentinel.networkmonitor

/**
 * Turns consented protocol evidence into the observations [SafeHarExporter] needs.
 *
 * HAR export was previously unreachable — the exporter was fully written and unit-tested,
 * but nothing could call it, because [HttpPayloadObservation] requires a URL and no URL
 * existed anywhere in this system. Now that
 * [ProtocolEvidenceConfiguration.captureRequestTargets] can retain the request target and
 * Host, an entry can be built.
 *
 * What this produces is deliberately a METADATA HAR: request line and URL only. Headers
 * and bodies are not included, because protocol evidence still never retains them. That is
 * a real limitation and callers must state it rather than implying a full capture — a HAR
 * with no headers is useful for seeing what was requested, not for replaying it.
 */
object ProtocolEvidenceHarBridge {

    /** The limitation every export produced from this source carries. */
    const val METADATA_ONLY_NOTE = "Headers and bodies are not captured; entries contain the request line and URL only."

    /**
     * Maps observations to HAR-ready entries, newest last.
     *
     * Only cleartext HTTP requests that actually reconstructed a URL become entries.
     * Responses are skipped: protocol evidence carries no flow identity in its public
     * model, so a response cannot be honestly paired with the request it answered, and
     * inventing a pairing would misattribute a status code to the wrong URL.
     */
    fun toPayloadObservations(
        observations: List<ProtocolEvidenceObservation>,
        maximumEntries: Int = DEFAULT_MAXIMUM_ENTRIES,
    ): List<HttpPayloadObservation> {
        if (maximumEntries <= 0) return emptyList()
        return observations.asSequence()
            .filter { it.source == ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST }
            .mapNotNull { observation ->
                val request = observation.value as? ProtocolEvidenceValue.HttpRequest ?: return@mapNotNull null
                val url = request.absoluteUrl ?: return@mapNotNull null
                runCatching {
                    HttpPayloadObservation(
                        url = url,
                        method = request.method,
                        startedAtMillis = observation.observedAtMillis,
                        // Never "complete": no body was captured, and saying otherwise
                        // would let a reader assume an empty body was observed.
                        complete = false,
                    )
                }.getOrNull()
            }
            .take(maximumEntries)
            .toList()
    }

    /** True when at least one entry could be built, so a UI can offer export honestly. */
    fun canExport(observations: List<ProtocolEvidenceObservation>): Boolean =
        observations.any {
            it.source == ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST &&
                (it.value as? ProtocolEvidenceValue.HttpRequest)?.absoluteUrl != null
        }

    private const val DEFAULT_MAXIMUM_ENTRIES = 512
}
