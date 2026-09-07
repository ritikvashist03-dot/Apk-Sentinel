package app.apksentinel.mobile

import app.apksentinel.core.model.Confidence
import app.apksentinel.core.model.Evidence
import app.apksentinel.core.model.EvidenceId
import app.apksentinel.core.model.EvidenceSource
import app.apksentinel.core.model.FindingSubject
import app.apksentinel.core.model.FindingsRepository
import app.apksentinel.core.model.SubjectFindings
import app.apksentinel.feature.apps.InstalledAppRecord
import app.apksentinel.networkmonitor.AppAttribution
import app.apksentinel.networkmonitor.AttributionConfidence
import app.apksentinel.networkmonitor.NetworkEvent
import app.apksentinel.networkmonitor.PacketObservedEvent

/**
 * Joins what the app inspector knows about a package with what the network monitor saw
 * that package do.
 *
 * Before this, each engine kept its own results and nothing related them: the installed-app
 * view could not say whether an app had contacted anything, and the connection log could
 * not say whose traffic it was showing. The domain model for the join already existed in
 * core:model and was referenced only by its own tests.
 *
 * The repository is process-scoped and in-memory. Correlating observations while the user
 * is looking at them is useful; keeping a per-app dossier across sessions would be a
 * different product with a different privacy story.
 */
internal object FindingsComposition {
    private val repository = FindingsRepository()

    fun repository(): FindingsRepository = repository

    /** Records that a package was observed on the network during this session. */
    fun recordNetworkObservations(events: List<NetworkEvent>, atMillis: Long) {
        events.asSequence()
            .filterIsInstance<PacketObservedEvent>()
            .mapNotNull { (it.attribution as? AppAttribution.Known)?.packageName }
            .distinct()
            .forEach { packageName ->
                val id = evidenceId("net", packageName) ?: return@forEach
                repository.submit(
                    FindingSubject(packageName),
                    listOf(
                        Evidence(
                            id = id,
                            source = EvidenceSource.NETWORK_VPN_OBSERVATION,
                            observedAtEpochMillis = atMillis,
                            observation = "This app was seen sending or receiving traffic while monitoring was on.",
                            context = "Observed on the local VPN during the current session only.",
                            confidence = networkConfidence(events, packageName),
                            limitations = listOf(
                                "Traffic attribution can be incomplete, and apps sharing a UID cannot always be told apart.",
                            ),
                        ),
                    ),
                )
            }
    }

    /** Records the installed-artifact side of the join. */
    fun recordInstalledApps(apps: List<InstalledAppRecord>, atMillis: Long) {
        apps.forEach { app ->
            val id = evidenceId("pkg", app.packageName) ?: return@forEach
            repository.submit(
                FindingSubject(app.packageName),
                listOf(
                    Evidence(
                        id = id,
                        source = EvidenceSource.DEVICE_API,
                        observedAtEpochMillis = atMillis,
                        observation = "Installed on this device with ${app.requestedPermissionCount} requested and " +
                            "${app.grantedPermissionCount} granted permissions.",
                        context = "Read from Android's package manager on this device.",
                        confidence = Confidence(
                            score = 80,
                            rationale = "Reported directly by the platform for an installed package.",
                        ),
                    ),
                ),
            )
        }
    }

    /** Packages backed by BOTH an installed-artifact reading and a network observation. */
    fun crossSourceSubjects(): List<SubjectFindings> = repository.crossSourceSubjects()

    fun clear() = repository.clear()

    /**
     * Confidence follows the strongest attribution actually reported for this package.
     * Attribution is a platform best effort, so it is never presented as certain.
     */
    private fun networkConfidence(events: List<NetworkEvent>, packageName: String): Confidence {
        val strongest = events.asSequence()
            .filterIsInstance<PacketObservedEvent>()
            .mapNotNull { it.attribution as? AppAttribution.Known }
            .filter { it.packageName == packageName }
            .map { it.confidence }
            // AttributionConfidence is declared HIGH, MEDIUM, LOW, UNKNOWN, so the
            // strongest value is the LOWEST ordinal. maxByOrNull would select UNKNOWN.
            .minByOrNull { it.ordinal }
        return when (strongest) {
            AttributionConfidence.HIGH -> Confidence(70, "Android reported a connection owner for this traffic.")
            AttributionConfidence.MEDIUM -> Confidence(50, "Attribution was reported but cannot be independently confirmed.")
            else -> Confidence(30, "Attribution is weak or partially unavailable for this traffic.")
        }
    }

    /**
     * EvidenceId only accepts 2..128 characters starting alphanumeric, so a long package
     * name is truncated rather than allowed to throw inside a UI refresh.
     */
    private fun evidenceId(prefix: String, packageName: String): EvidenceId? {
        val sanitized = packageName.filter { it.isLetterOrDigit() || it == '.' || it == '_' || it == '-' }
        if (sanitized.isEmpty() || !sanitized.first().isLetterOrDigit()) return null
        return runCatching { EvidenceId("$prefix.$sanitized".take(128)) }.getOrNull()
    }
}
