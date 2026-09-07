package app.apksentinel.mobile

import app.apksentinel.networkmonitor.MonitorLifecycleState

internal enum class HomeEvidenceState { NOT_CHECKED, LOCAL_EVIDENCE, REVIEW }

internal data class HomeEvidenceItem(
    val key: String,
    val state: HomeEvidenceState,
    val nextActionKey: String,
)

internal data class HomeEvidenceSummary(
    val items: List<HomeEvidenceItem>,
    val nextActionKey: String,
)

/**
 * Small, deterministic home aggregation boundary. It keeps product copy out
 * of feature engines and makes unknown/untested surfaces explicit.
 */
internal object HomeEvidenceAggregator {
    fun from(
        networkState: MonitorLifecycleState,
        installedAppsVisible: Int? = null,
        hasAnalysis: Boolean = false,
    ): HomeEvidenceSummary {
        val network = when (networkState) {
            MonitorLifecycleState.ACTIVE -> HomeEvidenceState.LOCAL_EVIDENCE
            MonitorLifecycleState.STARTING, MonitorLifecycleState.STOPPING -> HomeEvidenceState.REVIEW
            else -> HomeEvidenceState.NOT_CHECKED
        }
        val apps = when {
            installedAppsVisible == null -> HomeEvidenceState.NOT_CHECKED
            installedAppsVisible >= 0 -> HomeEvidenceState.LOCAL_EVIDENCE
            else -> HomeEvidenceState.REVIEW
        }
        val analyze = if (hasAnalysis) HomeEvidenceState.LOCAL_EVIDENCE else HomeEvidenceState.NOT_CHECKED
        val items = listOf(
            HomeEvidenceItem("device", HomeEvidenceState.NOT_CHECKED, "device"),
            HomeEvidenceItem("apps", apps, if (apps == HomeEvidenceState.NOT_CHECKED) "apps" else "none"),
            HomeEvidenceItem("analyze", analyze, if (analyze == HomeEvidenceState.NOT_CHECKED) "analyze" else "none"),
            HomeEvidenceItem("network", network, if (network == HomeEvidenceState.NOT_CHECKED) "network" else "none"),
        )
        val next = items.firstOrNull { it.nextActionKey != "none" }?.nextActionKey ?: "none"
        return HomeEvidenceSummary(items, next)
    }
}
