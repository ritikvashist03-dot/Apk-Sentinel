package app.apksentinel.feature.device

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelExpandableSection
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.SentinelResponsiveColumn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal object DevicePostureLayoutContract {
    const val READING_MAX_WIDTH_DP = 720
    const val VERTICAL_SCROLL_OWNER_COUNT = 1
}

@Composable
fun DevicePostureScreen(
    modifier: Modifier = Modifier,
    onUserCheckCompleted: (DevicePostureSnapshot) -> Unit = {},
) {
    val context = LocalContext.current
    val repository = remember(context) { DevicePostureRepository(context.applicationContext) }
    val historyController = remember(context) { DevicePostureHistoryController.android(context.applicationContext) }
    var snapshot by remember { mutableStateOf(repository.snapshot()) }
    var historyResult by remember { mutableStateOf<PostureHistoryResult?>(null) }
    var actionFeedback by remember { mutableStateOf<Int?>(null) }
    var leftForSettings by remember { mutableStateOf(false) }
    var showCompleted by rememberSaveable { mutableStateOf(false) }
    var refreshRequested by rememberSaveable { mutableStateOf(false) }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        snapshot = repository.snapshot()
        if (leftForSettings) {
            onUserCheckCompleted(snapshot)
            actionFeedback = R.string.settings_returned_refreshed
            leftForSettings = false
        }
    }
    LaunchedEffect(snapshot.generatedAtMillis) {
        historyResult = withContext(Dispatchers.IO) { historyController.compareAndRecord(snapshot) }
    }

    SentinelResponsiveColumn(
        modifier = modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        readingMaxWidth = DevicePostureLayoutContract.READING_MAX_WIDTH_DP.dp,
        contentPadding = PaddingValues(horizontal = 18.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // The result leads. A refresh button above the answer asks the reader to act before
        // they know what they are acting on.
        CheckupSummary(snapshot, refreshRequested)
        actionFeedback?.let { feedback ->
            SentinelCard(Modifier.semantics { liveRegion = LiveRegionMode.Polite }) {
                Text(stringResource(feedback), style = MaterialTheme.typography.bodyMedium)
            }
        }

        val reviewChecks = snapshot.checks.filter { it.state != CheckState.PASS }
        val completedChecks = snapshot.checks.filter { it.state == CheckState.PASS }
        if (reviewChecks.isNotEmpty()) {
            Text(
                stringResource(R.string.next_steps_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
        }
        reviewChecks.forEach { check ->
            PostureCheckCard(
                check = check,
                actionAvailable = check.action?.let(repository::isActionAvailable) ?: false,
                onAction = { action ->
                    val launched = runCatching { context.startActivity(repository.intentFor(action)) }.isSuccess
                    actionFeedback = if (launched) R.string.settings_opened_recheck_on_return else R.string.settings_open_failed
                    leftForSettings = launched
                },
                onRetry = { snapshot = repository.snapshot(); actionFeedback = R.string.refresh_complete },
            )
        }
        // These two sections sit back to back in the same list; flat keeps them a single
        // divider-separated list instead of two stacked filled cards.
        if (completedChecks.isNotEmpty()) {
            SentinelExpandableSection(
                title = stringResource(R.string.posture_settled_title),
                summary = stringResource(R.string.posture_settled_summary, completedChecks.size),
                initiallyExpanded = showCompleted,
                flat = true,
            ) {
                completedChecks.forEach { PostureCheckCard(it, false, {}, {}) }
            }
        }
        historyResult?.let { history ->
            SentinelExpandableSection(
                title = stringResource(R.string.history_title),
                summary = stringResource(R.string.posture_history_summary),
                flat = true,
            ) {
                CheckupHistory(history)
            }
        }
        FullWidthOutlinedAction(
            label = stringResource(R.string.refresh),
            onClick = {
                snapshot = repository.snapshot().also(onUserCheckCompleted)
                refreshRequested = true
                actionFeedback = R.string.refresh_complete
            },
        )
    }
}

@Composable
private fun CheckupSummary(snapshot: DevicePostureSnapshot, refreshRequested: Boolean) {
    SentinelCard(Modifier.semantics {
        if (refreshRequested) liveRegion = LiveRegionMode.Polite
    }) {
        val coverage = snapshot.coverage
        SentinelStatusLabel(
            label = when {
                coverage.attentionCount > 0 -> stringResource(R.string.status_review)
                coverage.unknownCount > 0 -> stringResource(R.string.status_incomplete)
                else -> stringResource(R.string.status_good)
            },
            tone = when {
                coverage.attentionCount > 0 -> SentinelStatusTone.REVIEW
                coverage.unknownCount > 0 -> SentinelStatusTone.INFORMATION
                else -> SentinelStatusTone.GOOD
            },
        )
        Text(
            when {
                coverage.attentionCount > 0 -> pluralStringResource(R.plurals.items_worth_reviewing, coverage.attentionCount, coverage.attentionCount)
                coverage.unknownCount > 0 -> stringResource(R.string.no_urgent_verified)
                else -> stringResource(R.string.no_urgent_checks)
            },
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
        )
        Text(stringResource(R.string.checks_result_summary, coverage.resultCount, snapshot.checks.size, coverage.unknownCount))
        // Timing, partial results and the honesty caveat all matter, but none of them is
        // the answer, so they sit one tap below it rather than competing with it.
        SentinelExpandableSection(
            title = stringResource(R.string.posture_detail_title),
            summary = stringResource(R.string.posture_detail_summary),
        ) {
            if (coverage.partialResultCount > 0) {
                Text(
                    stringResource(R.string.partial_result_summary, coverage.partialResultCount),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(
                stringResource(
                    R.string.checked_at,
                    java.text.DateFormat.getDateTimeInstance().format(java.util.Date(snapshot.generatedAtMillis)),
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(stringResource(R.string.coverage_not_guarantee), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun CheckupHistory(history: PostureHistoryResult) {
    SentinelCard {
        Text(stringResource(R.string.history_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(
            if (history.changedCount == 0 && history.unchangedCount == 0) stringResource(R.string.history_no_comparable_prior)
            else stringResource(R.string.history_summary, history.changedCount, history.unchangedCount, history.unverifiableCount),
            style = MaterialTheme.typography.bodySmall,
        )
        if (history.failure != PostureHistoryFailure.NONE) Text(stringResource(historyFailureLabel(history.failure)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun historyFailureLabel(failure: PostureHistoryFailure): Int = when (failure) {
    PostureHistoryFailure.NONE -> R.string.history_unavailable
    PostureHistoryFailure.CLOCK_UNTRUSTWORTHY -> R.string.history_clock_untrusted
    PostureHistoryFailure.READ_UNAVAILABLE, PostureHistoryFailure.WRITE_UNAVAILABLE -> R.string.history_storage_unavailable
    PostureHistoryFailure.CORRUPT -> R.string.history_data_unavailable
}

@Composable
private fun PostureCheckCard(check: PostureCheck, actionAvailable: Boolean, onAction: (PostureAction) -> Unit, onRetry: () -> Unit) {
    SentinelCard {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(check.title, modifier = Modifier.weight(1f).padding(end = 8.dp), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            SentinelStatusLabel(label = checkStatusText(check), tone = checkStatusTone(check))
        }
        Text(stringResource(evidenceLabel(check.evidenceMode)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(check.explanation, style = MaterialTheme.typography.bodyMedium)
        check.action?.let { action ->
            if (actionAvailable) {
                Text(stringResource(actionConsequenceLabel(action)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                FullWidthOutlinedAction(label = stringResource(actionLabel(action)), onClick = { onAction(action) })
            } else {
                // Retrying re-runs the same check and can never change the outcome, so the
                // user was left with a button that did nothing. Name the destination
                // instead, so there is something they can actually act on.
                Text(stringResource(R.string.settings_unavailable), style = MaterialTheme.typography.bodySmall)
                Text(
                    stringResource(R.string.settings_find_manually, stringResource(manualSettingName(action))),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                )
                FullWidthOutlinedAction(label = stringResource(R.string.retry_check), onClick = onRetry)
            }
        }
    }
}

@Composable private fun checkStatusText(check: PostureCheck): String = stringResource(
    when {
        check.evidenceMode == PostureEvidenceMode.USER_GUIDED_REVIEW -> R.string.status_guided_review
        check.evidenceMode == PostureEvidenceMode.UNAVAILABLE -> R.string.status_unavailable
        check.state == CheckState.PASS -> R.string.status_good
        check.state == CheckState.ATTENTION -> R.string.status_review
        else -> R.string.status_unknown
    },
)

private fun checkStatusTone(check: PostureCheck): SentinelStatusTone = when {
    check.evidenceMode == PostureEvidenceMode.USER_GUIDED_REVIEW -> SentinelStatusTone.INFORMATION
    check.evidenceMode == PostureEvidenceMode.UNAVAILABLE -> SentinelStatusTone.NEUTRAL
    check.state == CheckState.PASS -> SentinelStatusTone.GOOD
    check.state == CheckState.ATTENTION -> SentinelStatusTone.REVIEW
    else -> SentinelStatusTone.NEUTRAL
}

private fun evidenceLabel(mode: PostureEvidenceMode): Int = when (mode) {
    PostureEvidenceMode.AUTOMATICALLY_OBSERVED -> R.string.evidence_mode_automatic
    PostureEvidenceMode.PARTLY_OBSERVED -> R.string.evidence_mode_partial
    PostureEvidenceMode.USER_GUIDED_REVIEW -> R.string.evidence_mode_guided
    PostureEvidenceMode.UNAVAILABLE -> R.string.evidence_mode_unavailable
}

private fun actionLabel(action: PostureAction): Int = when (action) {
    PostureAction.OPEN_SECURITY -> R.string.open_security_settings
    PostureAction.OPEN_DEVELOPER -> R.string.open_developer_options
    PostureAction.OPEN_UPDATE -> R.string.open_system_update
    PostureAction.OPEN_SETTINGS_HOME -> R.string.open_android_settings
}

/** Plain-language name of the Android Settings screen, for when no intent resolves. */
private fun manualSettingName(action: PostureAction): Int = when (action) {
    PostureAction.OPEN_SECURITY -> R.string.setting_name_security
    PostureAction.OPEN_DEVELOPER -> R.string.setting_name_developer
    PostureAction.OPEN_UPDATE -> R.string.setting_name_update
    PostureAction.OPEN_SETTINGS_HOME -> R.string.setting_name_settings
}

private fun actionConsequenceLabel(action: PostureAction): Int = when (action) {
    PostureAction.OPEN_SECURITY -> R.string.action_security_consequence
    PostureAction.OPEN_DEVELOPER -> R.string.action_developer_consequence
    PostureAction.OPEN_UPDATE -> R.string.action_update_consequence
    PostureAction.OPEN_SETTINGS_HOME -> R.string.action_settings_consequence
}
