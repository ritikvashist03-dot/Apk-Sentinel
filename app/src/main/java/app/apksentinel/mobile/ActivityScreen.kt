package app.apksentinel.mobile

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelExpandableSection
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.networkmonitor.DurableHistoryReadState
import app.apksentinel.networkmonitor.DurableHistorySnapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

internal enum class ActivitySourceCategory { NETWORK, PRIVACY_ERASE, APK_CHECK, LINK_CHECK, DEVICE_CHECK }
internal enum class ActivitySourceOutcome { COMPLETED, ATTENTION, UNAVAILABLE, CANCELLED }
internal enum class ActivityDateFilter { ALL, LAST_7_DAYS, LAST_30_DAYS }

internal data class ActivityRow(
    val category: ActivitySourceCategory,
    val outcome: ActivitySourceOutcome,
    val atMillis: Long,
)

@Composable
internal fun ActivityScreen(
    padding: PaddingValues,
    onRunCheckup: () -> Unit,
) {
    val context = LocalContext.current
    val activityStore = remember(context) { SafeActivityStoreController.android(context.applicationContext) }
    val receiptStore = remember(context) { PrivacyDeletionReceiptController.android(context.applicationContext) }
    var safeActivity by remember { mutableStateOf<SafeActivityReadResult?>(null) }
    var receipt by remember { mutableStateOf<PrivacyReceiptReadResult?>(null) }
    var network by remember { mutableStateOf<DurableHistorySnapshot?>(NetworkHistoryComposition.snapshot()) }
    // Saveable so a rotation does not silently discard the user's search and filters,
    // matching NetworkScreen and InstalledAppsScreen. Kotlin enums are Serializable, so
    // the default saver handles the filter values.
    var query by rememberSaveable { mutableStateOf("") }
    var category by rememberSaveable { mutableStateOf<ActivitySourceCategory?>(null) }
    var outcome by rememberSaveable { mutableStateOf<ActivitySourceOutcome?>(null) }
    var dateFilter by rememberSaveable { mutableStateOf(ActivityDateFilter.ALL) }

    LaunchedEffect(activityStore, receiptStore) {
        val results = withContext(Dispatchers.IO) {
            activityStore.read() to receiptStore.read()
        }
        safeActivity = results.first
        receipt = results.second
        NetworkHistoryComposition.requestLoad { network = it }
    }

    val allRows = remember(safeActivity, receipt, network) {
        buildList {
            safeActivity?.records.orEmpty().forEach { record -> add(record.toActivityRow()) }
            receipt?.receipt?.let { value ->
                add(
                    ActivityRow(
                        category = ActivitySourceCategory.PRIVACY_ERASE,
                        outcome = if (value.networkHistoryConfirmed && value.privateFilesConfirmed && value.preferencesConfirmed) {
                            ActivitySourceOutcome.COMPLETED
                        } else {
                            ActivitySourceOutcome.ATTENTION
                        },
                        atMillis = value.completedAtMillis,
                    ),
                )
            }
            network?.takeIf { it.state == DurableHistoryReadState.READY && it.records.isNotEmpty() }?.records?.maxOfOrNull { it.atMillis }?.let { time ->
                add(ActivityRow(ActivitySourceCategory.NETWORK, ActivitySourceOutcome.COMPLETED, time))
            }
        }.sortedByDescending { it.atMillis }
    }
    val visibleRows = remember(allRows, query, category, outcome, dateFilter, context) {
        filterActivityRows(allRows, query, category, outcome, dateFilter, System.currentTimeMillis()) { row ->
            activityCategoryText(context, row.category) to activityOutcomeText(context, row.outcome)
        }
    }

    ScreenColumn(padding) {
        SentinelCard {
            Text(stringResource(R.string.activity_summary_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.activity_summary_body))
            Text(
                text = networkCoverageText(network, allRows.isNotEmpty()),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                stringResource(R.string.activity_not_risk_score),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Button(onClick = onRunCheckup, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.activity_next_checkup))
            }
        }
        SentinelExpandableSection(
            title = stringResource(R.string.activity_filters_title),
            summary = stringResource(R.string.activity_filters_summary),
            flat = true,
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it.take(60) },
                label = { Text(stringResource(R.string.activity_search_label)) },
                supportingText = { Text(stringResource(R.string.activity_search_hint)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Text(stringResource(R.string.activity_filter_category), style = MaterialTheme.typography.labelLarge)
            FilterChip(selected = category == null, onClick = { category = null }, label = { Text(stringResource(R.string.activity_filter_all)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = category == ActivitySourceCategory.NETWORK, onClick = { category = ActivitySourceCategory.NETWORK }, label = { Text(stringResource(R.string.activity_category_network)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = category == ActivitySourceCategory.PRIVACY_ERASE, onClick = { category = ActivitySourceCategory.PRIVACY_ERASE }, label = { Text(stringResource(R.string.activity_category_privacy)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = category == ActivitySourceCategory.APK_CHECK, onClick = { category = ActivitySourceCategory.APK_CHECK }, label = { Text(stringResource(R.string.activity_category_apk)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = category == ActivitySourceCategory.LINK_CHECK, onClick = { category = ActivitySourceCategory.LINK_CHECK }, label = { Text(stringResource(R.string.activity_category_link)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = category == ActivitySourceCategory.DEVICE_CHECK, onClick = { category = ActivitySourceCategory.DEVICE_CHECK }, label = { Text(stringResource(R.string.activity_category_device)) }, modifier = Modifier.fillMaxWidth())
            Text(stringResource(R.string.activity_filter_result), style = MaterialTheme.typography.labelLarge)
            FilterChip(selected = outcome == null, onClick = { outcome = null }, label = { Text(stringResource(R.string.activity_filter_any_status)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = outcome == ActivitySourceOutcome.COMPLETED, onClick = { outcome = ActivitySourceOutcome.COMPLETED }, label = { Text(stringResource(R.string.activity_outcome_completed)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = outcome == ActivitySourceOutcome.ATTENTION, onClick = { outcome = ActivitySourceOutcome.ATTENTION }, label = { Text(stringResource(R.string.activity_outcome_attention)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = outcome == ActivitySourceOutcome.UNAVAILABLE, onClick = { outcome = ActivitySourceOutcome.UNAVAILABLE }, label = { Text(stringResource(R.string.activity_outcome_unavailable)) }, modifier = Modifier.fillMaxWidth())
            FilterChip(selected = outcome == ActivitySourceOutcome.CANCELLED, onClick = { outcome = ActivitySourceOutcome.CANCELLED }, label = { Text(stringResource(R.string.activity_outcome_cancelled)) }, modifier = Modifier.fillMaxWidth())
            Text(stringResource(R.string.activity_filter_date), style = MaterialTheme.typography.labelLarge)
            ActivityDateFilter.entries.forEach { option ->
                FilterChip(selected = dateFilter == option, onClick = { dateFilter = option }, label = { Text(activityDateFilterText(option)) }, modifier = Modifier.fillMaxWidth())
            }
        }
        when (safeActivity?.state) {
            null -> ActivityStateCard(R.string.activity_loading, SentinelStatusTone.NEUTRAL)
            SafeActivityReadState.UNAVAILABLE -> ActivityStateCard(R.string.activity_storage_unavailable, SentinelStatusTone.NEUTRAL)
            SafeActivityReadState.CORRUPT -> ActivityStateCard(R.string.activity_storage_corrupt, SentinelStatusTone.NEUTRAL)
            SafeActivityReadState.CLOCK_UNTRUSTWORTHY -> ActivityStateCard(R.string.activity_clock_unavailable, SentinelStatusTone.NEUTRAL)
            SafeActivityReadState.READY -> Unit
        }
        when (network?.state) {
            DurableHistoryReadState.FAILED -> ActivityStateCard(R.string.activity_network_unavailable, SentinelStatusTone.NEUTRAL)
            DurableHistoryReadState.NOT_LOADED, DurableHistoryReadState.ERASING -> ActivityStateCard(R.string.activity_loading, SentinelStatusTone.NEUTRAL)
            else -> Unit
        }
        if (visibleRows.isEmpty()) {
            SentinelCard(modifier = Modifier.semantics { liveRegion = androidx.compose.ui.semantics.LiveRegionMode.Polite }) {
                Text(stringResource(if (allRows.isEmpty()) R.string.activity_empty else R.string.activity_no_matches), style = MaterialTheme.typography.bodyMedium)
            }
        } else {
            SentinelCard(modifier = Modifier.semantics { liveRegion = androidx.compose.ui.semantics.LiveRegionMode.Polite }) {
                Text(stringResource(R.string.activity_results_count, visibleRows.size), style = MaterialTheme.typography.labelLarge)
                visibleRows.forEach { row ->
                    Text(activityCategoryText(context, row.category), style = MaterialTheme.typography.titleSmall)
                    SentinelStatusLabel(
                        label = activityOutcomeText(context, row.outcome),
                        tone = activityOutcomeTone(row.outcome),
                    )
                    Text(DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(row.atMillis)), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun ActivityStateCard(label: Int, tone: SentinelStatusTone) = SentinelCard {
    SentinelStatusLabel(stringResource(label), tone)
}

@Composable
private fun networkCoverageText(network: DurableHistorySnapshot?, hasRows: Boolean): String = when (network?.state) {
    DurableHistoryReadState.READY -> stringResource(R.string.activity_coverage_network_available)
    DurableHistoryReadState.NOT_LOADED, DurableHistoryReadState.ERASING -> stringResource(R.string.activity_coverage_loading)
    DurableHistoryReadState.FAILED -> stringResource(R.string.activity_coverage_network_unavailable)
    else -> if (hasRows) stringResource(R.string.activity_coverage_local_only) else stringResource(R.string.activity_coverage_local_only)
}

private fun SafeActivityRecord.toActivityRow(): ActivityRow = ActivityRow(
    category = when (category) {
        SafeActivityCategory.APK_CHECK -> ActivitySourceCategory.APK_CHECK
        SafeActivityCategory.LINK_CHECK -> ActivitySourceCategory.LINK_CHECK
        SafeActivityCategory.DEVICE_CHECK -> ActivitySourceCategory.DEVICE_CHECK
    },
    outcome = when (outcome) {
        SafeActivityOutcome.COMPLETED -> ActivitySourceOutcome.COMPLETED
        SafeActivityOutcome.ATTENTION -> ActivitySourceOutcome.ATTENTION
        SafeActivityOutcome.UNAVAILABLE -> ActivitySourceOutcome.UNAVAILABLE
        SafeActivityOutcome.CANCELLED -> ActivitySourceOutcome.CANCELLED
    },
    atMillis = atMillis,
)

internal fun filterActivityRows(
    rows: List<ActivityRow>,
    query: String,
    category: ActivitySourceCategory?,
    outcome: ActivitySourceOutcome?,
    dateFilter: ActivityDateFilter,
    nowMillis: Long,
    labels: (ActivityRow) -> Pair<String, String>,
): List<ActivityRow> {
    val cutoff = when (dateFilter) {
        ActivityDateFilter.ALL -> 0L
        ActivityDateFilter.LAST_7_DAYS -> (nowMillis - 7L * 24 * 60 * 60 * 1_000L).coerceAtLeast(0L)
        ActivityDateFilter.LAST_30_DAYS -> (nowMillis - 30L * 24 * 60 * 60 * 1_000L).coerceAtLeast(0L)
    }
    val normalized = query.trim().lowercase()
    return rows.filter { row ->
        val (categoryText, outcomeText) = labels(row)
        row.atMillis >= cutoff &&
            (category == null || row.category == category) &&
            (outcome == null || row.outcome == outcome) &&
            (normalized.isBlank() || categoryText.lowercase().contains(normalized) || outcomeText.lowercase().contains(normalized) ||
                DateFormat.getDateInstance().format(Date(row.atMillis)).lowercase().contains(normalized))
    }
}

private fun activityCategoryText(context: android.content.Context, category: ActivitySourceCategory): String = context.getString(
    when (category) {
        ActivitySourceCategory.NETWORK -> R.string.activity_category_network
        ActivitySourceCategory.PRIVACY_ERASE -> R.string.activity_category_privacy
        ActivitySourceCategory.APK_CHECK -> R.string.activity_category_apk
        ActivitySourceCategory.LINK_CHECK -> R.string.activity_category_link
        ActivitySourceCategory.DEVICE_CHECK -> R.string.activity_category_device
    },
)

private fun activityOutcomeText(context: android.content.Context, outcome: ActivitySourceOutcome): String = context.getString(
    when (outcome) {
        ActivitySourceOutcome.COMPLETED -> R.string.activity_outcome_completed
        ActivitySourceOutcome.ATTENTION -> R.string.activity_outcome_attention
        ActivitySourceOutcome.UNAVAILABLE -> R.string.activity_outcome_unavailable
        ActivitySourceOutcome.CANCELLED -> R.string.activity_outcome_cancelled
    },
)

/**
 * Each outcome gets a deliberate tone instead of an ATTENTION/else split. UNAVAILABLE is
 * context (the check itself could not run) rather than something to review; COMPLETED and
 * CANCELLED are both ordinary, expected outcomes of the user's own action.
 */
private fun activityOutcomeTone(outcome: ActivitySourceOutcome): SentinelStatusTone = when (outcome) {
    ActivitySourceOutcome.COMPLETED -> SentinelStatusTone.NEUTRAL
    ActivitySourceOutcome.ATTENTION -> SentinelStatusTone.REVIEW
    ActivitySourceOutcome.UNAVAILABLE -> SentinelStatusTone.INFORMATION
    ActivitySourceOutcome.CANCELLED -> SentinelStatusTone.NEUTRAL
}

@Composable
private fun activityDateFilterText(filter: ActivityDateFilter): String = stringResource(
    when (filter) {
        ActivityDateFilter.ALL -> R.string.activity_date_all
        ActivityDateFilter.LAST_7_DAYS -> R.string.activity_date_7_days
        ActivityDateFilter.LAST_30_DAYS -> R.string.activity_date_30_days
    },
)
