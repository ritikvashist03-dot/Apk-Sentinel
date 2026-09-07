package app.apksentinel.mobile

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.core.security.SafeTextNormalizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream

@Composable
internal fun ThreatIntelCard(manager: ThreatIntelManager) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf(manager.load()) }
    var feedBytes by remember { mutableStateOf<ByteArray?>(null) }
    var feedName by rememberSaveable { mutableStateOf<String?>(null) }
    var signature by rememberSaveable { mutableStateOf("") }
    var operationStatus by remember { mutableStateOf<ThreatFeedOperationStatus?>(null) }
    var busy by rememberSaveable { mutableStateOf(false) }
    var networkProtection by remember { mutableStateOf(ThreatNetworkProtectionComposition.current(context)) }
    val feedPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) {
            operationStatus = ThreatFeedOperationStatus.SelectionCancelled
            return@rememberLauncherForActivityResult
        }
        busy = true
        scope.launch {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = context.contentResolver.openInputStream(uri)?.use { it.readUpTo(MAX_FEED_BYTES + 1) }
                        ?: error("No input stream")
                    require(bytes.size <= MAX_FEED_BYTES) { "Feed exceeds the one-megabyte import limit." }
                    bytes
                }
            }
            feedBytes = loaded.getOrNull()
            feedName = runCatching {
                context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        SafeTextNormalizer.normalizeDisplayText(cursor.getString(0), "Selected threat feed", 96)
                    } else {
                        null
                    }
                }
            }.getOrNull()
            operationStatus = if (loaded.isSuccess) ThreatFeedOperationStatus.Loaded else ThreatFeedOperationStatus.ReadFailed
            busy = false
        }
    }

    val selectedFeedName = feedName
    SentinelCard {
        Text(stringResource(R.string.threat_feed_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        when (val current = state) {
            is AppThreatFeedState.Active -> {
                Text(stringResource(R.string.threat_feed_active_version, current.feed.version, current.feed.indicators.size))
                Text(stringResource(R.string.threat_feed_expires, java.text.DateFormat.getDateTimeInstance().format(java.util.Date(current.feed.expiresAtMillis))), style = MaterialTheme.typography.bodySmall)
            }
            AppThreatFeedState.Missing -> Text(stringResource(R.string.threat_feed_missing))
            is AppThreatFeedState.Unavailable -> Text(
                stringResource(current.failure.issue.messageResource()),
                color = MaterialTheme.colorScheme.error,
            )
        }
        Text(stringResource(R.string.threat_feed_import_explainer), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.feed_update_optional_privacy), style = MaterialTheme.typography.bodySmall)
        FullWidthOutlinedAction(
            label = stringResource(R.string.feed_update_check_for_threat_feed),
            onClick = {
                busy = true
                scope.launch {
                    val fetched = withContext(Dispatchers.IO) {
                        SignedBundleUpdateClient.fetch(
                            endpoint = BuildConfig.THREAT_FEED_UPDATE_ENDPOINT,
                            maximumBodyBytes = MAX_FEED_BYTES,
                        )
                    }
                    operationStatus = when (fetched) {
                        is SignedBundleUpdateResult.Failure -> ThreatFeedOperationStatus.UpdateFailed(fetched.reason)
                        is SignedBundleUpdateResult.Success -> {
                            val outcome = try {
                                withContext(Dispatchers.IO) {
                                    manager.install(fetched.body, fetched.signatureBase64)
                                }
                            } finally {
                                fetched.body.fill(0)
                            }
                            state = manager.load()
                            ThreatFeedOperationStatus.Update(outcome)
                        }
                    }
                    busy = false
                }
            },
            enabled = BuildConfig.THREAT_FEED_UPDATE_ENDPOINT.isNotBlank() && !busy,
        )
        FullWidthOutlinedAction(
            label = if (selectedFeedName == null) stringResource(R.string.threat_feed_choose) else stringResource(R.string.threat_feed_selected, selectedFeedName),
            onClick = { feedPicker.launch(arrayOf("text/plain", "application/octet-stream")) },
            enabled = !busy,
        )
        OutlinedTextField(
            value = signature,
            onValueChange = { signature = it.filterNot(Char::isWhitespace).take(4_096) },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.threat_feed_signature)) },
            supportingText = { Text(stringResource(R.string.threat_feed_signature_hint)) },
            minLines = 2,
        )
        Button(
            onClick = {
                val payload = feedBytes ?: return@Button
                busy = true
                scope.launch {
                    operationStatus = try {
                        ThreatFeedOperationStatus.Install(
                            withContext(Dispatchers.IO) { manager.install(payload, signature) },
                        )
                    } finally {
                        payload.fill(0)
                        feedBytes = null
                        feedName = null
                        signature = ""
                    }
                    state = manager.load()
                    networkProtection = ThreatNetworkProtectionComposition.refreshForNextSession(context.applicationContext)
                    busy = false
                }
            },
            enabled = feedBytes != null && signature.isNotBlank() && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(if (busy) stringResource(R.string.threat_feed_working) else stringResource(R.string.threat_feed_verify_install)) }
        if (state is AppThreatFeedState.Active) {
            SentinelToggleRow(
                title = stringResource(R.string.threat_network_title),
                description = stringResource(R.string.threat_network_body),
                checked = networkProtection.enabled,
                onCheckedChange = { enabled ->
                    if (ThreatNetworkProtectionComposition.setEnabled(context.applicationContext, enabled)) {
                        networkProtection = ThreatNetworkProtectionComposition.current(context.applicationContext)
                    }
                },
                onStateLabel = stringResource(R.string.threat_network_on),
                offStateLabel = stringResource(R.string.threat_network_off),
            )
            Text(
                stringResource(
                    R.string.threat_network_rule_count,
                    networkProtection.activeRuleCount,
                    networkProtection.eligibleIndicatorCount,
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            if (networkProtection.truncated) Text(stringResource(R.string.threat_network_truncated), style = MaterialTheme.typography.bodySmall)
            if (networkProtection.pendingUntilNextSession) Text(stringResource(R.string.threat_network_next_session), style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(
                label = stringResource(R.string.threat_feed_delete),
                onClick = {
                    val deleted = manager.erase()
                    operationStatus = if (deleted) ThreatFeedOperationStatus.Deleted else ThreatFeedOperationStatus.DeleteFailed
                    state = manager.load()
                    networkProtection = ThreatNetworkProtectionComposition.refreshForNextSession(context.applicationContext)
                },
                enabled = !busy,
            )
        }
        operationStatus?.let { status ->
            Text(
                text = status.message(context),
                style = MaterialTheme.typography.bodySmall,
                color = if (status.isFailure) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    OfflineAttributionCard()
}

private const val MAX_FEED_BYTES = 1_000_000

/** API-1-compatible bounded read; InputStream.readNBytes is Android API 33. */
private fun InputStream.readUpTo(maximumBytes: Int): ByteArray {
    require(maximumBytes >= 0)
    if (maximumBytes == 0) return ByteArray(0)
    val result = ByteArray(maximumBytes)
    var offset = 0
    while (offset < result.size) {
        val count = read(result, offset, result.size - offset)
        if (count < 0) break
        if (count == 0) {
            val single = read()
            if (single < 0) break
            result[offset++] = single.toByte()
        } else {
            offset += count
        }
    }
    return if (offset == result.size) result else result.copyOf(offset)
}

    private sealed interface ThreatFeedOperationStatus {
    data object SelectionCancelled : ThreatFeedOperationStatus
    data object Loaded : ThreatFeedOperationStatus
    data object ReadFailed : ThreatFeedOperationStatus
    data class Install(val outcome: ThreatFeedInstallOutcome) : ThreatFeedOperationStatus
    data class Update(val outcome: ThreatFeedInstallOutcome) : ThreatFeedOperationStatus
    data class UpdateFailed(val reason: SignedBundleUpdateFailure) : ThreatFeedOperationStatus
    data object Deleted : ThreatFeedOperationStatus
    data object DeleteFailed : ThreatFeedOperationStatus

    val isFailure: Boolean
        get() = this is ReadFailed || this is DeleteFailed ||
            (this is Install && outcome is ThreatFeedInstallOutcome.Rejected) ||
            (this is Update && outcome is ThreatFeedInstallOutcome.Rejected) ||
            this is UpdateFailed

    fun message(context: android.content.Context): String = when (this) {
        SelectionCancelled -> context.getString(R.string.threat_feed_selection_cancelled)
        Loaded -> context.getString(R.string.threat_feed_loaded)
        ReadFailed -> context.getString(R.string.threat_feed_read_failed)
        is Install -> when (val result = outcome) {
            is ThreatFeedInstallOutcome.Installed -> context.getString(
                R.string.threat_feed_install_success,
                result.version,
                result.indicatorCount,
            )
            is ThreatFeedInstallOutcome.Rejected -> context.getString(result.failure.issue.messageResource())
        }
        is Update -> when (val result = outcome) {
            is ThreatFeedInstallOutcome.Installed -> context.getString(
                R.string.feed_update_installed,
                result.version,
            )
            is ThreatFeedInstallOutcome.Rejected -> context.getString(
                R.string.feed_update_failed_kept_current,
            )
        }
        is UpdateFailed -> context.getString(R.string.feed_update_failed_kept_current)
        Deleted -> context.getString(R.string.threat_feed_deleted)
        DeleteFailed -> context.getString(R.string.threat_feed_delete_failed)
    }
}

private fun ThreatFeedIssue.messageResource(): Int = when (this) {
    ThreatFeedIssue.PUBLISHER_KEY_UNAVAILABLE -> R.string.threat_feed_issue_publisher_key_unavailable
    ThreatFeedIssue.SECURE_STORAGE_UNAVAILABLE -> R.string.threat_feed_issue_secure_storage_unavailable
    ThreatFeedIssue.STORED_SNAPSHOT_INCONSISTENT -> R.string.threat_feed_issue_stored_snapshot_inconsistent
    ThreatFeedIssue.PAYLOAD_SIZE -> R.string.threat_feed_issue_payload_size
    ThreatFeedIssue.DEVICE_CLOCK -> R.string.threat_feed_issue_device_clock
    ThreatFeedIssue.FEED_FORMAT -> R.string.threat_feed_issue_feed_format
    ThreatFeedIssue.INDICATOR_LIMIT -> R.string.threat_feed_issue_indicator_limit
    ThreatFeedIssue.TIME_OR_VERSION -> R.string.threat_feed_issue_time_or_version
    ThreatFeedIssue.FEED_LIFETIME -> R.string.threat_feed_issue_feed_lifetime
    ThreatFeedIssue.FUTURE_DATED -> R.string.threat_feed_issue_future_dated
    ThreatFeedIssue.EXPIRED -> R.string.threat_feed_issue_expired
    ThreatFeedIssue.ROLLBACK -> R.string.threat_feed_issue_rollback
    ThreatFeedIssue.SIGNING_KEY_UNTRUSTED -> R.string.threat_feed_issue_signing_key_untrusted
    ThreatFeedIssue.SIGNING_KEY_CONFIGURATION -> R.string.threat_feed_issue_signing_key_configuration
    ThreatFeedIssue.SIGNING_KEY_INACTIVE -> R.string.threat_feed_issue_signing_key_inactive
    ThreatFeedIssue.SIGNING_KEY_VALIDITY -> R.string.threat_feed_issue_signing_key_validity
    ThreatFeedIssue.SIGNATURE_FORMAT -> R.string.threat_feed_issue_signature_format
    ThreatFeedIssue.SIGNATURE_INVALID -> R.string.threat_feed_issue_signature_invalid
    ThreatFeedIssue.NO_INDICATORS -> R.string.threat_feed_issue_no_indicators
    ThreatFeedIssue.INVALID_INDICATOR -> R.string.threat_feed_issue_invalid_indicator
    ThreatFeedIssue.DUPLICATE_INDICATOR -> R.string.threat_feed_issue_duplicate_indicator
    ThreatFeedIssue.SNAPSHOT_TOO_LARGE -> R.string.threat_feed_issue_snapshot_too_large
    ThreatFeedIssue.MALFORMED_SNAPSHOT -> R.string.threat_feed_issue_malformed_snapshot
    ThreatFeedIssue.UNKNOWN -> R.string.threat_feed_issue_unknown
}
