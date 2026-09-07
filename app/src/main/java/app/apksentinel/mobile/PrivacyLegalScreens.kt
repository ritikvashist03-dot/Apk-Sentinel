package app.apksentinel.mobile

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.Manifest
import android.app.Activity
import android.os.Build
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import android.text.format.Formatter
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.KeyValueRow
import app.apksentinel.design.SectionTitle
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelExpandableSection
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.feature.apps.InstalledAppSnapshotController
import app.apksentinel.feature.apps.InstalledAppSnapshotEraseResult
import app.apksentinel.feature.device.DevicePostureHistoryController
import app.apksentinel.networkmonitor.NetworkMonitorController
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.text.DateFormat
import java.util.Date
import kotlin.coroutines.resume

/** Privacy controls entry point. */
@Composable
internal fun PrivacyScreen(
    padding: PaddingValues,
    highContrast: Boolean,
    reduceMotion: Boolean,
    onHighContrastChanged: (Boolean) -> Unit,
    onReduceMotionChanged: (Boolean) -> Unit,
    onOpenTerms: () -> Unit,
) = PrivacyScreenContent(
    padding = padding,
    highContrast = highContrast,
    reduceMotion = reduceMotion,
    onHighContrastChanged = onHighContrastChanged,
    onReduceMotionChanged = onReduceMotionChanged,
    onOpenTerms = onOpenTerms,
)

/** Legal disclosure entry point. */
@Composable
internal fun TermsScreen(padding: PaddingValues, onBack: () -> Unit) =
    TermsScreenContent(padding, onBack)

@Composable
internal fun PrivacyScreenContent(
    padding: PaddingValues,
    highContrast: Boolean,
    reduceMotion: Boolean,
    onHighContrastChanged: (Boolean) -> Unit,
    onReduceMotionChanged: (Boolean) -> Unit,
    onOpenTerms: () -> Unit,
) {
    val context = LocalContext.current
    val threatIntelManager = remember(context) { ThreatIntelManager(context.applicationContext) }
    val deletionReceiptController = remember(context) { PrivacyDeletionReceiptController.android(context.applicationContext) }
    val preferences = remember { context.getSharedPreferences("privacy_preferences", 0) }
    val notificationPreferencesStore = remember(context) { NotificationPreferencesStore(context.applicationContext) }
    var selectedLanguage by remember { mutableStateOf(AppLocaleController.selected(context)) }
    var notificationPreferences by remember { mutableStateOf(notificationPreferencesStore.read()) }
    var sensitiveMode by rememberSaveable { mutableStateOf(false) }
    var showEraseConfirmation by rememberSaveable { mutableStateOf(false) }
    // Read from the process-lifetime coordinator, so an erase started before a rotation
    // is still correctly reported as running by the recreated composition.
    val eraseInProgress = PrivacyEraseCoordinator.inProgress
    var deletionReceipt by rememberSaveable { mutableStateOf<String?>(null) }
    var inventoryRefresh by rememberSaveable { mutableStateOf(0) }
    var inventoryLoading by remember { mutableStateOf(true) }
    var inventory by remember { mutableStateOf<LocalDataInventorySnapshot?>(null) }
    var eraseFailed by remember { mutableStateOf(false) }
    // Picks up an erase that completed while this screen was being recreated, so the
    // outcome is always shown even though the work no longer belongs to this composition.
    LaunchedEffect(PrivacyEraseCoordinator.completionCount) {
        if (PrivacyEraseCoordinator.completionCount == 0) return@LaunchedEffect
        val receipt = PrivacyEraseCoordinator.lastReceipt
        eraseFailed = receipt == null
        if (receipt != null) {
            sensitiveMode = false
            notificationPreferences = withContext(Dispatchers.IO) { notificationPreferencesStore.read() }
            deletionReceipt = formatDeletionReceipt(context, receipt)
            inventoryRefresh++
        }
    }
    LaunchedEffect(deletionReceiptController) {
        val stored = withContext(Dispatchers.IO) { deletionReceiptController.read() }
        deletionReceipt = stored.receipt?.let { formatDeletionReceipt(context, it) }
    }
    LaunchedEffect(inventoryRefresh) {
        inventoryLoading = true
        inventory = withContext(Dispatchers.IO) { LocalDataInventory.inspect(context.applicationContext) }
        inventoryLoading = false
    }
    ScreenColumn(padding) {
        SectionTitle(stringResource(R.string.privacy_consent_title), stringResource(R.string.privacy_consent_subtitle))
        SentinelCard {
            Text(stringResource(R.string.privacy_no_analytics_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.privacy_no_analytics_body))
        }
        SentinelCard {
            Text(stringResource(R.string.privacy_sensitive_advanced_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.privacy_sensitive_advanced_body))
            SentinelToggleRow(
                title = stringResource(R.string.privacy_sensitive_preview_title),
                description = stringResource(R.string.privacy_sensitive_preview_description),
                checked = sensitiveMode,
                onCheckedChange = { sensitiveMode = it },
            )
            if (sensitiveMode) Text(stringResource(R.string.privacy_sensitive_preview_active), style = MaterialTheme.typography.bodySmall)
        }
        SentinelCard {
            Text(stringResource(R.string.privacy_accessibility_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            SentinelToggleRow(
                title = stringResource(R.string.privacy_high_contrast_title),
                description = stringResource(R.string.privacy_high_contrast_description),
                checked = highContrast,
                onCheckedChange = onHighContrastChanged,
            )
            SentinelToggleRow(
                title = stringResource(R.string.privacy_reduce_motion_title),
                description = stringResource(R.string.privacy_reduce_motion_description),
                checked = reduceMotion,
                onCheckedChange = onReduceMotionChanged,
            )
        }
        SentinelCard {
            Text(stringResource(R.string.privacy_language_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.privacy_language_body), style = MaterialTheme.typography.bodySmall)
            LanguageSelector(
                selected = selectedLanguage,
                onSelected = { language ->
                    if (AppLocaleController.select(context, language)) {
                        selectedLanguage = language
                    }
                },
            )
        }
        NotificationPreferencesCard(
            preferences = notificationPreferences,
            weeklySummaryEligible = false, // No durable seven-day monitoring evidence is currently available to this app layer.
            onChanged = { updated ->
                if (notificationPreferencesStore.save(updated)) {
                    notificationPreferences = updated
                    LocalNotificationScheduler.reconcile(context.applicationContext)
                    requestOptionalNotificationPermissionOnce(context, updated)
                }
            },
        )
        ThreatIntelCard(threatIntelManager)
        SentinelCard {
            Text(stringResource(R.string.privacy_trust_center_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.privacy_trust_center_body), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.privacy_trust_center_network_note), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.privacy_tls_certificate_note), style = MaterialTheme.typography.bodySmall)
            inventory?.let { snapshot ->
                KeyValueRow(stringResource(R.string.privacy_data_total), Formatter.formatShortFileSize(context, snapshot.totalBytes))
                snapshot.categories.forEach { category ->
                    KeyValueRow(
                        label = stringResource(localDataCategoryLabel(category.category)),
                        value = stringResource(
                            R.string.privacy_data_size_and_files,
                            Formatter.formatShortFileSize(context, category.bytes),
                            category.files,
                        ),
                    )
                }
                if (snapshot.truncated) Text(stringResource(R.string.privacy_data_inventory_truncated), style = MaterialTheme.typography.bodySmall)
                if (snapshot.failed) Text(stringResource(R.string.privacy_data_inventory_partial), style = MaterialTheme.typography.bodySmall)
            }
            Text(stringResource(R.string.privacy_exported_files_excluded), style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(
                label = stringResource(if (inventoryLoading) R.string.privacy_data_inventory_loading else R.string.privacy_data_inventory_refresh),
                enabled = !inventoryLoading,
                onClick = { inventoryRefresh++ },
            )
        }
        SentinelCard {
            Text(stringResource(R.string.privacy_controls_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.privacy_controls_body))
            FullWidthOutlinedAction(label = stringResource(R.string.privacy_read_terms), onClick = onOpenTerms)
            Button(
                onClick = { showEraseConfirmation = true },
                enabled = !eraseInProgress,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(if (eraseInProgress) R.string.privacy_erase_in_progress else R.string.privacy_erase_action))
            }
            deletionReceipt?.let { receipt ->
                SentinelStatusLabel(
                    label = stringResource(R.string.privacy_erase_done),
                    tone = SentinelStatusTone.GOOD,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                SentinelExpandableSection(
                    title = stringResource(R.string.privacy_erase_details_title),
                    summary = stringResource(R.string.privacy_erase_details_summary),
                ) {
                    Text(receipt, style = MaterialTheme.typography.bodySmall)
                    Text(
                        stringResource(R.string.privacy_erase_receipt_retention),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            // An erase that ends without a receipt previously showed nothing at all, which
            // reads as "nothing happened" when data may in fact have been partly removed.
            if (eraseFailed) {
                Text(
                    stringResource(R.string.privacy_erase_incomplete),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
    if (showEraseConfirmation) AlertDialog(
        onDismissRequest = { showEraseConfirmation = false },
        title = { Text(stringResource(R.string.privacy_erase_dialog_title)) },
        text = { Text(stringResource(R.string.privacy_erase_dialog_body)) },
        confirmButton = {
            TextButton(onClick = {
                showEraseConfirmation = false
                // PrivacyEraseCoordinator.start() owns the in-progress flag now.
                deletionReceipt = null
                eraseFailed = false
                AppRawPcapngDocumentCoordinator.onMonitoringStopped()
                runCatching { NetworkMonitorController.stop(context) }
                // Runs on a process-lifetime scope, NOT this composition's scope: a
                // rotation part-way through must not cancel a half-finished erase.
                // Only application context is captured.
                val applicationContext = context.applicationContext
                PrivacyEraseCoordinator.start {
                    val monitorStopped = awaitMonitorStopped()
                    val (networkHistory, local) = coroutineScope {
                        val networkDeferred = async { awaitNetworkHistoryErase(applicationContext) }
                        val localDeferred = async(Dispatchers.IO) {
                            eraseAppOwnedLocalData(
                                context = applicationContext,
                                threatIntelManager = threatIntelManager,
                                privacyPreferences = preferences,
                                monitorStopped = monitorStopped,
                            )
                        }
                        networkDeferred.await() to localDeferred.await()
                    }
                    val receipt = PrivacyDeletionReceipt(
                        completedAtMillis = System.currentTimeMillis(),
                        grantsReleased = local.grantsReleased,
                        networkEventsCleared = local.networkEventsCleared,
                        firewallRulesCleared = local.firewallRulesCleared,
                        firewallPolicyConfirmed = local.firewallPolicyConfirmed,
                        threatDataConfirmed = local.threatDataConfirmed,
                        installedHistoryConfirmed = local.installedHistoryConfirmed,
                        networkHistoryConfirmed = networkHistory.confirmed,
                        postureHistoryConfirmed = local.postureHistoryConfirmed,
                        privateFilesConfirmed = local.privateFilesConfirmed,
                        preferencesConfirmed = local.preferencesConfirmed,
                        documentGrantsConfirmed = local.documentGrantsConfirmed,
                        monitorStopped = monitorStopped,
                    )
                    withContext(Dispatchers.IO) { deletionReceiptController.save(receipt) }
                    receipt
                }
            }, enabled = !eraseInProgress) { Text(stringResource(R.string.privacy_erase_confirm)) }
        },
        dismissButton = { TextButton(onClick = { showEraseConfirmation = false }) { Text(stringResource(R.string.privacy_cancel)) } },
    )
}

private data class LocalPrivacyEraseResult(
    val grantsReleased: Int,
    val networkEventsCleared: Int,
    val firewallRulesCleared: Int,
    val firewallPolicyConfirmed: Boolean,
    val threatDataConfirmed: Boolean,
    val installedHistoryConfirmed: Boolean,
    val postureHistoryConfirmed: Boolean,
    val privateFilesConfirmed: Boolean,
    val preferencesConfirmed: Boolean,
    val documentGrantsConfirmed: Boolean,
)

@Composable
private fun NotificationPreferencesCard(
    preferences: NotificationPreferences,
    weeklySummaryEligible: Boolean,
    onChanged: (NotificationPreferences) -> Unit,
) {
    val context = LocalContext.current
    SentinelCard {
        Text(stringResource(R.string.notification_preferences_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.notification_preferences_body), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.notification_foreground_service_note), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.notification_important_alerts_title),
            description = stringResource(R.string.notification_important_alerts_body),
            checked = preferences.importantAlerts,
            onCheckedChange = { onChanged(preferences.copy(importantAlerts = it)) },
        )
        SentinelToggleRow(
            title = stringResource(R.string.notification_interruption_title),
            description = stringResource(R.string.notification_interruption_body),
            checked = preferences.interruptionReminder,
            onCheckedChange = { onChanged(preferences.copy(interruptionReminder = it)) },
        )
        SentinelToggleRow(
            title = stringResource(R.string.notification_monthly_title),
            description = stringResource(R.string.notification_monthly_body),
            checked = preferences.monthlyCheckupReminder,
            onCheckedChange = { onChanged(preferences.copy(monthlyCheckupReminder = it)) },
        )
        SentinelToggleRow(
            title = stringResource(R.string.notification_weekly_title),
            description = stringResource(if (weeklySummaryEligible) R.string.notification_weekly_ready_body else R.string.notification_weekly_unavailable_body),
            checked = preferences.weeklySummary,
            enabled = weeklySummaryEligible,
            onCheckedChange = { onChanged(preferences.copy(weeklySummary = it)) },
        )
        SentinelToggleRow(
            title = stringResource(R.string.notification_lock_screen_title),
            description = stringResource(R.string.notification_lock_screen_body),
            checked = preferences.hideLockScreenDetails,
            onCheckedChange = { onChanged(preferences.copy(hideLockScreenDetails = it)) },
        )
        Text(stringResource(R.string.notification_quiet_hours_body), style = MaterialTheme.typography.bodySmall)
        FullWidthOutlinedAction(
            label = stringResource(R.string.notification_open_settings),
            onClick = {
                runCatching {
                    context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                        putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                    })
                }
            },
        )
    }
}

private fun formatDeletionReceipt(context: Context, receipt: PrivacyDeletionReceipt): String = context.getString(
    R.string.privacy_erase_receipt,
    DateFormat.getDateTimeInstance().format(Date(receipt.completedAtMillis)),
    receipt.grantsReleased,
    receipt.networkEventsCleared,
    receipt.firewallRulesCleared,
    context.getString(if (receipt.firewallPolicyConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.threatDataConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.installedHistoryConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.networkHistoryConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.postureHistoryConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.privateFilesConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.preferencesConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.documentGrantsConfirmed) R.string.privacy_erase_removed else R.string.privacy_erase_not_confirmed),
    context.getString(if (receipt.monitorStopped) R.string.privacy_erase_stopped else R.string.privacy_erase_stop_not_confirmed),
)

private suspend fun awaitNetworkHistoryErase(context: Context): HistoryPrivacyEraseResult =
    withTimeoutOrNull(HISTORY_ERASE_WAIT_MILLIS) {
        suspendCancellableCoroutine { continuation ->
            NetworkHistoryComposition.eraseForPrivacy(context) { result ->
                if (continuation.isActive) continuation.resume(result)
            }
        }
    } ?: HistoryPrivacyEraseResult(
        snapshot = NetworkHistoryComposition.snapshot(),
        confirmed = false,
    )

private suspend fun awaitMonitorStopped(): Boolean {
    repeat(MONITOR_STOP_POLL_COUNT) {
        if (NetworkMonitorRuntime.currentStatus().state == app.apksentinel.networkmonitor.MonitorLifecycleState.STOPPED) return true
        delay(MONITOR_STOP_POLL_MILLIS)
    }
    return NetworkMonitorRuntime.currentStatus().state == app.apksentinel.networkmonitor.MonitorLifecycleState.STOPPED
}

/** Blocking storage/Binder work. Always call from Dispatchers.IO. */
private fun eraseAppOwnedLocalData(
    context: Context,
    threatIntelManager: ThreatIntelManager,
    privacyPreferences: SharedPreferences,
    monitorStopped: Boolean,
): LocalPrivacyEraseResult {
    val networkEventsCleared = runCatching { NetworkMonitorRuntime.clearRecentEvents() }.getOrDefault(0)
    val firewallRulesCleared = runCatching { NetworkMonitorRuntime.inMemoryFirewallRules()?.clear() ?: 0 }.getOrDefault(0)
    val firewallPolicyConfirmed = if (monitorStopped) {
        runCatching { FirewallPolicyComposition.eraseForPrivacy() }.getOrDefault(false)
    } else {
        false
    }
    val threatFeedDeleted = runCatching { threatIntelManager.erase() }.getOrDefault(false)
    val encryptedThreatPreferencesCleared = context
        .getSharedPreferences("threat_feed_encrypted", Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit()
    val installedSnapshotErase = runCatching { InstalledAppSnapshotController.erase(context) }.getOrNull()
    val postureHistoryErased = runCatching { DevicePostureHistoryController.android(context).erase() }.getOrDefault(false)

    val grants = runCatching { context.contentResolver.persistedUriPermissions }.getOrDefault(emptyList())
    val grantsReleased = grants.count { grant ->
        runCatching {
            var flags = 0
            if (grant.isReadPermission) flags = flags or Intent.FLAG_GRANT_READ_URI_PERMISSION
            if (grant.isWritePermission) flags = flags or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            context.contentResolver.releasePersistableUriPermission(grant.uri, flags)
        }.isSuccess
    }
    val documentGrantsConfirmed = runCatching { context.contentResolver.persistedUriPermissions.isEmpty() }.getOrDefault(false)

    val privacyPreferencesCleared = runCatching { privacyPreferences.edit().clear().commit() }.getOrDefault(false)
    val onboardingCleared = runCatching {
        context.getSharedPreferences("onboarding", Context.MODE_PRIVATE).edit().clear().commit()
    }.getOrDefault(false)
    val savedViewsCleared = runCatching { SavedNetworkViewStore(context).clear() }.getOrDefault(false)
    // Capture catalog metadata is app-owned and encrypted; this never deletes a
    // user-selected SAF document, only its catalog row and persisted read grant.
    val captureCatalogCleared = runCatching { CaptureDocumentComposition.eraseBlocking(context) }.getOrDefault(false)
    val networkSelectionCleared = runCatching { NetworkAppSelectionStore.clear(context) }.getOrDefault(false)
    val activityCleared = runCatching { SafeActivityStoreController.android(context).erase() }.getOrDefault(false)
    val notificationPreferencesCleared = runCatching {
        val deliveryDataCleared = LocalNotificationDelivery(context).erase()
        val preferencesCleared = NotificationPreferencesStore(context).erase()
        val permissionPromptStateCleared = context
            .getSharedPreferences("notification_permission", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        deliveryDataCleared && preferencesCleared && permissionPromptStateCleared
    }.getOrDefault(false)
    val threatNetworkPreferencesCleared = runCatching { ThreatNetworkProtectionComposition.erase(context) }.getOrDefault(false)
    val offlineAttributionCleared = runCatching { OfflineAttributionComposition.erase(context) }.getOrDefault(false)
    val remoteStreamPairingCleared = runCatching { RemoteStreamComposition.eraseForPrivacy(context) }.getOrDefault(false)
    // Stops rooted diagnostic capture and removes its app-cache output before generic cache deletion.
    val rootCaptureCleared = runCatching { RootCaptureComposition.eraseForPrivacy() }.getOrDefault(false)
    // Only the app-owned Keystore key can be removed here. A certificate a user
    // added through Android Settings stays under the user's Android control.
    val tlsInspectionCleared = runCatching { TlsInspectionComposition.eraseForPrivacy().confirmed }.getOrDefault(false)
    val preferencesConfirmed = privacyPreferencesCleared && onboardingCleared && savedViewsCleared && captureCatalogCleared && networkSelectionCleared && activityCleared &&
        notificationPreferencesCleared && threatNetworkPreferencesCleared && offlineAttributionCleared && remoteStreamPairingCleared &&
        tlsInspectionCleared
    val cacheCleared = deleteAppPrivateChildren(context.cacheDir)
    val filesCleared = deleteAppPrivateChildren(context.filesDir)
    val privateFilesConfirmed = rootCaptureCleared && cacheCleared && filesCleared

    return LocalPrivacyEraseResult(
        grantsReleased = grantsReleased,
        networkEventsCleared = networkEventsCleared,
        firewallRulesCleared = firewallRulesCleared,
        firewallPolicyConfirmed = firewallPolicyConfirmed,
        threatDataConfirmed = threatFeedDeleted && encryptedThreatPreferencesCleared,
        installedHistoryConfirmed = installedSnapshotErase == InstalledAppSnapshotEraseResult.ERASED,
        postureHistoryConfirmed = postureHistoryErased,
        privateFilesConfirmed = privateFilesConfirmed,
        preferencesConfirmed = preferencesConfirmed,
        documentGrantsConfirmed = documentGrantsConfirmed,
    )
}

private fun deleteAppPrivateChildren(directory: java.io.File): Boolean = runCatching {
    directory.listFiles().orEmpty().map { child -> runCatching { child.deleteRecursively() }.getOrDefault(false) }.all { it }
}.getOrDefault(false)

private fun requestOptionalNotificationPermissionOnce(context: Context, preferences: NotificationPreferences) {
    if (Build.VERSION.SDK_INT < 33 || !(preferences.importantAlerts || preferences.interruptionReminder || preferences.monthlyCheckupReminder || preferences.weeklySummary)) return
    if (context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) return
    val asked = context.getSharedPreferences("notification_permission", Context.MODE_PRIVATE)
    if (asked.getBoolean("asked", false)) return
    val activity = context.findActivityForNotificationPermission() ?: return
    runCatching {
        activity.requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 9041)
    }.onSuccess {
        asked.edit().putBoolean("asked", true).commit()
    }
}

private tailrec fun Context.findActivityForNotificationPermission(): Activity? = when (this) {
    is Activity -> this
    is android.content.ContextWrapper -> baseContext.findActivityForNotificationPermission()
    else -> null
}

private const val MONITOR_STOP_POLL_COUNT = 20
private const val MONITOR_STOP_POLL_MILLIS = 250L
private const val HISTORY_ERASE_WAIT_MILLIS = 10_000L

private fun localDataCategoryLabel(category: LocalDataCategory): Int = when (category) {
    LocalDataCategory.ENCRYPTED_HISTORIES -> R.string.privacy_data_encrypted_histories
    LocalDataCategory.THREAT_DATA -> R.string.privacy_data_threat_data
    LocalDataCategory.DISPLAY_AND_SECURITY_PREFERENCES -> R.string.privacy_data_preferences
    LocalDataCategory.REPORT_AND_WORK_CACHE -> R.string.privacy_data_cache
    LocalDataCategory.OTHER_APP_PRIVATE_DATA -> R.string.privacy_data_other
}

@Composable
internal fun TermsScreenContent(padding: PaddingValues, onBack: () -> Unit) {
    val context = LocalContext.current
    val releaseIdentity = remember {
        releaseIdentityOrNull(
            publisherName = BuildConfig.LEGAL_PUBLISHER_NAME,
            supportEmail = BuildConfig.SUPPORT_EMAIL,
            privacyPolicyUrl = BuildConfig.PRIVACY_POLICY_URL,
            effectiveDate = BuildConfig.TERMS_EFFECTIVE_DATE,
        )
    }
    ScreenColumn(padding) {
    SectionTitle(
        stringResource(R.string.terms_title),
        stringResource(if (releaseIdentity == null) R.string.terms_subtitle_pre_release else R.string.terms_subtitle_configured),
    )
    SentinelCard {
        Text(stringResource(R.string.terms_purpose_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.terms_purpose_body))
    }
    SentinelCard {
        Text(stringResource(R.string.terms_inspection_tools_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.terms_inspection_tools_body))
    }
    SentinelCard {
        Text(stringResource(R.string.terms_network_rule_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.terms_network_rule_body))
    }
    SentinelCard {
        Text(stringResource(R.string.terms_sensitive_advanced_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.terms_sensitive_advanced_body))
    }
    SentinelCard {
        Text(stringResource(R.string.terms_privacy_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.terms_privacy_body))
    }
    SentinelCard {
        Text(stringResource(R.string.terms_consent_rule_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.terms_consent_rule_body))
    }
    SentinelCard {
        if (releaseIdentity == null) {
            Text(stringResource(R.string.terms_pre_release_legal_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.terms_pre_release_legal_body))
        } else {
            Text(stringResource(R.string.terms_legal_record_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.terms_legal_publisher, releaseIdentity.publisherName))
            Text(stringResource(R.string.terms_legal_support_email, releaseIdentity.supportEmail))
            Text(stringResource(R.string.terms_legal_effective_date, releaseIdentity.effectiveDate))
            Text(stringResource(R.string.terms_legal_privacy_url, releaseIdentity.privacyPolicyUrl))
            FullWidthOutlinedAction(
                label = stringResource(R.string.terms_open_privacy_policy),
                onClick = {
                    runCatching {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(releaseIdentity.privacyPolicyUrl)))
                    }
                },
            )
        }
    }
    FullWidthOutlinedAction(label = stringResource(R.string.terms_back_to_privacy), onClick = onBack)
    }
}
