package app.apksentinel.mobile

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.core.content.ContextCompat
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.KeyValueRow
import app.apksentinel.core.security.SafeDocumentWriter
import app.apksentinel.design.SentinelExpandableSection
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelPagedList
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.networkmonitor.AppAttribution
import app.apksentinel.networkmonitor.CapabilityAvailability
import app.apksentinel.networkmonitor.FirewallAction
import app.apksentinel.networkmonitor.FirewallPolicyAction
import app.apksentinel.networkmonitor.FirewallPolicyMutationCode
import app.apksentinel.networkmonitor.FirewallPolicyRule
import app.apksentinel.networkmonitor.FirewallPolicyRuleDraft
import app.apksentinel.networkmonitor.FirewallPolicySnapshot
import app.apksentinel.networkmonitor.FirewallPolicyUndoToken
import app.apksentinel.networkmonitor.FirewallRule
import app.apksentinel.networkmonitor.IpCidr
import app.apksentinel.networkmonitor.MonitorLifecycleState
import app.apksentinel.networkmonitor.MonitoringCapabilityId
import app.apksentinel.networkmonitor.MonitoringMode
import app.apksentinel.networkmonitor.NetworkEvent
import app.apksentinel.networkmonitor.DomainCollector
import app.apksentinel.networkmonitor.ProtocolEvidenceHarBridge
import app.apksentinel.networkmonitor.SafeHarExporter
import app.apksentinel.networkmonitor.NetworkMonitorController
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import app.apksentinel.networkmonitor.NetworkMonitorStartRequest
import app.apksentinel.networkmonitor.PacketObservedEvent
import app.apksentinel.networkmonitor.PacketDirection
import app.apksentinel.networkmonitor.PayloadInspectionConfiguration
import app.apksentinel.networkmonitor.PayloadInspectionConsent
import app.apksentinel.networkmonitor.PayloadInspectionDropReason
import app.apksentinel.networkmonitor.PayloadInspectionFailureReason
import app.apksentinel.networkmonitor.PayloadInspectionLimitation
import app.apksentinel.networkmonitor.PayloadInspectionSnapshot
import app.apksentinel.networkmonitor.PayloadInspectionState
import app.apksentinel.networkmonitor.PayloadInspectionTransport
import app.apksentinel.networkmonitor.PayloadRenderFormat
import app.apksentinel.networkmonitor.PayloadRevealAcknowledgement
import app.apksentinel.networkmonitor.PayloadRevealToken
import app.apksentinel.networkmonitor.RenderedPayloadContent
import app.apksentinel.networkmonitor.NetworkUiText
import app.apksentinel.networkmonitor.RawPcapngCaptureFailureReason
import app.apksentinel.networkmonitor.RawPcapngCaptureLimits
import app.apksentinel.networkmonitor.RawPcapngCaptureStartRejection
import app.apksentinel.networkmonitor.RawPcapngCaptureStartResult
import app.apksentinel.networkmonitor.RawPcapngCaptureState
import app.apksentinel.networkmonitor.RawPcapngCaptureStatus
import app.apksentinel.networkmonitor.TunnelConfiguration
import app.apksentinel.networkmonitor.VpnDisclosureAcknowledgement
import app.apksentinel.networkmonitor.VpnDisclosurePolicy
import java.text.DateFormat
import java.util.Date
import java.io.ByteArrayOutputStream
import app.apksentinel.networkmonitor.DurableHistoryReadState
import app.apksentinel.networkmonitor.DurableHistoryRetentionPolicy
import app.apksentinel.networkmonitor.DurableHistorySnapshot
import app.apksentinel.networkmonitor.FlowRegistrySnapshot
import app.apksentinel.networkmonitor.NetworkFlow
import app.apksentinel.networkmonitor.NetworkReviewAnalyzer
import app.apksentinel.networkmonitor.ProtocolEvidenceConfiguration
import app.apksentinel.networkmonitor.ProtocolEvidenceConsent
import app.apksentinel.networkmonitor.ProtocolEvidenceObservation
import app.apksentinel.networkmonitor.ProtocolEvidenceSnapshot
import app.apksentinel.networkmonitor.ProtocolEvidenceValue
import app.apksentinel.networkmonitor.SafeFlowCsvExporter
import app.apksentinel.networkmonitor.SafeFlowMetadataExporter
import app.apksentinel.networkmonitor.SafeFlowXlsxExporter
import app.apksentinel.networkmonitor.SafeDnsName
import app.apksentinel.networkmonitor.presentationReason
import app.apksentinel.networkmonitor.isSessionConfigurationLocked
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import app.apksentinel.networkmonitor.CaptureDocumentRecord
import app.apksentinel.networkmonitor.CaptureDocumentFormat
import app.apksentinel.networkmonitor.CaptureInspectionResult
import app.apksentinel.networkmonitor.CaptureInspectionFailure
import app.apksentinel.networkmonitor.TransportProtocol
import app.apksentinel.networkmonitor.VpnAppSelection

/** Network feature entry point, including the explicit raw-capture flow. */
@Composable
internal fun NetworkEntryScreen(padding: PaddingValues) = NetworkEntryScreenContent(padding)

@Composable
internal fun NetworkEntryScreenContent(padding: PaddingValues) {
    val context = LocalContext.current
    val handler = remember { Handler(Looper.getMainLooper()) }
    var disclosureAccepted by rememberSaveable { mutableStateOf(false) }
    var notificationGranted by remember {
        mutableStateOf(Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
    }
    var status by remember { mutableStateOf(NetworkMonitorRuntime.currentStatus()) }
    var recentEvents by remember { mutableStateOf(NetworkMonitorRuntime.recentEvents(128)) }
    var metrics by remember { mutableStateOf(NetworkMonitorRuntime.forwardingMetrics()) }
    var firewallMode by rememberSaveable { mutableStateOf(false) }
    var ipRuleText by rememberSaveable { mutableStateOf("") }
    var firewallRules by remember { mutableStateOf(NetworkMonitorRuntime.inMemoryFirewallRules()?.snapshot().orEmpty()) }
    var policySnapshot by remember { mutableStateOf(FirewallPolicyComposition.controller()?.current()) }
    var policyUndo by remember { mutableStateOf<FirewallPolicyUndoToken?>(null) }
    var ruleStatus by rememberSaveable { mutableStateOf<String?>(null) }
    var rawDisclosureAccepted by rememberSaveable { mutableStateOf(false) }
    var rawCaptureNotice by rememberSaveable { mutableStateOf(RawCaptureUiNotice.NONE.name) }
    var rawCaptureStatus by remember { mutableStateOf(AppRawPcapngDocumentCoordinator.status()) }
    var payloadAdvancedEnabled by rememberSaveable { mutableStateOf(false) }
    var payloadDisclosureAccepted by rememberSaveable { mutableStateOf(false) }
    var payloadSnapshot by remember { mutableStateOf(NetworkMonitorRuntime.payloadInspectionSnapshot()) }
    var selectedPayloadRecordId by rememberSaveable { mutableStateOf<Long?>(null) }
    var payloadRevealAcknowledged by rememberSaveable { mutableStateOf(false) }
    var payloadRevealToken by remember { mutableStateOf<PayloadRevealToken?>(null) }
    var renderedPayload by remember { mutableStateOf<RenderedPayloadContent?>(null) }
    var payloadRevealUnavailable by rememberSaveable { mutableStateOf(false) }
    var protocolEvidenceEnabled by rememberSaveable { mutableStateOf(false) }
    var protocolDisclosureAccepted by rememberSaveable { mutableStateOf(false) }
    var protocolSniEnabled by rememberSaveable { mutableStateOf(false) }
    var protocolHttpEnabled by rememberSaveable { mutableStateOf(false) }
    var protocolUrlEnabled by rememberSaveable { mutableStateOf(false) }
    var protocolSnapshot by remember { mutableStateOf(NetworkMonitorRuntime.protocolEvidenceSnapshot()) }
    var flowSnapshot by remember { mutableStateOf(NetworkMonitorRuntime.flowRegistrySnapshot()) }
    var selectedFlowId by rememberSaveable { mutableStateOf<String?>(null) }
    var flowExportNotice by rememberSaveable { mutableStateOf<String?>(null) }
    var showAdvancedTools by rememberSaveable { mutableStateOf(false) }
    var pendingStartRequest by remember { mutableStateOf<NetworkMonitorStartRequest?>(null) }
    var history by remember { mutableStateOf<DurableHistorySnapshot?>(null) }
    var historyNotice by rememberSaveable { mutableStateOf<String?>(null) }
    var historyOperationBusy by remember { mutableStateOf(NetworkHistoryComposition.isOperationInProgress()) }
    var showHistoryClearConfirmation by rememberSaveable { mutableStateOf(false) }
    val savedViewStore = remember(context) { SavedNetworkViewStore(context.applicationContext) }
    var showAdvancedFilters by rememberSaveable { mutableStateOf(false) }
    var filterExpression by rememberSaveable { mutableStateOf("all") }
    var appliedFilter by remember { mutableStateOf(NetworkFlowFilter()) }
    var filterNotice by rememberSaveable { mutableStateOf<String?>(null) }
    var savedViewName by rememberSaveable { mutableStateOf("") }
    var savedViews by remember { mutableStateOf(savedViewStore.load()) }
    var appSelectionMode by rememberSaveable { mutableStateOf(NetworkAppSelectionMode.ALL_APPS_EXCEPT.name) }
    var appSelectionPackages by rememberSaveable { mutableStateOf("") }
    var appPickerSearch by rememberSaveable { mutableStateOf("") }
    // Collapsed by default. Expanded, this inlines every visible package - 259 rows on a
    // stock device - between the session controls and everything below them, so exports and
    // firewall rules become unreachable by scrolling. The user opens it to choose apps.
    var showAppPicker by rememberSaveable { mutableStateOf(false) }
    var showAdvancedAppText by rememberSaveable { mutableStateOf(false) }
    var installedSelectionApps by remember { mutableStateOf<List<NetworkSelectableApp>>(emptyList()) }
    var protocolRuleText by rememberSaveable { mutableStateOf("") }
    var portRuleText by rememberSaveable { mutableStateOf("") }
    var domainRuleText by rememberSaveable { mutableStateOf("") }
    var appRuleText by rememberSaveable { mutableStateOf("") }
    var captureRows by remember { mutableStateOf(CaptureDocumentComposition.snapshot(context)) }
    var captureInspection by remember { mutableStateOf<CaptureDocumentInspectionState?>(null) }
    var captureNotice by rememberSaveable { mutableStateOf<String?>(null) }
    var settingsNotice by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingSettingsPreview by remember { mutableStateOf<PortableSettingsPreview?>(null) }
    val sessionConfigurationLocked = isSessionConfigurationLocked(status.state)
    val refreshStatus = {
        status = NetworkMonitorRuntime.currentStatus()
        recentEvents = NetworkMonitorRuntime.recentEvents(128)
        metrics = NetworkMonitorRuntime.forwardingMetrics()
        firewallRules = NetworkMonitorRuntime.inMemoryFirewallRules()?.snapshot().orEmpty()
        policySnapshot = FirewallPolicyComposition.controller()?.current()
        rawCaptureStatus = AppRawPcapngDocumentCoordinator.status()
        payloadSnapshot = NetworkMonitorRuntime.payloadInspectionSnapshot()
        protocolSnapshot = NetworkMonitorRuntime.protocolEvidenceSnapshot()
        flowSnapshot = NetworkMonitorRuntime.flowRegistrySnapshot()
        if (selectedFlowId != null && flowSnapshot.flows.none { it.id == selectedFlowId }) selectedFlowId = null
        history = NetworkHistoryComposition.snapshot() ?: history
        captureRows = CaptureDocumentComposition.snapshot(context)
        historyOperationBusy = NetworkHistoryComposition.isOperationInProgress()
        if (
            rawCaptureNotice in setOf(RawCaptureUiNotice.STARTED.name, RawCaptureUiNotice.STOPPING.name) &&
            rawCaptureStatus.state == RawPcapngCaptureState.STOPPED &&
            !AppRawPcapngDocumentCoordinator.ownsDocumentStream()
        ) {
            rawCaptureNotice = if (
                AppRawPcapngDocumentCoordinator.documentCloseOutcome() == RawPcapngDocumentCloseOutcome.FAILED
            ) RawCaptureUiNotice.DOCUMENT_CLOSE_FAILED.name else RawCaptureUiNotice.STOPPED.name
        }
    }
    LaunchedEffect(Unit) {
        CaptureDocumentComposition.initialize(context)
        withContext(Dispatchers.IO) {
            NetworkAppSelectionStore.load(context)
        }.let { stored ->
            appSelectionMode = stored.mode.name
            appSelectionPackages = stored.packageNames.joinToString(", ")
        }
        installedSelectionApps = withContext(Dispatchers.IO) { InstalledAppSelectionCatalog.read(context.applicationContext) }
        NetworkHistoryComposition.initialize(context) { history = it }
    }
    // The effect above is one-time setup. The recurring refresh is split out and bound to
    // the resumed lifecycle: this is the broadest poll in the app (status, events,
    // forwarding metrics, firewall rules, payload/protocol/flow snapshots, capture
    // catalog, history) and it previously kept running with the app backgrounded.
    LifecyclePolling {
        notificationGranted = Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        refreshStatus()
        // Relate this session's attributed traffic to the installed-app evidence so an app
        // and what it did on the network stop being two unrelated views.
        FindingsComposition.recordNetworkObservations(recentEvents, System.currentTimeMillis())
    }
    fun clearPayloadReveal() {
        NetworkMonitorRuntime.revokePayloadRevealTokens()
        payloadRevealToken = null
        renderedPayload = null
        selectedPayloadRecordId = null
        payloadRevealAcknowledged = false
        payloadRevealUnavailable = false
    }
    LaunchedEffect(status.state) {
        if (status.state != MonitorLifecycleState.ACTIVE) {
            clearPayloadReveal()
            // Protocol acknowledgement is session-scoped and must be fresh
            // after every stop, revoke, failed start, or capability change.
            protocolDisclosureAccepted = false
            // A future protected receiver session may not survive VPN stop,
            // revocation, or a changed forwarding owner.
            RemoteStreamComposition.stopForVpnStopped()
        }
    }
    DisposableEffect(Unit) {
        onDispose {
            // Pending postDelayed callbacks would otherwise fire after this composition is
            // gone and write into discarded MutableState. AnalyzeScreen already guards its
            // equivalent; this brings NetworkScreen in line.
            handler.removeCallbacksAndMessages(null)
            clearPayloadReveal()
            payloadDisclosureAccepted = false
            protocolDisclosureAccepted = false
            protocolEvidenceEnabled = false
            protocolUrlEnabled = false
            RemoteStreamComposition.stopForScreenDisposal()
        }
    }
    val request = {
        val selectedPackages = appSelectionPackages.split(',', ';', '\n').map(String::trim).filter(String::isNotBlank).toSet()
        val selectedAppSelection = NetworkAppSelection.parse(appSelectionMode, selectedPackages)
        if (selectedAppSelection != null) NetworkAppSelectionStore.save(context, selectedAppSelection)
        NetworkMonitorStartRequest(
            tunnel = TunnelConfiguration(
                mode = if (firewallMode) MonitoringMode.FIREWALL_ENFORCEMENT else MonitoringMode.METADATA_ONLY,
                payloadInspection = if (payloadAdvancedEnabled && payloadDisclosureAccepted) {
                    PayloadInspectionConfiguration(
                        enabled = true,
                        consent = PayloadInspectionConsent("payload-inspection-v1", System.currentTimeMillis()),
                    )
                } else {
                    PayloadInspectionConfiguration()
                },
                protocolEvidence = ProtocolEvidenceConfiguration(
                    enabled = protocolEvidenceEnabled && protocolDisclosureAccepted &&
                        (protocolSniEnabled || protocolHttpEnabled),
                    consent = if (
                        protocolEvidenceEnabled && protocolDisclosureAccepted && (protocolSniEnabled || protocolHttpEnabled)
                    ) ProtocolEvidenceConsent("protocol-evidence-v1", System.currentTimeMillis()) else null,
                    inspectTlsClientHelloSni = protocolSniEnabled,
                    inspectCleartextHttp = protocolHttpEnabled,
                    // URL capture cannot outlive HTTP inspection being on.
                    captureRequestTargets = protocolUrlEnabled && protocolHttpEnabled &&
                        protocolEvidenceEnabled && protocolDisclosureAccepted,
                ),
                appSelection = selectedAppSelection?.toVpnSelection() ?: VpnAppSelection.AllAppsExcept(),
                tlsInspection = TlsInspectionComposition.currentTunnelConfiguration(),
            ),
            disclosureAcknowledgement = VpnDisclosureAcknowledgement(VpnDisclosurePolicy.CURRENT_VERSION, System.currentTimeMillis()),
            remoteStreamAttachmentToken = RemoteStreamComposition.currentAttachmentToken(),
        )
    }
    val consentLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val startRequest = pendingStartRequest
        pendingStartRequest = null
        if (result.resultCode == Activity.RESULT_OK && startRequest != null) {
            NetworkMonitorController.startAfterUserConsent(context, startRequest)
            handler.postDelayed({ refreshStatus() }, 700)
        }
    }
    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationGranted = granted
    }
    val rawCaptureLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        when {
            uri == null -> rawCaptureNotice = RawCaptureUiNotice.DOCUMENT_CANCELLED.name
            !rawPcapngExportAvailable(NetworkMonitorRuntime.currentStatus()) -> {
                rawCaptureNotice = RawCaptureUiNotice.NOT_AVAILABLE.name
            }
            else -> {
                runCatching {
                    context.contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                    )
                }
                val output = runCatching { context.contentResolver.openOutputStream(uri, "w") }.getOrNull()
                if (output == null) {
                    rawCaptureNotice = RawCaptureUiNotice.DOCUMENT_OPEN_FAILED.name
                } else {
                    when (val result = AppRawPcapngDocumentCoordinator.start(output, rawPcapngEvidenceLimits())) {
                        is RawPcapngCaptureStartResult.Started -> {
                            CaptureDocumentComposition.recordCreated(context, uri) { outcome ->
                                if (outcome != app.apksentinel.networkmonitor.CaptureMetadataWriteOutcome.WRITTEN) {
                                    captureNotice = context.getString(R.string.capture_catalog_save_failed)
                                }
                            }
                            // Require a fresh acknowledgement for every capture,
                            // not merely once per screen lifetime.
                            rawDisclosureAccepted = false
                            if (rawPcapngExportAvailable(NetworkMonitorRuntime.currentStatus())) {
                                rawCaptureNotice = RawCaptureUiNotice.STARTED.name
                            } else {
                                // The VPN can stop while the document picker is
                                // open. Do not leave an empty capture running.
                                AppRawPcapngDocumentCoordinator.onMonitoringStopped()
                                rawCaptureNotice = RawCaptureUiNotice.NOT_AVAILABLE.name
                            }
                        }
                        is RawPcapngCaptureStartResult.Rejected -> rawCaptureNotice = RawCaptureUiNotice.from(result.reason).name
                    }
            rawCaptureStatus = AppRawPcapngDocumentCoordinator.status()
            history = NetworkHistoryComposition.snapshot() ?: history
                }
            }
        }
    }
    fun writeFlowExport(uri: Uri?, json: Boolean) {
        if (uri == null) {
            flowExportNotice = null
            return
        }
        val output = runCatching { context.contentResolver.openOutputStream(uri, "w") }.getOrNull()
        if (output == null) {
            flowExportNotice = context.getString(R.string.protocol_export_failed)
            return
        }
        flowExportNotice = runCatching {
            val result = if (json) {
                SafeFlowMetadataExporter.writeJson(flowSnapshot, output)
            } else {
                SafeFlowMetadataExporter.writeJsonLines(flowSnapshot, output)
            }
            context.getString(
                R.string.protocol_export_done,
                result.recordsWritten,
                result.bytesWritten,
                if (result.truncated) context.getString(R.string.protocol_export_truncated) else "",
            )
        }.getOrElse { context.getString(R.string.protocol_export_failed) }
        runCatching { output.close() }
    }
    fun writeFlowSpreadsheet(uri: Uri?, xlsx: Boolean) {
        if (uri == null) {
            flowExportNotice = null
            return
        }
        flowExportNotice = SafeDocumentWriter.useOutputStream(context, uri) { output ->
            if (xlsx) {
                // A zip has no final size until it is closed, so this reports rows only
                // rather than inventing a byte count.
                val result = SafeFlowXlsxExporter.write(flowSnapshot, output)
                context.getString(
                    R.string.protocol_export_done_rows,
                    result.recordsWritten,
                    if (result.truncated) context.getString(R.string.protocol_export_truncated) else "",
                )
            } else {
                val result = SafeFlowCsvExporter.write(flowSnapshot, output)
                context.getString(
                    R.string.protocol_export_done,
                    result.recordsWritten,
                    result.bytesWritten,
                    if (result.truncated) context.getString(R.string.protocol_export_truncated) else "",
                )
            }
        } ?: context.getString(R.string.protocol_export_failed)
    }
    val flowCsvExportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafeFlowCsvExporter.MIME_TYPE),
    ) { uri -> writeFlowSpreadsheet(uri, xlsx = false) }
    val flowXlsxExportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafeFlowXlsxExporter.MIME_TYPE),
    ) { uri -> writeFlowSpreadsheet(uri, xlsx = true) }
    val flowExportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafeFlowMetadataExporter.MIME_TYPE),
    ) { uri -> writeFlowExport(uri, json = false) }
    val flowJsonExportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument(SafeFlowMetadataExporter.JSON_MIME_TYPE),
    ) { uri -> writeFlowExport(uri, json = true) }
    val captureOpenLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) {
            captureNotice = context.getString(R.string.capture_import_cancelled)
        } else {
            runCatching {
                context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            captureInspection = CaptureDocumentInspectionState(uri.toString(), null, null, busy = true)
            CaptureDocumentComposition.openAndInspect(context, uri) {
                captureInspection = it
                captureRows = CaptureDocumentComposition.snapshot(context)
                captureNotice = context.getString(
                    if (it.result is CaptureInspectionResult.Opened) R.string.capture_import_opened else R.string.capture_import_not_opened,
                )
            }
        }
    }
    val settingsExportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        val output = uri?.let { runCatching { context.contentResolver.openOutputStream(it, "w") }.getOrNull() }
        if (output == null) settingsNotice = context.getString(R.string.settings_export_failed)
        else runCatching {
            output.use { it.write(NetworkSettingsPortability.export(context, FirewallPolicyComposition.controller()?.current()?.rules.orEmpty())) }
            settingsNotice = context.getString(R.string.settings_export_done)
        }.onFailure { settingsNotice = context.getString(R.string.settings_export_failed) }
    }
    val settingsImportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val bytes = uri?.let { runCatching { context.contentResolver.openInputStream(it)?.use(::readBoundedSettingsBytes) }.getOrNull() }
        if (bytes == null) settingsNotice = context.getString(R.string.settings_import_failed)
        else {
            val preview = NetworkSettingsPortability.preview(context, bytes)
            if (preview.settings == null) settingsNotice = context.getString(R.string.settings_import_failed)
            else pendingSettingsPreview = preview
        }
    }
    if (pendingSettingsPreview?.settings != null) {
        AlertDialog(
            onDismissRequest = { pendingSettingsPreview = null },
            title = { Text(stringResource(R.string.settings_import_preview_title)) },
            text = { Text(stringResource(R.string.settings_import_preview_body, pendingSettingsPreview?.settings?.firewallRules?.size ?: 0, pendingSettingsPreview?.settings?.appSelection?.packageNames?.size ?: 0, pendingSettingsPreview?.conflicts?.size ?: 0)) },
            dismissButton = { TextButton(onClick = { pendingSettingsPreview = null }) { Text(stringResource(R.string.privacy_cancel)) } },
            confirmButton = {
                TextButton(onClick = {
                    val result = NetworkSettingsPortability.apply(context, requireNotNull(pendingSettingsPreview), confirmed = true)
                    settingsNotice = context.getString(if (result is PortableSettingsApplyResult.Applied) R.string.settings_import_applied else R.string.settings_import_failed)
                    if (result is PortableSettingsApplyResult.Applied) {
                        result.preview.settings?.appSelection?.let { selection ->
                            appSelectionMode = selection.mode.name
                            appSelectionPackages = selection.packageNames.joinToString(", ")
                        }
                    }
                    pendingSettingsPreview = null
                }) { Text(stringResource(R.string.settings_import_apply)) }
            },
        )
    }
    if (showHistoryClearConfirmation) {
        AlertDialog(
            onDismissRequest = { showHistoryClearConfirmation = false },
            title = { Text(stringResource(R.string.history_clear_confirmation_title)) },
            text = { Text(stringResource(R.string.history_clear_confirmation_body)) },
            dismissButton = {
                TextButton(onClick = { showHistoryClearConfirmation = false }) {
                    Text(stringResource(R.string.privacy_cancel))
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showHistoryClearConfirmation = false
                        historyNotice = null
                        historyOperationBusy = true
                        NetworkHistoryComposition.clearHistory(context) { result ->
                            history = result.snapshot
                            historyOperationBusy = false
                            historyNotice = context.getString(
                                if (result.confirmed) R.string.history_erased else R.string.history_not_confirmed,
                            )
                        }
                    },
                ) { Text(stringResource(R.string.history_clear)) }
            },
        )
    }
    ScreenColumn(padding) {
        SentinelCard {
            SentinelStatusLabel(
                label = when (status.state) {
                    MonitorLifecycleState.ACTIVE -> stringResource(R.string.network_status_monitoring_active)
                    MonitorLifecycleState.STARTING -> stringResource(R.string.network_status_starting_safely)
                    MonitorLifecycleState.CAPABILITY_UNAVAILABLE -> stringResource(R.string.network_status_forwarding_unavailable)
                    MonitorLifecycleState.CONSENT_REQUIRED -> stringResource(R.string.network_status_android_consent_required)
                    MonitorLifecycleState.FAILED -> stringResource(R.string.network_status_session_failed)
                    else -> stringResource(R.string.network_status_no_session_active)
                },
                tone = when (status.state) {
                    MonitorLifecycleState.ACTIVE -> SentinelStatusTone.GOOD
                    MonitorLifecycleState.STARTING, MonitorLifecycleState.STOPPING -> SentinelStatusTone.INFORMATION
                    MonitorLifecycleState.CAPABILITY_UNAVAILABLE, MonitorLifecycleState.FAILED, MonitorLifecycleState.REVOKED_BY_SYSTEM -> SentinelStatusTone.URGENT
                    MonitorLifecycleState.CONSENT_REQUIRED -> SentinelStatusTone.REVIEW
                    else -> SentinelStatusTone.NEUTRAL
                },
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Text(stringResource(NetworkUiTextMapper.text(status.uiText.code)))
            FullWidthOutlinedAction(label = stringResource(R.string.network_refresh_actual_state), onClick = refreshStatus)
            SentinelExpandableSection(
                title = stringResource(R.string.network_limits_title),
                summary = stringResource(R.string.network_limits_summary),
                flat = true,
            ) {
                Text(stringResource(R.string.network_proxy_limitation), style = MaterialTheme.typography.bodySmall)
            }
        }
        SentinelExpandableSection(
            title = stringResource(R.string.history_title),
            summary = stringResource(R.string.network_history_summary),
            flat = true,
        ) {
            val currentHistory = history
            Text(stringResource(R.string.history_body), style = MaterialTheme.typography.bodySmall)
            if (currentHistory != null) {
                KeyValueRow(stringResource(R.string.history_policy_label), historyPolicyText(currentHistory.policy))
                KeyValueRow(stringResource(R.string.history_records_label), currentHistory.records.size.toString())
                KeyValueRow(stringResource(R.string.history_bytes_label), currentHistory.retainedPlaintextBytes.toString())
                KeyValueRow(
                    stringResource(R.string.history_dropped_label),
                    (currentHistory.droppedIngressRecords + currentHistory.droppedByLimitRecords).toString(),
                )
                SentinelPagedList(
                    items = currentHistory.records.asReversed(),
                    initialVisibleCount = 8,
                ) { record -> Text(historyRecordText(record), style = MaterialTheme.typography.bodySmall) }
                if (currentHistory.state == DurableHistoryReadState.FAILED) Text(stringResource(R.string.history_not_confirmed), color = MaterialTheme.colorScheme.error)
            }
            DurableHistoryRetentionPolicy.entries.forEach { policy ->
                FullWidthOutlinedAction(
                    label = historyPolicyText(policy),
                    enabled = status.state == MonitorLifecycleState.STOPPED &&
                        !historyOperationBusy && currentHistory?.policy != policy,
                    onClick = {
                        historyNotice = null
                        historyOperationBusy = true
                        NetworkHistoryComposition.changePolicy(context, policy) { result ->
                            history = result.snapshot ?: history
                            historyOperationBusy = false
                            historyNotice = context.getString(
                                if (result.confirmed) R.string.history_policy_changed else R.string.history_operation_not_confirmed,
                            )
                        }
                    },
                )
            }
            if (status.state != MonitorLifecycleState.STOPPED) Text(stringResource(R.string.history_change_requires_stop), style = MaterialTheme.typography.bodySmall)
            if (historyOperationBusy) Text(stringResource(R.string.history_operation_in_progress), style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(
                label = stringResource(R.string.history_clear),
                onClick = { showHistoryClearConfirmation = true },
                enabled = currentHistory != null && status.state == MonitorLifecycleState.STOPPED && !historyOperationBusy,
            )
            historyNotice?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
        }
        CaptureLibraryCard(
            rows = captureRows,
            inspection = captureInspection,
            notice = captureNotice,
            catalogState = CaptureDocumentComposition.persistenceState(context),
            onOpen = { captureOpenLauncher.launch(arrayOf("application/octet-stream", "application/vnd.tcpdump.pcap", "application/x-pcapng", "application/json")) },
            onRefresh = { CaptureDocumentComposition.refresh(context) { captureRows = it } },
            onForget = { record ->
                CaptureDocumentComposition.forget(context, record) { removed ->
                    if (removed) captureRows = CaptureDocumentComposition.snapshot(context)
                    else captureNotice = context.getString(R.string.capture_catalog_save_failed)
                }
            },
        )
        SentinelExpandableSection(
            title = stringResource(R.string.settings_portability_title),
            summary = stringResource(R.string.network_portability_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.settings_portability_body), style = MaterialTheme.typography.bodySmall)
            Button(onClick = { settingsExportLauncher.launch("apk-sentinel-settings-v1.txt") }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.settings_export))
            }
            FullWidthOutlinedAction(label = stringResource(R.string.settings_import), onClick = { settingsImportLauncher.launch(arrayOf("text/plain", "application/octet-stream")) })
            settingsNotice?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
        }
        SentinelCard {
            Text(stringResource(R.string.network_before_starting), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.network_disclosure_body))
            SentinelToggleRow(
                title = stringResource(R.string.network_allow_local_session),
                description = if (disclosureAccepted) stringResource(R.string.network_disclosure_accepted_attempt) else stringResource(R.string.network_disclosure_review),
                checked = disclosureAccepted,
                onCheckedChange = { disclosureAccepted = it },
                onStateLabel = stringResource(R.string.network_disclosure_accepted_start),
                offStateLabel = stringResource(R.string.network_disclosure_not_accepted),
            )
            if (!notificationGranted && Build.VERSION.SDK_INT >= 33) {
                Text(stringResource(R.string.network_notification_explainer))
                FullWidthOutlinedAction(label = stringResource(R.string.network_allow_session_notification), onClick = { notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) })
                FullWidthOutlinedAction(
                    label = stringResource(R.string.network_open_notification_settings),
                    onClick = {
                        context.startActivity(
                            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                                .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName),
                        )
                    },
                )
            }
            SentinelToggleRow(
                title = stringResource(R.string.network_apply_firewall_rules),
                description = stringResource(R.string.network_firewall_mode_description),
                checked = firewallMode,
                onCheckedChange = { firewallMode = it },
                enabled = status.state !in setOf(MonitorLifecycleState.STARTING, MonitorLifecycleState.ACTIVE, MonitorLifecycleState.STOPPING),
                onStateLabel = stringResource(R.string.network_firewall_requested),
                offStateLabel = stringResource(R.string.network_metadata_only_requested),
            )
            Text(stringResource(R.string.network_app_selection_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.network_app_selection_body), style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(
                label = stringResource(R.string.network_app_selection_all_except),
                enabled = appSelectionMode != NetworkAppSelectionMode.ALL_APPS_EXCEPT.name,
                onClick = {
                    appSelectionMode = NetworkAppSelectionMode.ALL_APPS_EXCEPT.name
                },
            )
            FullWidthOutlinedAction(
                label = stringResource(R.string.network_app_selection_only),
                enabled = appSelectionMode != NetworkAppSelectionMode.ONLY_APPS.name,
                onClick = { appSelectionMode = NetworkAppSelectionMode.ONLY_APPS.name },
            )
            val selectionForUi = NetworkAppSelection.parse(
                appSelectionMode,
                appSelectionPackages.split(',', ';', '\n').map(String::trim).filter(String::isNotBlank).toSet(),
            )
            val selectedPackagesForUi = appSelectionPackages.split(',', ';', '\n').map(String::trim).filter(String::isNotBlank).toSet()
            val knownPackages = installedSelectionApps.mapTo(hashSetOf()) { it.packageName }
            Text(
                stringResource(R.string.network_app_selection_selected_count, selectedPackagesForUi.size),
                style = MaterialTheme.typography.bodySmall,
            )
            if (selectedPackagesForUi.any { it !in knownPackages } && installedSelectionApps.isNotEmpty()) {
                Text(stringResource(R.string.network_app_selection_unknown_selected), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            FullWidthOutlinedAction(
                label = stringResource(if (showAppPicker) R.string.network_app_selection_hide_picker else R.string.network_app_selection_show_picker),
                onClick = { showAppPicker = !showAppPicker },
            )
            if (showAppPicker) {
                OutlinedTextField(
                    value = appPickerSearch,
                    onValueChange = { appPickerSearch = it.take(96) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.network_app_selection_search)) },
                    supportingText = { Text(stringResource(R.string.network_app_selection_search_hint)) },
                    singleLine = true,
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.network_app_selection_clear),
                    enabled = selectedPackagesForUi.isNotEmpty(),
                    onClick = { appSelectionPackages = "" },
                )
                val visibleApps = InstalledAppSelectionCatalog.filter(installedSelectionApps, appPickerSearch)
                if (visibleApps.isEmpty()) {
                    Text(stringResource(if (installedSelectionApps.isEmpty()) R.string.network_app_selection_unavailable else R.string.network_app_selection_no_match), style = MaterialTheme.typography.bodySmall)
                } else {
                    visibleApps.forEach { app ->
                        val selected = app.packageName in selectedPackagesForUi
                        val appKind = stringResource(if (app.isSystem) R.string.network_app_selection_system else R.string.network_app_selection_user)
                        SentinelToggleRow(
                            title = app.label,
                            description = stringResource(R.string.network_app_selection_app_description, appKind, app.packageName),
                            checked = selected,
                            onCheckedChange = {
                                val next = if (it) selectedPackagesForUi + app.packageName else selectedPackagesForUi - app.packageName
                                appSelectionPackages = next.sorted().joinToString(", ")
                            },
                            onStateLabel = stringResource(R.string.network_app_selection_selected),
                            offStateLabel = stringResource(R.string.network_app_selection_not_selected),
                        )
                        Text(app.packageName, style = MaterialTheme.typography.bodySmall.copy(textDirection = androidx.compose.ui.text.style.TextDirection.Ltr))
                    }
                }
                if (installedSelectionApps.size >= InstalledAppSelectionCatalog.MAX_APPS) {
                    Text(stringResource(R.string.network_app_selection_coverage_limited, InstalledAppSelectionCatalog.MAX_APPS), style = MaterialTheme.typography.bodySmall)
                }
            }
            FullWidthOutlinedAction(
                label = stringResource(if (showAdvancedAppText) R.string.network_app_selection_hide_advanced else R.string.network_app_selection_show_advanced),
                onClick = { showAdvancedAppText = !showAdvancedAppText },
            )
            if (showAdvancedAppText) OutlinedTextField(
                value = appSelectionPackages,
                onValueChange = { appSelectionPackages = it.take(4_096) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.network_app_selection_packages)) },
                supportingText = { Text(stringResource(R.string.network_app_selection_hint)) },
                singleLine = false,
            )
            if (selectionForUi == null) {
                Text(stringResource(R.string.network_app_selection_invalid), color = MaterialTheme.colorScheme.error)
            }
            Button(
                onClick = {
                    ThreatNetworkProtectionComposition.refreshForNextSession(context.applicationContext)
                    val startRequest = request()
                    // The acknowledgement is consumed by this start attempt. The
                    // request itself retains it across Android's VPN consent UI.
                    disclosureAccepted = false
                    payloadDisclosureAccepted = false
                    protocolDisclosureAccepted = false
                    val intent = NetworkMonitorController.vpnConsentIntent(context)
                    if (intent != null) {
                        pendingStartRequest = startRequest
                        consentLauncher.launch(intent)
                    } else {
                        NetworkMonitorController.startAfterUserConsent(context, startRequest)
                        handler.postDelayed({ refreshStatus() }, 700)
                    }
                },
                enabled = disclosureAccepted && selectionForUi != null &&
                    status.state != MonitorLifecycleState.ACTIVE && !historyOperationBusy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.network_start_local_monitoring)) }
            // The button disables until the disclosure above is accepted. Without this the
            // user taps a greyed-out control and nothing happens, with nothing on screen
            // saying what is missing.
            if (!disclosureAccepted) {
                Text(
                    stringResource(R.string.network_start_needs_disclosure),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            // Same reasoning as the disclosure check above: these are the other two ways
            // this button silently stays disabled, and each needs its own on-screen reason.
            if (status.state == MonitorLifecycleState.ACTIVE) {
                Text(
                    stringResource(R.string.network_start_already_active),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (historyOperationBusy) {
                Text(
                    stringResource(R.string.network_start_needs_history_wait),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            FullWidthOutlinedAction(
                label = stringResource(R.string.network_stop_session),
                onClick = {
                    AppRawPcapngDocumentCoordinator.onMonitoringStopped()
                    clearPayloadReveal()
                    payloadDisclosureAccepted = false
                    NetworkMonitorController.stop(context)
                    handler.postDelayed({ refreshStatus() }, 500)
                },
                enabled = status.state != MonitorLifecycleState.STOPPED,
            )
        }
        status.capabilities?.reports?.let { reports ->
            SentinelExpandableSection(
                title = stringResource(R.string.network_engine_capabilities),
                summary = stringResource(R.string.network_engine_capabilities_summary),
                flat = true,
            ) {
                reports.forEach { report ->
                    Text(
                        stringResource(
                            R.string.network_capability_report,
                            stringResource(NetworkUiTextMapper.capabilityName(report.capability)),
                            stringResource(NetworkUiTextMapper.capabilityAvailability(report.availability)),
                        ),
                    )
                    Text(
                        stringResource(NetworkUiTextMapper.capabilityReason(report.presentationReason())),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        SentinelExpandableSection(
            title = stringResource(R.string.network_live_counters),
            summary = stringResource(R.string.network_counters_summary),
            flat = true,
        ) {
            KeyValueRow(stringResource(R.string.network_active_tcp_udp), "${metrics.activeTcpFlows} / ${metrics.activeUdpFlows}")
            KeyValueRow(stringResource(R.string.network_observed_packets), "${metrics.outboundPackets + metrics.inboundPackets}")
            KeyValueRow(stringResource(R.string.network_forwarded_upstream_bytes), "${metrics.upstreamSentBytes + metrics.upstreamReceivedBytes}")
            KeyValueRow(stringResource(R.string.network_confirmed_blocked_packets), metrics.blockedPackets.toString())
            KeyValueRow(stringResource(R.string.network_unsupported_malformed), "${metrics.unsupportedPackets} / ${metrics.malformedPackets}")
            Text(stringResource(R.string.network_counters_limitation), style = MaterialTheme.typography.bodySmall)
        }
        FirewallPolicyCard(
            ipRuleText = ipRuleText,
            onIpRuleTextChange = { ipRuleText = it.filterNot(Char::isWhitespace).take(64); ruleStatus = null },
            protocolRuleText = protocolRuleText,
            onProtocolRuleTextChange = { protocolRuleText = it.take(12); ruleStatus = null },
            portRuleText = portRuleText,
            onPortRuleTextChange = { portRuleText = it.filterNot(Char::isWhitespace).take(11); ruleStatus = null },
            domainRuleText = domainRuleText,
            onDomainRuleTextChange = { domainRuleText = it.take(253); ruleStatus = null },
            appRuleText = appRuleText,
            onAppRuleTextChange = { appRuleText = it.take(4_096); ruleStatus = null },
            snapshot = policySnapshot,
            undo = policyUndo,
            onMutation = { message, undo ->
                ruleStatus = message
                policyUndo = undo
                policySnapshot = FirewallPolicyComposition.controller()?.current()
            },
        )
        SentinelExpandableSection(
            title = stringResource(R.string.network_filters_title),
            summary = stringResource(R.string.network_filters_summary_short),
            flat = true,
        ) {
            Text(stringResource(R.string.network_filters_body), style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(label = stringResource(R.string.network_filter_all), onClick = {
                appliedFilter = NetworkFlowFilter()
                filterExpression = "all"
                filterNotice = context.getString(R.string.network_filter_applied)
            })
            FullWidthOutlinedAction(label = stringResource(R.string.network_filter_blocked), onClick = {
                appliedFilter = NetworkFlowFilter(decision = NetworkFilterDecision.BLOCKED)
                filterExpression = "decision:blocked"
                filterNotice = context.getString(R.string.network_filter_applied)
            })
            FullWidthOutlinedAction(label = stringResource(R.string.network_filter_unknown_app), onClick = {
                appliedFilter = NetworkFlowFilter(attribution = NetworkFilterAttribution.UNKNOWN)
                filterExpression = "app:unknown"
                filterNotice = context.getString(R.string.network_filter_applied)
            })
            SentinelToggleRow(
                title = stringResource(R.string.network_advanced_filters_title),
                description = stringResource(R.string.network_advanced_filters_body),
                checked = showAdvancedFilters,
                onCheckedChange = { showAdvancedFilters = it },
                onStateLabel = stringResource(R.string.network_advanced_filters_shown),
                offStateLabel = stringResource(R.string.network_advanced_filters_hidden),
            )
            if (showAdvancedFilters) {
                OutlinedTextField(
                    value = filterExpression,
                    onValueChange = { filterExpression = it.take(NetworkFilterParser.MAX_EXPRESSION_CODE_POINTS); filterNotice = null },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.network_filter_expression)) },
                    supportingText = { Text(stringResource(R.string.network_filter_expression_help)) },
                )
                FullWidthOutlinedAction(label = stringResource(R.string.network_filter_apply), onClick = {
                    when (val parsed = NetworkFilterParser.parse(filterExpression)) {
                        is NetworkFilterParseResult.Success -> {
                            appliedFilter = parsed.filter
                            filterExpression = parsed.canonicalExpression
                            filterNotice = context.getString(R.string.network_filter_applied)
                        }
                        is NetworkFilterParseResult.Failure -> filterNotice = context.getString(networkFilterFailureText(parsed.reason))
                    }
                })
                OutlinedTextField(
                    value = savedViewName,
                    onValueChange = { savedViewName = it.take(SavedNetworkViewStore.MAX_NAME_CODE_POINTS); filterNotice = null },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.network_saved_view_name)) },
                    singleLine = true,
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.network_save_view),
                    enabled = savedViewName.isNotBlank() && NetworkFilterParser.parse(filterExpression) is NetworkFilterParseResult.Success,
                    onClick = {
                        val saved = savedViewStore.save(SavedNetworkView(savedViewName, filterExpression))
                        if (saved) {
                            savedViews = savedViewStore.load()
                            savedViewName = ""
                        }
                        filterNotice = context.getString(if (saved) R.string.network_saved_view_saved else R.string.network_saved_view_failed)
                    },
                )
                // Silent otherwise: this button needs both a name and a filter expression
                // that currently parses, and neither gap has any other visible signal.
                if (savedViewName.isBlank() || NetworkFilterParser.parse(filterExpression) !is NetworkFilterParseResult.Success) {
                    Text(
                        stringResource(R.string.network_save_view_needs_valid_filter),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                savedViews.forEach { view ->
                    KeyValueRow(view.name, view.expression) {
                        TextButton(onClick = {
                            val parsed = NetworkFilterParser.parse(view.expression) as? NetworkFilterParseResult.Success
                            if (parsed != null) {
                                appliedFilter = parsed.filter
                                filterExpression = parsed.canonicalExpression
                                filterNotice = context.getString(R.string.network_filter_applied)
                            }
                        }) { Text(stringResource(R.string.network_saved_view_use)) }
                        TextButton(onClick = {
                            val removed = savedViewStore.remove(view.name)
                            if (removed) savedViews = savedViewStore.load()
                            filterNotice = context.getString(if (removed) R.string.network_saved_view_removed else R.string.network_saved_view_failed)
                        }) { Text(stringResource(R.string.network_remove_rule)) }
                    }
                }
            }
            filterNotice?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        SentinelCard {
            Text(stringResource(R.string.network_recent_flows), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            val decisionStates = firewallDecisionsByFlow(recentEvents)
            val recentFlows = recentEvents.filterIsInstance<PacketObservedEvent>()
                .asReversed()
                .distinctBy(PacketObservedEvent::flowId)
                .filter { event -> appliedFilter.matches(event, decisionStates[event.flowId]) }
            if (recentFlows.isEmpty()) {
                Text(stringResource(R.string.network_no_packet_metadata))
            } else {
                SentinelPagedList(items = recentFlows, initialVisibleCount = 8) { event ->
                    Text(networkEventSummary(event), style = MaterialTheme.typography.bodySmall)
                }
            }
            FullWidthOutlinedAction(
                label = stringResource(R.string.network_clear_retained_events),
                onClick = {
                    val cleared = NetworkMonitorRuntime.clearRecentEvents()
                    recentEvents = emptyList()
                    ruleStatus = context.getString(R.string.network_events_cleared, cleared)
                },
                enabled = recentEvents.isNotEmpty(),
            )
            // Flow registry, per-flow detail, and review indicators are the protocol-level
            // deep-dive behind the plain "recent flows" list above. Collapsed by default so
            // the everyday view is not swamped by per-flow technical rows.
            SentinelExpandableSection(
                title = stringResource(R.string.flow_registry_title),
                summary = stringResource(R.string.flow_registry_body),
                chevron = painterResource(R.drawable.ic_chevron),
            ) {
                if (flowSnapshot.flows.isEmpty()) {
                    Text(stringResource(R.string.flow_registry_empty), style = MaterialTheme.typography.bodySmall)
                } else {
                    SentinelPagedList(items = flowSnapshot.flows.asReversed(), initialVisibleCount = 8) { flow ->
                        KeyValueRow(
                            label = stringResource(
                                R.string.flow_registry_row,
                                flow.key.protocol.name,
                                flow.direction.name,
                                flow.packetCount,
                                flow.observedBytes,
                            ),
                            value = flow.key.destination.port?.toString() ?: "-",
                        ) {
                            TextButton(onClick = { selectedFlowId = flow.id }) {
                                Text(stringResource(R.string.flow_registry_select))
                            }
                        }
                    }
                    flowSnapshot.droppedFlowCount.takeIf { it > 0L }?.let {
                        Text(stringResource(R.string.flow_registry_evicted, it), style = MaterialTheme.typography.bodySmall)
                    }
                }
                flowSnapshot.flows.firstOrNull { it.id == selectedFlowId }?.let { flow ->
                    FlowDetail(flow)
                }
                val reviewIndicators = NetworkReviewAnalyzer.indicators(
                    flows = flowSnapshot.flows,
                    events = recentEvents,
                    protocolEvidence = protocolSnapshot,
                )
                if (reviewIndicators.isNotEmpty()) {
                    Text(stringResource(R.string.flow_review_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(stringResource(R.string.flow_review_body), style = MaterialTheme.typography.bodySmall)
                    reviewIndicators.forEach { indicator ->
                        Text(
                            stringResource(NetworkUiTextMapper.reviewIndicator(indicator.code), indicator.count),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
        }
        AdvancedToolsCard(
            expanded = showAdvancedTools,
            onExpandedChange = { showAdvancedTools = it },
            sessionConfigurationLocked = sessionConfigurationLocked,
            payloadAdvancedEnabled = payloadAdvancedEnabled,
            onPayloadAdvancedEnabledChange = {
                payloadAdvancedEnabled = it
                if (!it) {
                    payloadDisclosureAccepted = false
                    clearPayloadReveal()
                }
            },
            payloadDisclosureAccepted = payloadDisclosureAccepted,
            onPayloadDisclosureChange = { payloadDisclosureAccepted = it },
            payloadSnapshot = payloadSnapshot,
            selectedPayloadRecordId = selectedPayloadRecordId,
            onSelectPayloadRecord = { selectedPayloadRecordId = it; clearPayloadReveal(); selectedPayloadRecordId = it },
            payloadRevealAcknowledged = payloadRevealAcknowledged,
            onPayloadRevealAcknowledgedChange = { payloadRevealAcknowledged = it },
            renderedPayload = renderedPayload,
            onPayloadReveal = {
                selectedPayloadRecordId?.let { recordId ->
                    val token = NetworkMonitorRuntime.issuePayloadRevealToken(
                        PayloadRevealAcknowledgement("payload-reveal-v1", System.currentTimeMillis()),
                    )
                    payloadRevealToken = token
                    renderedPayload = token?.let { NetworkMonitorRuntime.renderPayload(recordId, it, PayloadRenderFormat.TEXT) }
                    payloadRevealUnavailable = renderedPayload == null
                }
            },
            onPayloadRenderFormat = { format ->
                val recordId = selectedPayloadRecordId
                val token = payloadRevealToken
                if (recordId != null && token != null) {
                    renderedPayload = NetworkMonitorRuntime.renderPayload(recordId, token, format)
                    payloadRevealUnavailable = renderedPayload == null
                }
            },
            onPayloadHide = ::clearPayloadReveal,
            payloadRevealUnavailable = payloadRevealUnavailable,
            protocolEvidenceEnabled = protocolEvidenceEnabled,
            onProtocolEvidenceEnabledChange = {
                protocolEvidenceEnabled = it
                if (!it) protocolDisclosureAccepted = false
            },
            protocolDisclosureAccepted = protocolDisclosureAccepted,
            onProtocolDisclosureChange = { protocolDisclosureAccepted = it },
            protocolSniEnabled = protocolSniEnabled,
            onProtocolSniChange = { protocolSniEnabled = it },
            protocolHttpEnabled = protocolHttpEnabled,
            onProtocolHttpChange = { protocolHttpEnabled = it },
            protocolUrlEnabled = protocolUrlEnabled,
            onProtocolUrlChange = { protocolUrlEnabled = it },
            protocolSnapshot = protocolSnapshot,
            status = status.state,
            rawDisclosureAccepted = rawDisclosureAccepted,
            onRawDisclosureChange = { rawDisclosureAccepted = it },
            rawCaptureStatus = rawCaptureStatus,
            rawCaptureNotice = rawCaptureNotice.toRawCaptureUiNotice(),
            ownsRawDocument = AppRawPcapngDocumentCoordinator.ownsDocumentStream(),
            onChooseRawDocument = {
                rawCaptureNotice = RawCaptureUiNotice.NONE.name
                rawCaptureLauncher.launch(context.getString(R.string.raw_capture_document_name))
            },
            onStopRawCapture = {
                AppRawPcapngDocumentCoordinator.requestStopAndClose()
                rawCaptureNotice = RawCaptureUiNotice.STOPPING.name
                rawCaptureStatus = AppRawPcapngDocumentCoordinator.status()
            },
            flowSnapshot = flowSnapshot,
            flowExportNotice = flowExportNotice,
            onExportFlows = { flowExportLauncher.launch("apk-sentinel-network-flows.ndjson") },
            onExportFlowsJson = { flowJsonExportLauncher.launch("apk-sentinel-network-flows.json") },
            onExportFlowsCsv = { flowCsvExportLauncher.launch("apk-sentinel-network-flows.csv") },
            onExportFlowsXlsx = { flowXlsxExportLauncher.launch("apk-sentinel-network-flows.xlsx") },
        )
    }
}

@Composable
private fun CaptureLibraryCard(
    rows: List<CaptureDocumentRecord>,
    inspection: CaptureDocumentInspectionState?,
    notice: String?,
    catalogState: app.apksentinel.networkmonitor.CaptureMetadataPersistenceState,
    onOpen: () -> Unit,
    onRefresh: () -> Unit,
    onForget: (CaptureDocumentRecord) -> Unit,
) {
    SentinelExpandableSection(
        title = stringResource(R.string.capture_library_title),
        summary = stringResource(R.string.capture_library_summary),
        flat = true,
    ) {
        Text(stringResource(R.string.capture_library_body), style = MaterialTheme.typography.bodySmall)
        Button(onClick = onOpen, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.capture_open_document)) }
        FullWidthOutlinedAction(label = stringResource(R.string.capture_refresh), onClick = onRefresh)
        if (catalogState in setOf(
                app.apksentinel.networkmonitor.CaptureMetadataPersistenceState.UNAVAILABLE,
                app.apksentinel.networkmonitor.CaptureMetadataPersistenceState.CORRUPT,
                app.apksentinel.networkmonitor.CaptureMetadataPersistenceState.REJECTED,
            )
        ) Text(stringResource(R.string.capture_catalog_save_failed), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        if (rows.isEmpty()) Text(stringResource(R.string.capture_library_empty), style = MaterialTheme.typography.bodySmall)
        SentinelPagedList(items = rows.asReversed(), initialVisibleCount = 10) { row ->
            KeyValueRow(
                label = row.displayName,
                value = "${captureFormatLabel(row.format)} · ${row.measuredBytes ?: "?"} B · ${captureAvailabilityLabel(row.availability)}",
            ) {
                TextButton(onClick = { onForget(row) }) { Text(stringResource(R.string.capture_forget)) }
            }
        }
        inspection?.let { state ->
            if (state.busy) Text(stringResource(R.string.capture_inspecting), style = MaterialTheme.typography.bodySmall)
            state.result?.let { result ->
                when (result) {
                    is CaptureInspectionResult.Opened -> {
                        Text(stringResource(R.string.capture_inspection_opened, result.summary.packetCount, result.summary.observedBytes), style = MaterialTheme.typography.bodySmall)
                        if (result.summary.truncated || result.summary.limitations.isNotEmpty()) Text(stringResource(R.string.capture_inspection_incomplete), style = MaterialTheme.typography.bodySmall)
                    }
                    is CaptureInspectionResult.Rejected -> Text(stringResource(R.string.capture_inspection_rejected, captureFailureLabel(result.failure)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
            }
        }
        notice?.let { Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
        Text(stringResource(R.string.capture_privacy_note), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun captureFormatLabel(format: CaptureDocumentFormat): String = when (format) {
    CaptureDocumentFormat.PCAP -> stringResource(R.string.capture_format_pcap)
    CaptureDocumentFormat.PCAPNG -> stringResource(R.string.capture_format_pcapng)
    CaptureDocumentFormat.HAR -> stringResource(R.string.capture_format_har)
    CaptureDocumentFormat.UNKNOWN -> stringResource(R.string.capture_format_unknown)
}

@Composable
private fun captureAvailabilityLabel(value: app.apksentinel.networkmonitor.CaptureDocumentAvailability): String = when (value) {
    app.apksentinel.networkmonitor.CaptureDocumentAvailability.AVAILABLE -> stringResource(R.string.capture_available)
    app.apksentinel.networkmonitor.CaptureDocumentAvailability.MISSING -> stringResource(R.string.capture_missing)
    app.apksentinel.networkmonitor.CaptureDocumentAvailability.ACCESS_REVOKED -> stringResource(R.string.capture_access_revoked)
    app.apksentinel.networkmonitor.CaptureDocumentAvailability.UNKNOWN -> stringResource(R.string.capture_availability_unknown)
}

@Composable
private fun captureFailureLabel(value: CaptureInspectionFailure): String = stringResource(
    when (value) {
        CaptureInspectionFailure.ENCRYPTED_OR_OPAQUE -> R.string.capture_reason_encrypted
        CaptureInspectionFailure.UNKNOWN_FORMAT -> R.string.capture_reason_unsupported
        CaptureInspectionFailure.UNSUPPORTED_VERSION -> R.string.capture_reason_unsupported
        else -> R.string.capture_reason_invalid_or_truncated
    },
)

@Composable
private fun FlowDetail(flow: NetworkFlow) {
    Text(stringResource(R.string.flow_registry_detail_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
    val source = flow.key.source.let { if (it.port == null) it.address else "${it.address}:${it.port}" }
    val destination = flow.key.destination.let { if (it.port == null) it.address else "${it.address}:${it.port}" }
    KeyValueRow(stringResource(R.string.flow_registry_detail_endpoint, "$source → $destination"), "")
    KeyValueRow(
        stringResource(
            R.string.flow_registry_detail_attribution,
            if (flow.attribution is AppAttribution.Known) stringResource(R.string.flow_registry_known)
            else stringResource(R.string.flow_registry_unknown),
        ),
        "",
    )
    KeyValueRow(stringResource(R.string.flow_registry_detail_time, flow.startedAtMillis, flow.lastSeenAtMillis), "")
    Text(
        stringResource(
            when (flow.latestDnsName) {
                null, SafeDnsName.NotCaptured -> R.string.flow_registry_dns_not_captured
                is SafeDnsName.Hashed -> R.string.flow_registry_dns_hashed
                is SafeDnsName.PlaintextAfterExplicitConsent -> R.string.flow_registry_dns_plaintext_omitted
            },
        ),
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun AdvancedToolsCard(
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    sessionConfigurationLocked: Boolean,
    payloadAdvancedEnabled: Boolean,
    onPayloadAdvancedEnabledChange: (Boolean) -> Unit,
    payloadDisclosureAccepted: Boolean,
    onPayloadDisclosureChange: (Boolean) -> Unit,
    payloadSnapshot: PayloadInspectionSnapshot,
    selectedPayloadRecordId: Long?,
    onSelectPayloadRecord: (Long) -> Unit,
    payloadRevealAcknowledged: Boolean,
    onPayloadRevealAcknowledgedChange: (Boolean) -> Unit,
    renderedPayload: RenderedPayloadContent?,
    onPayloadReveal: () -> Unit,
    onPayloadRenderFormat: (PayloadRenderFormat) -> Unit,
    onPayloadHide: () -> Unit,
    payloadRevealUnavailable: Boolean,
    protocolEvidenceEnabled: Boolean,
    onProtocolEvidenceEnabledChange: (Boolean) -> Unit,
    protocolDisclosureAccepted: Boolean,
    onProtocolDisclosureChange: (Boolean) -> Unit,
    protocolSniEnabled: Boolean,
    onProtocolSniChange: (Boolean) -> Unit,
    protocolHttpEnabled: Boolean,
    onProtocolHttpChange: (Boolean) -> Unit,
    protocolUrlEnabled: Boolean,
    onProtocolUrlChange: (Boolean) -> Unit,
    protocolSnapshot: ProtocolEvidenceSnapshot,
    status: MonitorLifecycleState,
    rawDisclosureAccepted: Boolean,
    onRawDisclosureChange: (Boolean) -> Unit,
    rawCaptureStatus: RawPcapngCaptureStatus,
    rawCaptureNotice: RawCaptureUiNotice,
    ownsRawDocument: Boolean,
    onChooseRawDocument: () -> Unit,
    onStopRawCapture: () -> Unit,
    flowSnapshot: FlowRegistrySnapshot,
    flowExportNotice: String?,
    onExportFlows: () -> Unit,
    onExportFlowsJson: () -> Unit,
    onExportFlowsCsv: () -> Unit,
    onExportFlowsXlsx: () -> Unit,
) {
    SentinelCard {
        Text(stringResource(R.string.protocol_advanced_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.protocol_advanced_body), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.protocol_advanced_title),
            description = stringResource(if (expanded) R.string.protocol_advanced_shown else R.string.protocol_advanced_hidden),
            checked = expanded,
            onCheckedChange = onExpandedChange,
            onStateLabel = stringResource(R.string.protocol_advanced_shown),
            offStateLabel = stringResource(R.string.protocol_advanced_hidden),
        )
        // Saving the observed flows is a primary action, not an advanced tool, so it
        // sits before the Advanced switch rather than three steps behind it.
        SentinelCard {
            Text(stringResource(R.string.protocol_export_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.protocol_export_body), style = MaterialTheme.typography.bodySmall)
            Text(
                stringResource(R.string.protocol_export_preview, flowSnapshot.flows.size, flowSnapshot.droppedFlowCount),
                style = MaterialTheme.typography.bodySmall,
            )
            Button(
                onClick = onExportFlows,
                enabled = flowSnapshot.flows.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.protocol_export_choose)) }
            FullWidthOutlinedAction(
                label = stringResource(R.string.protocol_export_choose_csv),
                onClick = onExportFlowsCsv,
                enabled = flowSnapshot.flows.isNotEmpty(),
            )
            FullWidthOutlinedAction(
                label = stringResource(R.string.protocol_export_choose_xlsx),
                onClick = onExportFlowsXlsx,
                enabled = flowSnapshot.flows.isNotEmpty(),
            )
            FullWidthOutlinedAction(
                label = stringResource(R.string.protocol_export_choose_json),
                onClick = onExportFlowsJson,
                enabled = flowSnapshot.flows.isNotEmpty(),
            )
            if (flowSnapshot.flows.isEmpty()) Text(stringResource(R.string.protocol_export_unavailable), style = MaterialTheme.typography.bodySmall)
            flowExportNotice?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }

        if (!expanded) return@SentinelCard

        // Grouped by what the user is trying to do, and collapsed by default. Previously
        // seven technical cards sat at one level, so a reader met every advanced route at
        // once with nothing indicating which mattered to them.
        val inspectIcon = painterResource(R.drawable.ic_section_inspect)
        val exportIcon = painterResource(R.drawable.ic_section_export)
        val advancedIcon = painterResource(R.drawable.ic_section_advanced)
        val sectionChevron = painterResource(R.drawable.ic_chevron)

        SentinelExpandableSection(
            title = stringResource(R.string.network_group_inspect_title),
            summary = stringResource(R.string.network_group_inspect_summary),
            icon = inspectIcon,
            chevron = sectionChevron,
        ) {
        ProtocolEvidenceCard(
            enabled = protocolEvidenceEnabled,
            onEnabledChange = onProtocolEvidenceEnabledChange,
            consentAccepted = protocolDisclosureAccepted,
            onConsentChange = onProtocolDisclosureChange,
            sniEnabled = protocolSniEnabled,
            onSniChange = onProtocolSniChange,
            httpEnabled = protocolHttpEnabled,
            onHttpChange = onProtocolHttpChange,
            urlEnabled = protocolUrlEnabled,
            onUrlChange = onProtocolUrlChange,
            snapshot = protocolSnapshot,
            monitorState = status,
            sessionConfigurationLocked = sessionConfigurationLocked,
        )
        PayloadInspectionCard(
            advancedEnabled = payloadAdvancedEnabled,
            onAdvancedEnabledChange = onPayloadAdvancedEnabledChange,
            sessionConsentAccepted = payloadDisclosureAccepted,
            onSessionConsentChange = onPayloadDisclosureChange,
            snapshot = payloadSnapshot,
            selectedRecordId = selectedPayloadRecordId,
            onSelectRecord = onSelectPayloadRecord,
            revealAcknowledged = payloadRevealAcknowledged,
            onRevealAcknowledgedChange = onPayloadRevealAcknowledgedChange,
            rendered = renderedPayload,
            onReveal = onPayloadReveal,
            onRenderFormat = onPayloadRenderFormat,
            onHide = onPayloadHide,
            revealUnavailable = payloadRevealUnavailable,
            sessionConfigurationLocked = sessionConfigurationLocked,
        )
        DomainDestinationsCard()
        }

        SentinelExpandableSection(
            title = stringResource(R.string.network_group_export_title),
            summary = stringResource(R.string.network_group_export_summary),
            icon = exportIcon,
            chevron = sectionChevron,
        ) {
        HarExportAvailabilityCard(protocolSnapshot, protocolUrlEnabled)
        RawPcapngCaptureCard(
            monitorActive = status == MonitorLifecycleState.ACTIVE,
            exportAvailable = rawPcapngExportAvailable(NetworkMonitorRuntime.currentStatus()),
            disclosureAccepted = rawDisclosureAccepted,
            onDisclosureChanged = onRawDisclosureChange,
            captureStatus = rawCaptureStatus,
            ownsDocumentStream = ownsRawDocument,
            notice = rawCaptureNotice,
            onChooseDocument = onChooseRawDocument,
            onStopCapture = onStopRawCapture,
        )
        }

        SentinelExpandableSection(
            title = stringResource(R.string.network_group_advanced_title),
            summary = stringResource(R.string.network_group_advanced_summary),
            icon = advancedIcon,
            chevron = sectionChevron,
        ) {
            TlsInspectionCard()
            RootCaptureCard()
            RemoteStreamAdvancedCard(monitorActive = status == MonitorLifecycleState.ACTIVE)
        }
    }
}

/**
 * Surfaces DomainCollector's destination groups.
 *
 * The collector was built and tested and had no caller, which made the "domain collector
 * destinations" capability real in the engine and invisible to the user.
 */
@Composable
private fun DomainDestinationsCard() {
    val groups = DomainCollector.let { collector ->
        val registry = NetworkMonitorRuntime.currentDomainBindings()
        val handling = NetworkMonitorRuntime.currentDnsNameHandling()
        if (registry == null || handling == null) {
            emptyList()
        } else {
            collector.collect(registry, handling, atMillis = System.currentTimeMillis())
        }
    }
    SentinelCard {
        Text(stringResource(R.string.destinations_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.destinations_body), style = MaterialTheme.typography.bodySmall)
        if (groups.isEmpty()) {
            Text(stringResource(R.string.destinations_empty), style = MaterialTheme.typography.bodySmall)
        } else {
            SentinelPagedList(items = groups, initialVisibleCount = 10) { group ->
                KeyValueRow(
                    label = group.displayName?.let {
                        stringResource(R.string.destinations_named, it, group.addresses.size)
                    } ?: stringResource(R.string.destinations_unnamed, group.addresses.size),
                    value = if (group.freshnessSeconds > 0) stringResource(R.string.destinations_fresh) else "",
                )
                group.addresses.forEach { address ->
                    Text(address, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun HarExportAvailabilityCard(
    protocolSnapshot: ProtocolEvidenceSnapshot,
    urlCaptureEnabled: Boolean,
) {
    val context = LocalContext.current
    var status by rememberSaveable { mutableStateOf<String?>(null) }
    val entries = remember(protocolSnapshot) {
        ProtocolEvidenceHarBridge.toPayloadObservations(protocolSnapshot.observations)
    }
    val saver = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        if (uri == null) {
            status = context.getString(R.string.har_export_cancelled)
        } else {
            val written = SafeDocumentWriter.useOutputStream(context, uri) { output ->
                SafeHarExporter.write(entries, output)
            }
            status = context.getString(
                if (written != null) R.string.har_export_saved else R.string.har_export_failed,
            )
        }
    }
    SentinelCard {
        Text(stringResource(R.string.har_export_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.har_export_body), style = MaterialTheme.typography.bodySmall)
        when {
            // The exporter needs a URL, and only the request-target consent produces one.
            !urlCaptureEnabled ->
                Text(stringResource(R.string.har_export_needs_urls), style = MaterialTheme.typography.bodySmall)
            entries.isEmpty() ->
                Text(stringResource(R.string.har_export_unavailable), style = MaterialTheme.typography.bodySmall)
            else -> {
                SentinelStatusLabel(
                    label = stringResource(R.string.har_export_available, entries.size),
                    tone = SentinelStatusTone.INFORMATION,
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.har_export_action),
                    onClick = { saver.launch("apk-sentinel-requests.har") },
                )
            }
        }
        Text(stringResource(R.string.har_export_no_claim), style = MaterialTheme.typography.bodySmall)
        status?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}

@Composable
private fun ProtocolEvidenceCard(
    enabled: Boolean,
    onEnabledChange: (Boolean) -> Unit,
    consentAccepted: Boolean,
    onConsentChange: (Boolean) -> Unit,
    sniEnabled: Boolean,
    onSniChange: (Boolean) -> Unit,
    httpEnabled: Boolean,
    onHttpChange: (Boolean) -> Unit,
    urlEnabled: Boolean,
    onUrlChange: (Boolean) -> Unit,
    snapshot: ProtocolEvidenceSnapshot,
    monitorState: MonitorLifecycleState,
    sessionConfigurationLocked: Boolean,
) {
    SentinelCard {
        Text(stringResource(R.string.protocol_evidence_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.protocol_evidence_body), style = MaterialTheme.typography.bodySmall)
        if (sessionConfigurationLocked) Text(stringResource(R.string.network_session_option_next_session), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.protocol_evidence_title),
            description = stringResource(if (enabled) R.string.protocol_evidence_consent_accepted else R.string.protocol_evidence_consent_not_accepted),
            checked = enabled,
            onCheckedChange = onEnabledChange,
            enabled = !sessionConfigurationLocked,
        )
        if (enabled) {
            SentinelToggleRow(
                title = stringResource(R.string.protocol_evidence_consent_title),
                description = stringResource(R.string.protocol_evidence_consent_body),
                checked = consentAccepted,
                onCheckedChange = onConsentChange,
                enabled = !sessionConfigurationLocked,
            )
            SentinelToggleRow(
                title = stringResource(R.string.protocol_evidence_sni_title),
                description = stringResource(R.string.protocol_evidence_sni_body),
                checked = sniEnabled,
                onCheckedChange = onSniChange,
                enabled = !sessionConfigurationLocked,
            )
            SentinelToggleRow(
                title = stringResource(R.string.protocol_evidence_http_title),
                description = stringResource(R.string.protocol_evidence_http_body),
                checked = httpEnabled,
                onCheckedChange = onHttpChange,
                enabled = !sessionConfigurationLocked,
            )
            if (httpEnabled) {
                SentinelToggleRow(
                    title = stringResource(R.string.protocol_evidence_url_title),
                    description = stringResource(R.string.protocol_evidence_url_body),
                    checked = urlEnabled,
                    onCheckedChange = onUrlChange,
                    enabled = !sessionConfigurationLocked,
                )
            }
        }
        if (monitorState != MonitorLifecycleState.ACTIVE || !consentAccepted || !enabled) {
            Text(stringResource(R.string.protocol_evidence_unavailable), style = MaterialTheme.typography.bodySmall)
        }
        if (snapshot.observations.isEmpty()) {
            Text(stringResource(R.string.protocol_evidence_no_observations), style = MaterialTheme.typography.bodySmall)
        } else {
            snapshot.observations.forEach { observation ->
                ProtocolObservation(observation)
            }
        }
        if (snapshot.droppedObservations > 0L) {
            Text(stringResource(R.string.protocol_evidence_dropped, snapshot.droppedObservations), style = MaterialTheme.typography.bodySmall)
        }
        snapshot.sessionLimitations.forEach { limitation ->
            Text(stringResource(R.string.protocol_evidence_limitation, stringResource(NetworkUiTextMapper.protocolLimitation(limitation))), style = MaterialTheme.typography.bodySmall)
        }
        Text(stringResource(R.string.protocol_technical_limits), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ProtocolObservation(observation: ProtocolEvidenceObservation) {
    Text(
        stringResource(
            R.string.protocol_evidence_observation,
            stringResource(NetworkUiTextMapper.protocolSource(observation.source)),
            when (observation.direction) {
                PacketDirection.OUTBOUND -> stringResource(R.string.protocol_evidence_direction_outbound)
                PacketDirection.INBOUND -> stringResource(R.string.protocol_evidence_direction_inbound)
                PacketDirection.UNKNOWN -> stringResource(R.string.protocol_evidence_direction_unknown)
            },
            observation.observedAtMillis,
            stringResource(NetworkUiTextMapper.protocolConfidence(observation.confidence)),
        ),
        style = MaterialTheme.typography.bodySmall,
    )
    observation.value?.let { value ->
        Text(
            when (value) {
                is ProtocolEvidenceValue.TlsServerName -> stringResource(R.string.protocol_evidence_sni_value, value.hostname)
                is ProtocolEvidenceValue.HttpRequest -> stringResource(R.string.protocol_evidence_http_request_value, value.method, value.version)
                is ProtocolEvidenceValue.HttpResponse -> stringResource(R.string.protocol_evidence_http_response_value, value.statusCode, value.version)
            },
            style = MaterialTheme.typography.bodySmall,
        )
    }
    observation.limitations.forEach { limitation ->
        Text(stringResource(R.string.protocol_evidence_limitation, stringResource(NetworkUiTextMapper.protocolLimitation(limitation))), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun FirewallPolicyCard(
    ipRuleText: String,
    onIpRuleTextChange: (String) -> Unit,
    protocolRuleText: String,
    onProtocolRuleTextChange: (String) -> Unit,
    portRuleText: String,
    onPortRuleTextChange: (String) -> Unit,
    domainRuleText: String,
    onDomainRuleTextChange: (String) -> Unit,
    appRuleText: String,
    onAppRuleTextChange: (String) -> Unit,
    snapshot: FirewallPolicySnapshot?,
    undo: FirewallPolicyUndoToken?,
    onMutation: (String, FirewallPolicyUndoToken?) -> Unit,
) {
    val context = LocalContext.current
    val controller = FirewallPolicyComposition.controller()
    SentinelCard {
        Text(stringResource(R.string.network_firewall_rules), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.network_firewall_policy_simple), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.network_firewall_policy_limitations), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(
            value = ipRuleText,
            onValueChange = onIpRuleTextChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.network_destination_ip_cidr)) },
            supportingText = { Text(stringResource(R.string.network_destination_ip_cidr_hint)) },
            singleLine = true,
        )
        OutlinedTextField(
            value = appRuleText,
            onValueChange = onAppRuleTextChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.network_rule_app_packages)) },
            supportingText = { Text(stringResource(R.string.network_rule_app_packages_hint)) },
            singleLine = true,
        )
        // Disabled rather than merely discouraged: a domain rule saved from this field could
        // never actually match (see network_rule_domain_unavailable), and a security control
        // must never let the user believe a rule is in effect when it is not.
        OutlinedTextField(
            value = domainRuleText,
            onValueChange = onDomainRuleTextChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.network_rule_domain)) },
            supportingText = { Text(stringResource(R.string.network_rule_domain_unavailable)) },
            singleLine = true,
            enabled = false,
        )
        OutlinedTextField(
            value = protocolRuleText,
            onValueChange = onProtocolRuleTextChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.network_rule_protocol)) },
            supportingText = { Text(stringResource(R.string.network_rule_protocol_hint)) },
            singleLine = true,
        )
        OutlinedTextField(
            value = portRuleText,
            onValueChange = onPortRuleTextChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.network_rule_port)) },
            supportingText = { Text(stringResource(R.string.network_rule_port_hint)) },
            singleLine = true,
        )
        val addRule: (FirewallPolicyAction, Long?) -> Unit = { action, expiresAt ->
            val normalized = ipRuleText.trim().let { value ->
                when {
                    '/' in value -> value
                    ':' in value -> "$value/128"
                    else -> "$value/32"
                }
            }
            val cidr = IpCidr.parse(normalized)
            when {
                cidr == null -> onMutation(context.getString(R.string.network_invalid_destination_rule), null)
                controller == null -> onMutation(context.getString(R.string.network_firewall_policy_unavailable), null)
                else -> {
                    val result = controller.upsert(
                        FirewallPolicyRuleDraft(
                            id = "ip-${System.currentTimeMillis()}",
                            action = action,
                            destinationCidrs = setOf(cidr.toString()),
                            expiresAtMillis = expiresAt,
                        ),
                    )
                    onMutation(
                        context.getString(if (result.code == FirewallPolicyMutationCode.APPLIED) R.string.network_firewall_policy_saved else R.string.network_firewall_policy_not_saved),
                        result.undoToken,
                    )
                }
            }
        }
        val addNarrowException = {
            // Domain destinations are deliberately excluded here: the field above is disabled
            // because a domain rule created from scratch cannot yet be guaranteed to match, and
            // this control must never report a save as successful when it will not take effect.
            val packages = appRuleText.split(',', ';').map(String::trim).filter(String::isNotBlank).toSet()
            val protocols = protocolRuleText.trim().uppercase().takeIf(String::isNotBlank)?.let {
                runCatching { setOf(TransportProtocol.valueOf(it)) }.getOrNull()
            }
            val ports = parsePortRange(portRuleText)
            val result = when {
                controller == null -> null
                packages.any { !isValidNetworkPackage(it) } || protocols == null && protocolRuleText.isNotBlank() || portRuleText.isNotBlank() && ports == null -> null
                else -> controller.upsert(
                    FirewallPolicyRuleDraft(
                        id = "exception-${System.currentTimeMillis()}",
                        action = FirewallPolicyAction.ALLOW,
                        appPackageNames = packages,
                        protocols = protocols.orEmpty(),
                        destinationPortRange = ports,
                    ),
                )
            }
            onMutation(
                context.getString(if (result?.code == FirewallPolicyMutationCode.APPLIED) R.string.network_narrow_exception_saved else R.string.network_narrow_exception_not_saved),
                result?.undoToken,
            )
        }
        FullWidthOutlinedAction(
            label = stringResource(R.string.network_add_narrow_exception),
            enabled = appRuleText.isNotBlank() || protocolRuleText.isNotBlank() || portRuleText.isNotBlank(),
            onClick = addNarrowException,
        )
        Button(
            onClick = { addRule(FirewallPolicyAction.BLOCK, null) },
            enabled = ipRuleText.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.network_add_destination_block_rule)) }
        FullWidthOutlinedAction(
            label = stringResource(R.string.network_firewall_policy_temporary_allow),
            enabled = ipRuleText.isNotBlank(),
            onClick = { addRule(FirewallPolicyAction.ALLOW, System.currentTimeMillis() + TEMPORARY_ALLOW_MILLIS) },
        )
        Text(stringResource(R.string.network_firewall_policy_temporary_allow_hint), style = MaterialTheme.typography.bodySmall)
        if (snapshot?.emergencyReleaseActive == true) {
            FullWidthOutlinedAction(
                label = stringResource(R.string.network_firewall_policy_restore),
                onClick = {
                    val result = controller?.clearEmergencyRelease()
                    onMutation(
                        context.getString(if (result?.code == FirewallPolicyMutationCode.APPLIED) R.string.network_firewall_policy_restored else R.string.network_firewall_policy_not_saved),
                        result?.undoToken,
                    )
                },
            )
        } else {
            FullWidthOutlinedAction(
                label = stringResource(R.string.network_firewall_policy_emergency_release),
                onClick = {
                    val result = controller?.emergencyRelease()
                    onMutation(
                        context.getString(if (result?.code == FirewallPolicyMutationCode.APPLIED) R.string.network_firewall_policy_released else R.string.network_firewall_policy_not_saved),
                        result?.undoToken,
                    )
                },
            )
        }
        undo?.let { token ->
            TextButton(onClick = {
                val result = controller?.undo(token)
                onMutation(
                    context.getString(if (result?.code == FirewallPolicyMutationCode.APPLIED) R.string.network_firewall_policy_undone else R.string.network_firewall_policy_undo_unavailable),
                    null,
                )
            }) { Text(stringResource(R.string.network_firewall_policy_undo)) }
        }
        snapshot?.rules?.zip(snapshot.statuses).orEmpty().forEach { (rule, state) ->
            val target = rule.destinationCidrs.joinToString().ifBlank { stringResource(R.string.network_unsupported_rule_type) }
            // A domain rule is only enforceable while this session has actually observed the
            // name resolve. Saying which of those it is beats a rule that silently never fires.
            val domainState = if (rule.domainNames.isEmpty()) {
                null
            } else {
                when (val resolution = DomainDestinationSecurity.resolveForPolicy(rule, ObservedDomainReceivers.current())) {
                    is DomainDestinationResolution.Resolved ->
                        stringResource(R.string.firewall_domain_bound, resolution.addresses.size) to SentinelStatusTone.GOOD
                    is DomainDestinationResolution.Unavailable -> when (resolution.reason) {
                        DomainDestinationUnavailableReason.AUTHENTICATED_RECEIVER_CONTRACT_MISSING ->
                            stringResource(R.string.firewall_domain_no_session) to SentinelStatusTone.NEUTRAL
                        DomainDestinationUnavailableReason.DNS_PIN_NOT_BOUND_TO_OBSERVED_FLOW,
                        DomainDestinationUnavailableReason.RESOLUTION_FAILED ->
                            stringResource(R.string.firewall_domain_unbound) to SentinelStatusTone.REVIEW
                    }
                }
            }
            val ruleDisplay = "${stringResource(firewallPolicyActionText(rule.action))} · $target"
            domainState?.let { (label, tone) -> SentinelStatusLabel(label = label, tone = tone) }
            KeyValueRow(
                label = ruleDisplay,
                value = stringResource(
                    R.string.network_firewall_policy_state,
                    stringResource(if (state.saved.name == "SAVED") R.string.network_firewall_policy_saved_short else R.string.network_firewall_policy_not_saved_short),
                    stringResource(if (state.enabled) R.string.network_firewall_policy_enabled else R.string.network_firewall_policy_disabled),
                    stringResource(if (state.active) R.string.network_firewall_policy_active else R.string.network_firewall_policy_limited),
                    state.confirmedHitCount,
                ),
            ) {
                TextButton(onClick = {
                    val result = controller?.upsert(rule.toDraft(enabled = !state.enabled))
                    onMutation(
                        context.getString(if (result?.code == FirewallPolicyMutationCode.APPLIED) R.string.network_firewall_policy_saved else R.string.network_firewall_policy_not_saved),
                        result?.undoToken,
                    )
                }) { Text(stringResource(if (state.enabled) R.string.network_firewall_policy_disable else R.string.network_firewall_policy_enable)) }
                TextButton(onClick = {
                    val result = controller?.remove(rule.id)
                    onMutation(
                        context.getString(if (result?.code == FirewallPolicyMutationCode.APPLIED) R.string.network_rule_removed else R.string.network_firewall_policy_not_saved),
                        result?.undoToken,
                    )
                }) { Text(stringResource(R.string.network_remove_rule)) }
            }
            if (state.limitations.isNotEmpty()) Text(stringResource(R.string.network_firewall_policy_limited_explainer), style = MaterialTheme.typography.bodySmall)
        }
        if (snapshot?.rules.isNullOrEmpty()) Text(stringResource(R.string.network_firewall_policy_none), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.network_firewall_policy_exact_evidence), style = MaterialTheme.typography.bodySmall)
    }
}

private fun FirewallPolicyRule.toDraft(enabled: Boolean) = FirewallPolicyRuleDraft(
    id = id,
    action = action,
    priority = priority,
    enabled = enabled,
    appUids = appUids,
    appPackageNames = appPackageNames,
    destinationCidrs = destinationCidrs.mapTo(linkedSetOf()) { it.toString() },
    domainNames = domainNames,
    protocols = protocols,
    destinationPortRange = destinationPortRange,
    expiresAtMillis = expiresAtMillis,
    unsupportedScopes = unsupportedScopes,
    safetyMode = safetyMode,
)

private fun firewallPolicyActionText(action: FirewallPolicyAction): Int = when (action) {
    FirewallPolicyAction.ALLOW -> R.string.network_firewall_policy_action_allow
    FirewallPolicyAction.BLOCK -> R.string.network_firewall_policy_action_block
}

private const val TEMPORARY_ALLOW_MILLIS = 5 * 60 * 1_000L

private fun readBoundedSettingsBytes(input: java.io.InputStream): ByteArray? {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(8 * 1_024)
    var total = 0
    while (true) {
        val count = input.read(buffer)
        if (count < 0) return output.toByteArray()
        if (count == 0) continue
        total += count
        if (total > 512 * 1_024) return null
        output.write(buffer, 0, count)
    }
}

private fun parsePortRange(value: String): IntRange? {
    if (value.isBlank()) return null
    val pieces = value.split('-', ':')
    if (pieces.size !in 1..2) return null
    val first = pieces[0].toIntOrNull() ?: return null
    val last = pieces.getOrNull(1)?.toIntOrNull() ?: first
    return first.takeIf { it in 1..65_535 }?.let { start -> last.takeIf { it in start..65_535 }?.let { start..it } }
}

private fun isValidNetworkPackage(value: String): Boolean = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+").matches(value)

private fun rawPcapngEvidenceLimits() = RawPcapngCaptureLimits(
    maximumDurationMillis = 60_000L,
    maximumPackets = 5_000L,
    maximumCapturedBytes = 20L * 1_024L * 1_024L,
    perPacketSnaplen = 65_535,
    queueCapacity = 128,
)

/** Deliberately isolated, non-persistent PC05 surface. It never offers copy, save, share, or export. */
@Composable
private fun PayloadInspectionCard(
    advancedEnabled: Boolean,
    onAdvancedEnabledChange: (Boolean) -> Unit,
    sessionConsentAccepted: Boolean,
    onSessionConsentChange: (Boolean) -> Unit,
    snapshot: PayloadInspectionSnapshot,
    selectedRecordId: Long?,
    onSelectRecord: (Long) -> Unit,
    revealAcknowledged: Boolean,
    onRevealAcknowledgedChange: (Boolean) -> Unit,
    rendered: RenderedPayloadContent?,
    onReveal: () -> Unit,
    onRenderFormat: (PayloadRenderFormat) -> Unit,
    onHide: () -> Unit,
    revealUnavailable: Boolean,
    sessionConfigurationLocked: Boolean,
) {
    SentinelCard {
        Text(stringResource(R.string.payload_advanced_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.payload_advanced_summary), style = MaterialTheme.typography.bodySmall)
        if (sessionConfigurationLocked) Text(stringResource(R.string.network_session_option_next_session), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.payload_advanced_enable),
            description = stringResource(if (advancedEnabled) R.string.payload_advanced_enabled else R.string.payload_advanced_disabled),
            checked = advancedEnabled,
            onCheckedChange = onAdvancedEnabledChange,
            enabled = !sessionConfigurationLocked,
        )
        if (!advancedEnabled) return@SentinelCard
        Text(stringResource(R.string.payload_disclosure), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.payload_limits), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.payload_session_ack),
            description = stringResource(if (sessionConsentAccepted) R.string.payload_session_acknowledged else R.string.payload_session_not_acknowledged),
            checked = sessionConsentAccepted,
            onCheckedChange = onSessionConsentChange,
            enabled = !sessionConfigurationLocked,
        )
        Text(stringResource(R.string.payload_status_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        SentinelStatusLabel(
            label = stringResource(NetworkUiTextMapper.payloadState(snapshot.state)),
            tone = when (snapshot.state) {
                PayloadInspectionState.RUNNING -> SentinelStatusTone.INFORMATION
                PayloadInspectionState.FAILED -> SentinelStatusTone.URGENT
                PayloadInspectionState.EXPIRED -> SentinelStatusTone.REVIEW
                PayloadInspectionState.DISABLED, PayloadInspectionState.STOPPED -> SentinelStatusTone.NEUTRAL
            },
        )
        KeyValueRow(stringResource(R.string.payload_records_label), snapshot.acceptedRecords.toString())
        KeyValueRow(stringResource(R.string.payload_bytes_label), snapshot.retainedBytes.toString())
        KeyValueRow(stringResource(R.string.payload_drops_label), payloadDropTotal(snapshot).toString())
        snapshot.failureReason?.let { reason ->
            Text(stringResource(NetworkUiTextMapper.payloadFailure(reason)), color = MaterialTheme.colorScheme.error)
        }
        snapshot.drops.forEach { (reason, count) ->
            KeyValueRow(stringResource(NetworkUiTextMapper.payloadDrop(reason)), count.toString())
        }
        snapshot.limitations.forEach { limitation ->
            Text(stringResource(NetworkUiTextMapper.payloadLimitation(limitation)), style = MaterialTheme.typography.bodySmall)
        }
        if (snapshot.records.isEmpty()) {
            Text(stringResource(R.string.payload_no_records), style = MaterialTheme.typography.bodySmall)
        } else {
            snapshot.records.forEach { record ->
                KeyValueRow(
                    stringResource(R.string.payload_record_label, record.id),
                    stringResource(
                        R.string.payload_record_metadata,
                        historyDirectionText(record.direction),
                        stringResource(NetworkUiTextMapper.payloadTransport(record.transport)),
                        record.retainedBytes,
                        record.observedBytes,
                    ),
                ) {
                    TextButton(onClick = { onSelectRecord(record.id) }) {
                        Text(stringResource(R.string.payload_select_record))
                    }
                }
                if (record.redactionApplied) Text(stringResource(R.string.payload_record_redacted), style = MaterialTheme.typography.bodySmall)
                if (record.wasTruncated) Text(stringResource(R.string.payload_record_truncated), style = MaterialTheme.typography.bodySmall)
                if (record.malformedUtf8WasRedacted) Text(stringResource(R.string.payload_record_malformed), style = MaterialTheme.typography.bodySmall)
            }
        }
        selectedRecordId?.let { recordId ->
            Text(stringResource(R.string.payload_selected_record, recordId), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.payload_reveal_warning), style = MaterialTheme.typography.bodySmall)
            SentinelToggleRow(
                title = stringResource(R.string.payload_reveal_ack),
                description = stringResource(if (revealAcknowledged) R.string.payload_reveal_acknowledged else R.string.payload_reveal_not_acknowledged),
                checked = revealAcknowledged,
                onCheckedChange = onRevealAcknowledgedChange,
            )
            Button(
                onClick = onReveal,
                enabled = revealAcknowledged && snapshot.state == PayloadInspectionState.RUNNING,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(stringResource(R.string.payload_reveal_action)) }
            // The toggle above explains an unaccepted acknowledgement, but a capture that
            // has since stopped, failed, or expired disables this button with no other
            // signal near it.
            if (snapshot.state != PayloadInspectionState.RUNNING) {
                Text(
                    stringResource(R.string.payload_reveal_needs_running),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (revealUnavailable) Text(stringResource(R.string.payload_reveal_unavailable), color = MaterialTheme.colorScheme.error)
        }
        rendered?.let { content ->
            Text(
                stringResource(R.string.payload_render_title, stringResource(NetworkUiTextMapper.payloadFormat(content.format))),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
            if (content.redactionApplied) Text(stringResource(R.string.payload_render_redaction), style = MaterialTheme.typography.bodySmall)
            Text(content.content, style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(label = stringResource(R.string.payload_render_text), onClick = { onRenderFormat(PayloadRenderFormat.TEXT) })
            FullWidthOutlinedAction(label = stringResource(R.string.payload_render_hex), onClick = { onRenderFormat(PayloadRenderFormat.HEX) })
            FullWidthOutlinedAction(label = stringResource(R.string.payload_hide), onClick = onHide)
        }
    }
}

private fun payloadDropTotal(snapshot: PayloadInspectionSnapshot): Long = snapshot.drops.values.fold(0L) { total, count ->
    if (count > Long.MAX_VALUE - total) Long.MAX_VALUE else total + count
}

@Composable
private fun historyPolicyText(policy: DurableHistoryRetentionPolicy): String = stringResource(when (policy) {
    DurableHistoryRetentionPolicy.SESSION_ONLY -> R.string.history_session
    DurableHistoryRetentionPolicy.ONE_DAY -> R.string.history_one_day
    DurableHistoryRetentionPolicy.SEVEN_DAYS -> R.string.history_seven_days
    DurableHistoryRetentionPolicy.THIRTY_DAYS -> R.string.history_thirty_days
})

@Composable
private fun historyRecordText(record: app.apksentinel.networkmonitor.DurableHistoryRecord): String = when (record) {
    is app.apksentinel.networkmonitor.DurableHistoryRecord.Packet -> stringResource(
        R.string.history_record_packet,
        historyDirectionText(record.direction),
        stringResource(NetworkUiTextMapper.transport(record.transport)),
        record.observedCount,
    )
    is app.apksentinel.networkmonitor.DurableHistoryRecord.MonitorState -> stringResource(
        R.string.history_record_monitor_state,
        stringResource(NetworkUiTextMapper.text(NetworkUiText.forLifecycle(record.state).code)),
    )
    is app.apksentinel.networkmonitor.DurableHistoryRecord.FirewallDecision -> stringResource(
        R.string.history_record_firewall,
        stringResource(NetworkUiTextMapper.firewallAction(record.requestedAction)),
    )
    is app.apksentinel.networkmonitor.DurableHistoryRecord.PacketParseFailure -> stringResource(
        R.string.history_record_parse,
        stringResource(NetworkUiTextMapper.parseFailure(record.code)),
    )
    is app.apksentinel.networkmonitor.DurableHistoryRecord.Limitation -> stringResource(
        R.string.history_record_limitation,
        stringResource(NetworkUiTextMapper.limitation(record.code)),
    )
    is app.apksentinel.networkmonitor.DurableHistoryRecord.Enforcement -> stringResource(
        R.string.history_record_enforcement,
        stringResource(NetworkUiTextMapper.firewallOutcome(record.outcome)),
    )
}

@Composable
private fun historyDirectionText(direction: PacketDirection): String = stringResource(when (direction) {
    PacketDirection.OUTBOUND -> R.string.history_direction_outbound
    PacketDirection.INBOUND -> R.string.history_direction_inbound
    PacketDirection.UNKNOWN -> R.string.history_direction_unknown
})

private fun networkFilterFailureText(reason: NetworkFilterParseFailure): Int = when (reason) {
    NetworkFilterParseFailure.TOO_LONG -> R.string.network_filter_too_long
    NetworkFilterParseFailure.TOO_MANY_TERMS -> R.string.network_filter_too_many_terms
    NetworkFilterParseFailure.UNKNOWN_TERM -> R.string.network_filter_unknown_term
    NetworkFilterParseFailure.DUPLICATE_TERM -> R.string.network_filter_duplicate_term
}

private fun rawPcapngExportAvailable(status: app.apksentinel.networkmonitor.NetworkMonitorStatus): Boolean =
    status.state == MonitorLifecycleState.ACTIVE &&
        status.capabilities?.reportFor(MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT)?.availability in setOf(
            CapabilityAvailability.LIMITED,
            CapabilityAvailability.AVAILABLE,
        )

private enum class RawCaptureUiNotice {
    NONE,
    DOCUMENT_CANCELLED,
    DOCUMENT_OPEN_FAILED,
    DOCUMENT_CLOSE_FAILED,
    NOT_AVAILABLE,
    STARTED,
    STOPPING,
    STOPPED,
    REJECTED_ALREADY_ACTIVE,
    REJECTED_CLOCK_UNAVAILABLE,
    REJECTED_INVALID_START_TIME,
    REJECTED_WRITER_START_FAILED;

    companion object {
        fun from(reason: RawPcapngCaptureStartRejection): RawCaptureUiNotice = when (reason) {
            RawPcapngCaptureStartRejection.ALREADY_ACTIVE -> REJECTED_ALREADY_ACTIVE
            RawPcapngCaptureStartRejection.CLOCK_UNAVAILABLE -> REJECTED_CLOCK_UNAVAILABLE
            RawPcapngCaptureStartRejection.INVALID_START_TIME -> REJECTED_INVALID_START_TIME
            RawPcapngCaptureStartRejection.WRITER_START_FAILED -> REJECTED_WRITER_START_FAILED
        }
    }
}

private fun String.toRawCaptureUiNotice(): RawCaptureUiNotice =
    runCatching { RawCaptureUiNotice.valueOf(this) }.getOrDefault(RawCaptureUiNotice.NONE)

@Composable
private fun RawPcapngCaptureCard(
    monitorActive: Boolean,
    exportAvailable: Boolean,
    disclosureAccepted: Boolean,
    onDisclosureChanged: (Boolean) -> Unit,
    captureStatus: RawPcapngCaptureStatus,
    ownsDocumentStream: Boolean,
    notice: RawCaptureUiNotice,
    onChooseDocument: () -> Unit,
    onStopCapture: () -> Unit,
) {
    val captureIsRunning = captureStatus.state in setOf(
        RawPcapngCaptureState.RUNNING,
        RawPcapngCaptureState.STOPPING,
    )
    SentinelCard {
        Text(stringResource(R.string.raw_capture_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.raw_capture_limited), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.raw_capture_before_start), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.raw_capture_disclosure))
        SentinelToggleRow(
            title = stringResource(R.string.raw_capture_acknowledge),
            description = stringResource(
                if (disclosureAccepted) R.string.raw_capture_acknowledged else R.string.raw_capture_not_acknowledged,
            ),
            checked = disclosureAccepted,
            onCheckedChange = onDisclosureChanged,
        )
        Text(stringResource(R.string.raw_capture_preset_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.raw_capture_preset_short), style = MaterialTheme.typography.bodySmall)
        if (!monitorActive || !exportAvailable) {
            Text(stringResource(R.string.raw_capture_unavailable), color = MaterialTheme.colorScheme.error)
        }
        Button(
            onClick = onChooseDocument,
            enabled = exportAvailable && disclosureAccepted && !ownsDocumentStream && !captureIsRunning,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.raw_capture_choose_document)) }
        if (ownsDocumentStream || captureIsRunning || captureStatus.state == RawPcapngCaptureState.FAILED) {
            Text(stringResource(R.string.raw_capture_status_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            SentinelStatusLabel(
                label = when (captureStatus.state) {
                    RawPcapngCaptureState.RUNNING -> stringResource(R.string.raw_capture_running)
                    RawPcapngCaptureState.STOPPING -> stringResource(R.string.raw_capture_stopping)
                    RawPcapngCaptureState.FAILED -> stringResource(R.string.raw_capture_failed)
                    RawPcapngCaptureState.STOPPED -> stringResource(R.string.raw_capture_stopped)
                },
                tone = when (captureStatus.state) {
                    RawPcapngCaptureState.RUNNING -> SentinelStatusTone.INFORMATION
                    RawPcapngCaptureState.STOPPING -> SentinelStatusTone.REVIEW
                    RawPcapngCaptureState.FAILED -> SentinelStatusTone.URGENT
                    RawPcapngCaptureState.STOPPED -> SentinelStatusTone.NEUTRAL
                },
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            captureStatus.startedAtMillis?.let { startedAt ->
                KeyValueRow(
                    stringResource(R.string.raw_capture_status_started),
                    DateFormat.getTimeInstance().format(Date(startedAt)),
                )
            }
            KeyValueRow(stringResource(R.string.raw_capture_status_accepted), captureStatus.acceptedPackets.toString())
            KeyValueRow(stringResource(R.string.raw_capture_status_written), captureStatus.writtenPackets.toString())
            KeyValueRow(stringResource(R.string.raw_capture_status_content_bytes), captureStatus.capturedBytes.toString())
            KeyValueRow(stringResource(R.string.raw_capture_status_file_bytes), captureStatus.writtenFileBytes.toString())
            KeyValueRow(
                stringResource(R.string.raw_capture_status_dropped),
                rawCaptureDroppedPackets(captureStatus).toString(),
            )
            KeyValueRow(stringResource(R.string.raw_capture_status_truncated), captureStatus.truncatedPackets.toString())
            captureStatus.failureReason?.let { Text(rawCaptureFailureText(it), color = MaterialTheme.colorScheme.error) }
            if (ownsDocumentStream && captureStatus.state.isRawCaptureTerminal()) {
                Text(stringResource(R.string.raw_capture_status_waiting_close), style = MaterialTheme.typography.bodySmall)
            }
        }
        rawCaptureNoticeText(notice)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        if (ownsDocumentStream || captureIsRunning) {
            FullWidthOutlinedAction(
                label = stringResource(R.string.raw_capture_stop),
                onClick = onStopCapture,
                enabled = captureStatus.state != RawPcapngCaptureState.STOPPING,
            )
        }
    }
}

private fun RawPcapngCaptureState.isRawCaptureTerminal(): Boolean =
    this == RawPcapngCaptureState.STOPPED || this == RawPcapngCaptureState.FAILED

private fun rawCaptureDroppedPackets(status: RawPcapngCaptureStatus): Long = listOf(
    status.droppedQueueFull,
    status.droppedByLimit,
    status.droppedUnsupportedPacket,
    status.droppedInvalidTimestamp,
).fold(0L) { total, count -> if (Long.MAX_VALUE - total < count) Long.MAX_VALUE else total + count }

@Composable
private fun rawCaptureNoticeText(notice: RawCaptureUiNotice): String? = when (notice) {
    RawCaptureUiNotice.NONE -> null
    RawCaptureUiNotice.DOCUMENT_CANCELLED -> stringResource(R.string.raw_capture_document_cancelled)
    RawCaptureUiNotice.DOCUMENT_OPEN_FAILED -> stringResource(R.string.raw_capture_document_open_failed)
    RawCaptureUiNotice.DOCUMENT_CLOSE_FAILED -> stringResource(R.string.raw_capture_document_close_failed)
    RawCaptureUiNotice.NOT_AVAILABLE -> stringResource(R.string.raw_capture_unavailable)
    RawCaptureUiNotice.STARTED -> stringResource(R.string.raw_capture_started)
    RawCaptureUiNotice.STOPPING -> stringResource(R.string.raw_capture_stopping)
    RawCaptureUiNotice.STOPPED -> stringResource(R.string.raw_capture_stopped)
    RawCaptureUiNotice.REJECTED_ALREADY_ACTIVE -> stringResource(R.string.raw_capture_rejection_already_active)
    RawCaptureUiNotice.REJECTED_CLOCK_UNAVAILABLE -> stringResource(R.string.raw_capture_rejection_clock_unavailable)
    RawCaptureUiNotice.REJECTED_INVALID_START_TIME -> stringResource(R.string.raw_capture_rejection_invalid_start_time)
    RawCaptureUiNotice.REJECTED_WRITER_START_FAILED -> stringResource(R.string.raw_capture_rejection_writer_start_failed)
}

@Composable
private fun rawCaptureFailureText(reason: RawPcapngCaptureFailureReason): String = when (reason) {
    RawPcapngCaptureFailureReason.CLOCK_UNAVAILABLE -> stringResource(R.string.raw_capture_failure_clock_unavailable)
    RawPcapngCaptureFailureReason.INVALID_CLOCK_TIME -> stringResource(R.string.raw_capture_failure_invalid_clock_time)
    RawPcapngCaptureFailureReason.OUTPUT_WRITE_FAILED -> stringResource(R.string.raw_capture_failure_output_write_failed)
    RawPcapngCaptureFailureReason.WRITER_INTERRUPTED -> stringResource(R.string.raw_capture_failure_writer_interrupted)
    RawPcapngCaptureFailureReason.WRITER_RUNTIME_FAILURE -> stringResource(R.string.raw_capture_failure_writer_runtime_failure)
    RawPcapngCaptureFailureReason.WRITER_START_FAILED -> stringResource(R.string.raw_capture_failure_writer_start_failed)
}

@Composable
private fun networkEventSummary(event: NetworkEvent): String = when (event) {
    is PacketObservedEvent -> {
        val owner = when (val attribution = event.attribution) {
            is AppAttribution.Known -> attribution.packageName
            is AppAttribution.Unknown -> stringResource(R.string.network_unknown_app)
        }
        val endpoint = event.metadata.destination.let { destination ->
            if (destination.port == null) destination.address else "${destination.address}:${destination.port}"
        }
        stringResource(
            R.string.network_packet_summary,
            owner,
            stringResource(NetworkUiTextMapper.transport(event.metadata.transportProtocol)),
            endpoint,
            event.metadata.capturedPacketBytes,
        )
    }
    is app.apksentinel.networkmonitor.FirewallDecisionEvent ->
        stringResource(
            R.string.network_firewall_summary,
            stringResource(NetworkUiTextMapper.firewallAction(event.decision.requestedAction)),
            stringResource(NetworkUiTextMapper.firewallState(event.decision.enforcement)),
        )
    is app.apksentinel.networkmonitor.MonitorStateEvent ->
        stringResource(NetworkUiTextMapper.text(event.uiText.code))
    is app.apksentinel.networkmonitor.PacketParseFailureEvent ->
        stringResource(R.string.network_parser_note, stringResource(NetworkUiTextMapper.parseFailure(event.code)))
    is app.apksentinel.networkmonitor.EngineLimitationEvent ->
        stringResource(NetworkUiTextMapper.limitation(event.limitation.code))
    is app.apksentinel.networkmonitor.ForwarderEnforcementEvent ->
        stringResource(NetworkUiTextMapper.firewallOutcome(event.result.outcome))
}
