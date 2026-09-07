package app.apksentinel.mobile

import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import app.apksentinel.core.security.SafeDocumentWriter
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.KeyValueRow
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.engine.rootcapture.RootCaptureCapability
import app.apksentinel.engine.rootcapture.RootCaptureCapabilityResult
import app.apksentinel.engine.rootcapture.RootCaptureConsent
import app.apksentinel.engine.rootcapture.RootCaptureConsentAction
import app.apksentinel.engine.rootcapture.RootCaptureExportResult
import app.apksentinel.engine.rootcapture.RootCaptureFilter
import app.apksentinel.engine.rootcapture.RootCaptureInterface
import app.apksentinel.engine.rootcapture.RootCaptureLimits
import app.apksentinel.engine.rootcapture.RootCaptureOutputStatus
import app.apksentinel.engine.rootcapture.RootCaptureScope
import app.apksentinel.engine.rootcapture.RootCaptureSessionSnapshot
import app.apksentinel.engine.rootcapture.RootCaptureStartRejection
import app.apksentinel.engine.rootcapture.RootCaptureStartRequest
import app.apksentinel.engine.rootcapture.RootCaptureStartResult
import app.apksentinel.engine.rootcapture.RootCaptureTerminalReason
import app.apksentinel.engine.rootcapture.requiredConsentAction
import java.util.UUID
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.compose.runtime.rememberCoroutineScope

private const val ROOT_CAPTURE_DISCLOSURE_VERSION = "root-capture-v2"
private val rootCaptureAvailableInterfaces = listOf(RootCaptureInterface.ALL_DEVICE)

private enum class RootCapturePreset {
    HEADERS_DEFAULT,
    FULL_COMPACT,
    FULL_STANDARD,
}

/**
 * An intentionally narrow Sensitive Advanced surface. It cannot start a root
 * command from a toggle, and it never represents this as full packet capture.
 */
@Composable
internal fun RootCaptureCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var advancedEnabled by rememberSaveable { mutableStateOf(false) }
    var capabilityAcknowledged by rememberSaveable { mutableStateOf(false) }
    var startAcknowledged by rememberSaveable { mutableStateOf(false) }
    var selectedScopeName by rememberSaveable { mutableStateOf(RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY.name) }
    var selectedFilterName by rememberSaveable { mutableStateOf(RootCaptureFilter.ALL_TRAFFIC.name) }
    var selectedPresetName by rememberSaveable { mutableStateOf(RootCapturePreset.HEADERS_DEFAULT.name) }
    var selectedInterfaceName by rememberSaveable { mutableStateOf(RootCaptureInterface.ALL_DEVICE.name) }
    var sessionInterfaceName by rememberSaveable { mutableStateOf(RootCaptureInterface.ALL_DEVICE.name) }
    var capability by remember { mutableStateOf<RootCaptureCapabilityResult?>(null) }
    var snapshot by remember { mutableStateOf(RootCaptureComposition.snapshot()) }
    var notice by rememberSaveable { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val selectedInterface = remember(selectedInterfaceName) {
        runCatching { RootCaptureInterface.valueOf(selectedInterfaceName) }.getOrDefault(RootCaptureInterface.ALL_DEVICE)
    }
    val selectedScope = remember(selectedScopeName) {
        runCatching { RootCaptureScope.valueOf(selectedScopeName) }
            .getOrDefault(RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY)
    }
    val selectedPreset = remember(selectedPresetName) {
        runCatching { RootCapturePreset.valueOf(selectedPresetName) }.getOrDefault(RootCapturePreset.HEADERS_DEFAULT)
    }
    val selectedFilter = remember(selectedFilterName) {
        runCatching { RootCaptureFilter.valueOf(selectedFilterName) }.getOrDefault(RootCaptureFilter.ALL_TRAFFIC)
    }

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap"),
    ) { uri ->
        if (uri == null) {
            notice = context.getString(R.string.root_capture_export_cancelled)
        } else {
            busy = true
            scope.launch {
                val result = SafeDocumentWriter.useOutputStream(context, uri) { RootCaptureComposition.export(it) }
                    ?: RootCaptureExportResult.Rejected(
                        app.apksentinel.engine.rootcapture.RootCaptureExportRejection.DESTINATION_WRITE_FAILED,
                    )
                notice = rootCaptureExportText(
                    result,
                    context.getString(R.string.root_capture_exported),
                    context.getString(R.string.root_capture_export_failed),
                )
                snapshot = RootCaptureComposition.snapshot()
                busy = false
            }
        }
    }

    LifecyclePolling(intervalMillis = 750L) { snapshot = RootCaptureComposition.snapshot() }
    DisposableEffect(Unit) {
        onDispose {
            // This mode is deliberately foreground-only; navigation also ends it.
            RootCaptureComposition.stopForBackground()
        }
    }

    SentinelCard {
        Text(stringResource(R.string.root_capture_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.root_capture_summary), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.root_capture_advanced_toggle_title),
            description = stringResource(R.string.root_capture_advanced_toggle_description),
            checked = advancedEnabled,
            enabled = !busy && snapshot?.active != true && snapshot?.finalizing != true,
            onCheckedChange = { enabled ->
                advancedEnabled = enabled
                capabilityAcknowledged = false
                startAcknowledged = false
                capability = null
                notice = null
            },
        )
        if (!advancedEnabled) return@SentinelCard

        Text(stringResource(R.string.root_capture_scope_title), style = MaterialTheme.typography.titleSmall)
        Text(stringResource(R.string.root_capture_scope_description), style = MaterialTheme.typography.bodySmall)
        listOf(
            RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
            RootCaptureScope.FULL_PACKET_CAPTURE,
        ).forEach { option ->
            OutlinedButton(
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy && snapshot?.active != true && snapshot?.finalizing != true,
                onClick = {
                    selectedScopeName = option.name
                    capabilityAcknowledged = false
                    startAcknowledged = false
                    capability = null
                    selectedPresetName = if (option == RootCaptureScope.FULL_PACKET_CAPTURE) {
                        RootCapturePreset.FULL_COMPACT.name
                    } else {
                        RootCapturePreset.HEADERS_DEFAULT.name
                    }
                    selectedFilterName = if (option == RootCaptureScope.FULL_PACKET_CAPTURE) {
                        RootCaptureFilter.ALL_TRAFFIC.name
                    } else {
                        RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD.name
                    }
                },
            ) {
                Text(
                    if (option == selectedScope) {
                        stringResource(R.string.root_capture_scope_selected, stringResource(rootCaptureScopeText(option)))
                    } else {
                        stringResource(rootCaptureScopeText(option))
                    },
                )
            }
        }
        if (selectedScope == RootCaptureScope.FULL_PACKET_CAPTURE) {
            Text(stringResource(R.string.root_capture_full_sensitive_warning), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.root_capture_filter_title), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(R.string.root_capture_filter_description), style = MaterialTheme.typography.bodySmall)
            listOf(RootCaptureFilter.ALL_TRAFFIC, RootCaptureFilter.IPV4_IPV6_TCP_UDP).forEach { option ->
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !busy && snapshot?.active != true && snapshot?.finalizing != true,
                    onClick = {
                        selectedFilterName = option.name
                        capabilityAcknowledged = false
                        startAcknowledged = false
                        capability = null
                    },
                ) {
                    Text(
                        if (option == selectedFilter) {
                            stringResource(R.string.root_capture_filter_selected, stringResource(rootCaptureFilterText(option)))
                        } else {
                            stringResource(rootCaptureFilterText(option))
                        },
                    )
                }
            }
        }

        Text(stringResource(R.string.root_capture_capability_disclosure), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.root_capture_capability_ack_title),
            description = stringResource(R.string.root_capture_capability_ack_description),
            checked = capabilityAcknowledged,
            onCheckedChange = { capabilityAcknowledged = it },
        )
        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = RootCaptureUiPolicy.canCheck(capabilityAcknowledged, busy),
            onClick = {
                busy = true
                notice = null
                scope.launch {
                    capability = RootCaptureComposition.checkCapability(
                        consent = rootCaptureConsent(RootCaptureConsentAction.CAPABILITY_CHECK, selectedScope),
                        apiLevel = Build.VERSION.SDK_INT,
                        scope = selectedScope,
                    )
                    capabilityAcknowledged = false
                    startAcknowledged = false
                    busy = false
                }
            },
        ) { Text(stringResource(R.string.root_capture_check_capability)) }

        capability?.let { result ->
            SentinelStatusLabel(
                label = stringResource(rootCaptureCapabilityText(result.capability)),
                tone = if (result.isUsable) SentinelStatusTone.GOOD else SentinelStatusTone.REVIEW,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Text(
                stringResource(
                    if (result.scope == RootCaptureScope.FULL_PACKET_CAPTURE) {
                        R.string.root_capture_capability_limitations_full
                    } else {
                        R.string.root_capture_capability_limitations
                    },
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }

        if (capability?.isUsable == true && capability?.scope == selectedScope) {
            Text(stringResource(R.string.root_capture_interface_title), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(R.string.root_capture_interface_description), style = MaterialTheme.typography.bodySmall)
            rootCaptureAvailableInterfaces.forEach { option ->
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !busy && snapshot?.active != true && snapshot?.finalizing != true,
                    onClick = {
                        selectedInterfaceName = option.name
                        startAcknowledged = false
                    },
                ) {
                    Text(
                        if (option == selectedInterface) {
                            stringResource(R.string.root_capture_interface_selected, stringResource(rootCaptureInterfaceText(option)))
                        } else {
                            stringResource(rootCaptureInterfaceText(option))
                        },
                    )
                }
            }
            Text(stringResource(R.string.root_capture_preset_title), style = MaterialTheme.typography.titleSmall)
            val presets = if (selectedScope == RootCaptureScope.FULL_PACKET_CAPTURE) {
                listOf(RootCapturePreset.FULL_COMPACT, RootCapturePreset.FULL_STANDARD)
            } else {
                listOf(RootCapturePreset.HEADERS_DEFAULT)
            }
            presets.forEach { preset ->
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !busy && snapshot?.active != true && snapshot?.finalizing != true,
                    onClick = {
                        selectedPresetName = preset.name
                        startAcknowledged = false
                    },
                ) {
                    Text(
                        if (preset == selectedPreset) {
                            stringResource(R.string.root_capture_preset_selected, stringResource(rootCapturePresetText(preset)))
                        } else {
                            stringResource(rootCapturePresetText(preset))
                        },
                    )
                }
            }
            Text(
                stringResource(rootCapturePresetDescriptionText(selectedPreset)),
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                stringResource(
                    if (selectedScope == RootCaptureScope.FULL_PACKET_CAPTURE) {
                        R.string.root_capture_full_start_disclosure
                    } else {
                        R.string.root_capture_start_disclosure
                    },
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            SentinelToggleRow(
                title = stringResource(R.string.root_capture_start_ack_title),
                description = stringResource(
                    if (selectedScope == RootCaptureScope.FULL_PACKET_CAPTURE) {
                        R.string.root_capture_full_start_ack_description
                    } else {
                        R.string.root_capture_start_ack_description
                    },
                ),
                checked = startAcknowledged,
                onCheckedChange = { startAcknowledged = it },
            )
            Button(
                modifier = Modifier.fillMaxWidth(),
                enabled = RootCaptureUiPolicy.canStart(capability, startAcknowledged, busy, snapshot, selectedScope),
                onClick = {
                    busy = true
                    notice = null
                    scope.launch {
                        when (val result = RootCaptureComposition.start(
                            rootCaptureConsent(selectedScope.requiredConsentAction(), selectedScope),
                            RootCaptureStartRequest(
                                androidApiLevel = Build.VERSION.SDK_INT,
                                featureEnabled = true,
                                scope = selectedScope,
                                captureInterface = selectedInterface,
                                filter = if (selectedScope == RootCaptureScope.FULL_PACKET_CAPTURE) {
                                    selectedFilter
                                } else {
                                    RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD
                                },
                                limits = rootCaptureLimits(selectedPreset),
                            ),
                        )) {
                            is RootCaptureStartResult.Started -> {
                                snapshot = result.session
                                sessionInterfaceName = selectedInterface.name
                                notice = context.getString(rootCaptureStartedText(selectedScope))
                            }
                            is RootCaptureStartResult.Rejected -> notice = context.getString(rootCaptureStartText(result.reason))
                            null -> notice = context.getString(R.string.root_capture_unavailable)
                        }
                        startAcknowledged = false
                        busy = false
                    }
                },
            ) { Text(stringResource(rootCaptureStartLabel(selectedScope))) }
        }

        val sessionInterface = runCatching { RootCaptureInterface.valueOf(sessionInterfaceName) }
            .getOrDefault(RootCaptureInterface.ALL_DEVICE)
        snapshot?.let { current ->
            RootCaptureSessionState(
                snapshot = current,
                captureInterface = sessionInterface,
                busy = busy,
                exportLauncher = exportLauncher,
                onBusyChange = { busy = it },
                onSnapshotChanged = { snapshot = it },
                onNotice = { notice = it },
            )
        }
        notice?.let {
            SentinelStatusLabel(
                label = it,
                tone = SentinelStatusTone.INFORMATION,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
    }
}

@Composable
private fun RootCaptureSessionState(
    snapshot: RootCaptureSessionSnapshot,
    captureInterface: RootCaptureInterface,
    busy: Boolean,
    exportLauncher: androidx.activity.result.ActivityResultLauncher<String>,
    onBusyChange: (Boolean) -> Unit,
    onSnapshotChanged: (RootCaptureSessionSnapshot?) -> Unit,
    onNotice: (String) -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    SentinelStatusLabel(
        label = if (snapshot.active) {
            stringResource(rootCaptureActiveText(snapshot.scope))
        } else {
            stringResource(rootCaptureTerminalText(snapshot.terminalReason))
        },
        tone = if (snapshot.active) SentinelStatusTone.URGENT else SentinelStatusTone.NEUTRAL,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
    )
    KeyValueRow(
        stringResource(R.string.root_capture_scope_label),
        stringResource(rootCaptureCaptureScopeText(snapshot.scope, snapshot.filter)),
    )
    KeyValueRow(stringResource(R.string.root_capture_interface_label), stringResource(rootCaptureInterfaceText(captureInterface)))
    KeyValueRow(
        stringResource(R.string.root_capture_counters_label),
        stringResource(R.string.root_capture_counters_value, snapshot.observedBytes, snapshot.observedPackets),
    )
    KeyValueRow(
        stringResource(R.string.root_capture_time_label),
        stringResource(R.string.root_capture_time_value, snapshot.maximumDurationMillis / 1_000L),
    )
    KeyValueRow(
        stringResource(R.string.root_capture_destination_label),
        stringResource(
            if (snapshot.outputStatus == RootCaptureOutputStatus.PARTIAL_OUTPUT_REJECTED) {
                R.string.root_capture_destination_unavailable
            } else {
                R.string.root_capture_destination_private
            },
        ),
    )
    KeyValueRow(
        stringResource(R.string.root_capture_drop_label),
        stringResource(R.string.root_capture_drop_unknown),
    )
    KeyValueRow(
        stringResource(R.string.root_capture_truncation_label),
        stringResource(
            if (snapshot.active || snapshot.finalizing) {
                R.string.root_capture_truncation_pending
            } else {
                rootCaptureOutputStatusText(snapshot.outputStatus)
            },
        ),
    )
    if (snapshot.active || snapshot.finalizing) {
        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = !busy && !snapshot.finalizing,
            onClick = {
                onBusyChange(true)
                scope.launch {
                    try {
                        onSnapshotChanged(RootCaptureComposition.stop())
                        onNotice(context.getString(R.string.root_capture_stopped))
                    } finally {
                        onBusyChange(false)
                    }
                }
            },
        ) { Text(stringResource(R.string.root_capture_stop)) }
    } else {
        FullWidthOutlinedAction(
            label = stringResource(R.string.root_capture_export),
            onClick = {
                when (RootCaptureComposition.prepareExport()) {
                    RootCaptureExportResult.UserMediatedDestinationRequired ->
                        exportLauncher.launch(context.getString(rootCaptureExportName(snapshot.scope)))
                    else -> onNotice(context.getString(R.string.root_capture_export_unavailable))
                }
            },
            enabled = RootCaptureUiPolicy.canExport(snapshot, busy),
        )
        Text(stringResource(R.string.root_capture_export_persistence), style = MaterialTheme.typography.bodySmall)
        OutlinedButton(
            modifier = Modifier.fillMaxWidth(),
            enabled = !busy,
            onClick = {
                onBusyChange(true)
                scope.launch {
                    val erased = withContext(Dispatchers.IO) { RootCaptureComposition.eraseTemporaryOutput() }
                    onSnapshotChanged(RootCaptureComposition.snapshot())
                    onNotice(
                        context.getString(
                            if (erased) R.string.root_capture_erased_receipt else R.string.root_capture_erase_failed,
                        ),
                    )
                    onBusyChange(false)
                }
            },
        ) { Text(stringResource(R.string.root_capture_erase)) }
    }
}

private fun rootCaptureConsent(action: RootCaptureConsentAction, scope: RootCaptureScope) = RootCaptureConsent(
    action = action,
    scope = scope,
    disclosureVersion = ROOT_CAPTURE_DISCLOSURE_VERSION,
    acknowledgedAtMillis = System.currentTimeMillis(),
    sessionNonce = UUID.randomUUID().toString().replace("-", ""),
)

private fun rootCaptureScopeText(scope: RootCaptureScope): Int = when (scope) {
    RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> R.string.root_capture_scope_headers
    RootCaptureScope.FULL_PACKET_CAPTURE -> R.string.root_capture_scope_full
}

private fun rootCaptureCaptureScopeText(scope: RootCaptureScope, filter: RootCaptureFilter): Int = when {
    scope == RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> R.string.root_capture_scope_headers
    filter == RootCaptureFilter.IPV4_IPV6_TCP_UDP -> R.string.root_capture_scope_full_narrow
    else -> R.string.root_capture_scope_full
}

private fun rootCaptureFilterText(filter: RootCaptureFilter): Int = when (filter) {
    RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD -> R.string.root_capture_scope_headers
    RootCaptureFilter.ALL_TRAFFIC -> R.string.root_capture_filter_all
    RootCaptureFilter.IPV4_IPV6_TCP_UDP -> R.string.root_capture_filter_narrow
}

private fun rootCaptureLimits(preset: RootCapturePreset): RootCaptureLimits = when (preset) {
    RootCapturePreset.HEADERS_DEFAULT -> RootCaptureLimits()
    RootCapturePreset.FULL_COMPACT -> RootCaptureLimits(
        maximumDurationMillis = 30_000L,
        maximumBytes = 1L * 1024L * 1024L,
        maximumPackets = 500,
        snapLengthBytes = 1_024,
    )
    RootCapturePreset.FULL_STANDARD -> RootCaptureLimits.fullPacketCaptureDefaults()
}

private fun rootCapturePresetText(preset: RootCapturePreset): Int = when (preset) {
    RootCapturePreset.HEADERS_DEFAULT -> R.string.root_capture_preset_headers
    RootCapturePreset.FULL_COMPACT -> R.string.root_capture_preset_full_compact
    RootCapturePreset.FULL_STANDARD -> R.string.root_capture_preset_full_standard
}

private fun rootCapturePresetDescriptionText(preset: RootCapturePreset): Int = when (preset) {
    RootCapturePreset.HEADERS_DEFAULT -> R.string.root_capture_preset_headers_description
    RootCapturePreset.FULL_COMPACT -> R.string.root_capture_preset_full_compact_description
    RootCapturePreset.FULL_STANDARD -> R.string.root_capture_preset_full_standard_description
}

private fun rootCaptureStartLabel(scope: RootCaptureScope): Int = when (scope) {
    RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> R.string.root_capture_start
    RootCaptureScope.FULL_PACKET_CAPTURE -> R.string.root_capture_full_start
}

private fun rootCaptureStartedText(scope: RootCaptureScope): Int = when (scope) {
    RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> R.string.root_capture_started
    RootCaptureScope.FULL_PACKET_CAPTURE -> R.string.root_capture_started_full
}

private fun rootCaptureActiveText(scope: RootCaptureScope): Int = when (scope) {
    RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> R.string.root_capture_active
    RootCaptureScope.FULL_PACKET_CAPTURE -> R.string.root_capture_active_full
}

private fun rootCaptureExportName(scope: RootCaptureScope): Int = when (scope) {
    RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> R.string.root_capture_export_name
    RootCaptureScope.FULL_PACKET_CAPTURE -> R.string.root_capture_full_export_name
}

private fun rootCaptureOutputStatusText(status: RootCaptureOutputStatus): Int = when (status) {
    RootCaptureOutputStatus.COMPLETE -> R.string.root_capture_truncation_complete
    RootCaptureOutputStatus.TRUNCATED_AT_BYTE_CAP -> R.string.root_capture_truncation_byte_cap
    RootCaptureOutputStatus.TRUNCATED_AT_PACKET_CAP -> R.string.root_capture_truncation_packet_cap
    RootCaptureOutputStatus.PARTIAL_OUTPUT_REJECTED -> R.string.root_capture_truncation_rejected
}

private fun rootCaptureCapabilityText(capability: RootCaptureCapability): Int = when (capability) {
    RootCaptureCapability.USABLE -> R.string.root_capture_capability_usable
    RootCaptureCapability.UNSUPPORTED_ANDROID_API -> R.string.root_capture_capability_unsupported_android
    RootCaptureCapability.ROOT_BINARY_UNAVAILABLE -> R.string.root_capture_capability_root_missing
    RootCaptureCapability.ROOT_ACCESS_DENIED -> R.string.root_capture_capability_root_denied
    RootCaptureCapability.ROOT_PROBE_FAILED -> R.string.root_capture_capability_root_failed
    RootCaptureCapability.TCPDUMP_UNAVAILABLE -> R.string.root_capture_capability_tcpdump_missing
    RootCaptureCapability.TCPDUMP_PROBE_FAILED -> R.string.root_capture_capability_tcpdump_failed
}

private fun rootCaptureStartText(reason: RootCaptureStartRejection): Int = when (reason) {
    RootCaptureStartRejection.DISABLED_BY_DEFAULT -> R.string.root_capture_start_disabled
    RootCaptureStartRejection.UNSUPPORTED_ANDROID_API -> R.string.root_capture_capability_unsupported_android
    RootCaptureStartRejection.CONSENT_REJECTED -> R.string.root_capture_start_consent_expired
    RootCaptureStartRejection.ROOT_UNAVAILABLE -> R.string.root_capture_start_root_unavailable
    RootCaptureStartRejection.TCPDUMP_UNAVAILABLE -> R.string.root_capture_start_tcpdump_unavailable
    RootCaptureStartRejection.TEMPORARY_OUTPUT_UNAVAILABLE -> R.string.root_capture_start_output_unavailable
    RootCaptureStartRejection.PROCESS_START_FAILED -> R.string.root_capture_start_process_failed
    RootCaptureStartRejection.ANOTHER_CAPTURE_ACTIVE -> R.string.root_capture_start_already_active
}

private fun rootCaptureInterfaceText(option: RootCaptureInterface): Int = when (option) {
    RootCaptureInterface.ALL_DEVICE -> R.string.root_capture_interface_all
    RootCaptureInterface.WIFI -> R.string.root_capture_interface_wifi
    RootCaptureInterface.MOBILE -> R.string.root_capture_interface_mobile
}

private fun rootCaptureTerminalText(reason: RootCaptureTerminalReason?): Int = when (reason) {
    RootCaptureTerminalReason.USER_STOPPED -> R.string.root_capture_stopped
    RootCaptureTerminalReason.DURATION_CAP_REACHED -> R.string.root_capture_terminal_duration
    RootCaptureTerminalReason.BYTE_CAP_REACHED -> R.string.root_capture_terminal_bytes
    RootCaptureTerminalReason.PACKET_CAP_REACHED -> R.string.root_capture_terminal_packets
    RootCaptureTerminalReason.PROCESS_EXITED -> R.string.root_capture_terminal_process_exited
    RootCaptureTerminalReason.PROCESS_DIED -> R.string.root_capture_terminal_process_died
    RootCaptureTerminalReason.OUTPUT_UNAVAILABLE -> R.string.root_capture_terminal_output_failed
    RootCaptureTerminalReason.ERASURE_REQUESTED -> R.string.root_capture_terminal_erased
    null -> R.string.root_capture_stopped
}

private fun rootCaptureExportText(result: RootCaptureExportResult, success: String, failure: String): String = when (result) {
    RootCaptureExportResult.ExportedAndErased -> success
    RootCaptureExportResult.UserMediatedDestinationRequired -> ""
    is RootCaptureExportResult.Rejected -> failure
}
