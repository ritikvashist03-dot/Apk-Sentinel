package app.apksentinel.mobile

import android.content.Intent
import android.os.Build
import android.app.Activity
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import app.apksentinel.engine.tlsinspection.CertificateInstallationState
import app.apksentinel.engine.tlsinspection.CertificateSetupConsent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import app.apksentinel.engine.tlsinspection.TlsInspectionSnapshot
import app.apksentinel.networkmonitor.NetworkMonitorController
import kotlinx.coroutines.delay

private const val TLS_CERTIFICATE_SETUP_DISCLOSURE_VERSION = "tls-certificate-setup-v1"

/**
 * Deliberately unavailable TLS-inspection surface. It can prepare a
 * non-exportable local CA for Android's user-mediated installer, but it cannot
 * start or simulate traffic decryption because no reviewed data plane exists.
 */
@Composable
internal fun TlsInspectionCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var advancedEnabled by rememberSaveable { mutableStateOf(false) }
    var setupConsentAcknowledged by rememberSaveable { mutableStateOf(false) }
    var sessionConsentAcknowledged by rememberSaveable { mutableStateOf(false) }
    var certificateStatus by remember { mutableStateOf<TlsInspectionCertificateStatus>(TlsInspectionCertificateStatus.NotInitialized) }
    var notice by rememberSaveable { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var pendingExportDer by remember { mutableStateOf<ByteArray?>(null) }
    var activeSnapshot by remember { mutableStateOf<TlsInspectionSnapshot?>(null) }
    var networkSessionActive by remember { mutableStateOf(false) }
    var decryptedCapture by rememberSaveable { mutableStateOf(false) }
    var decryptedSnapshot by remember { mutableStateOf(TlsInspectionComposition.decryptedSessionSnapshot()) }
    var keyLogCapture by rememberSaveable { mutableStateOf(false) }
    var keyLogSnapshot by remember { mutableStateOf(TlsInspectionComposition.keyLogSnapshot()) }
    var selectedPackages by remember { mutableStateOf<Set<String>>(emptySet()) }
    val packageOptions = remember(context) { TlsInspectionComposition.packageOptions(context) }

    val installerLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        // API 30+ returns a SAF destination, not an install result. Writing the
        // public DER is export only; the user must install it separately in
        // Android Settings and target-app trust remains unproven.
        scope.launch {
            val export = pendingExportDer
            pendingExportDer = null
            if (export != null) {
                val uri = it.data?.data
                if (it.resultCode == Activity.RESULT_OK && uri != null) {
                    val wrote = SafeDocumentWriter.writeBytes(context, uri, export)
                    notice = context.getString(
                        if (wrote) R.string.tls_inspection_certificate_exported_not_installed
                        else R.string.tls_inspection_certificate_export_failed,
                    )
                } else {
                    notice = context.getString(R.string.tls_inspection_certificate_export_cancelled)
                }
                export.fill(0)
            } else {
                notice = context.getString(R.string.tls_inspection_installer_returned_unknown)
            }
            certificateStatus = withContext(Dispatchers.IO) { TlsInspectionComposition.certificateStatus() }
        }
    }

    LaunchedEffect(Unit) {
        certificateStatus = withContext(Dispatchers.IO) { TlsInspectionComposition.certificateStatus() }
        activeSnapshot = TlsInspectionComposition.activeSessionSnapshot()
    }
    LifecyclePolling {
        networkSessionActive = TlsInspectionComposition.isNetworkSessionActive()
        if (!TlsInspectionComposition.isSessionConsentArmed()) sessionConsentAcknowledged = false
        decryptedSnapshot = TlsInspectionComposition.decryptedSessionSnapshot()
        keyLogSnapshot = TlsInspectionComposition.keyLogSnapshot()
    }
    DisposableEffect(Unit) {
        onDispose {
            pendingExportDer?.fill(0)
            pendingExportDer = null
            // Leaving the screen erases retained plaintext as well as stopping the session.
            TlsInspectionComposition.setDecryptedSessionCapture(enabled = false)
            TlsInspectionComposition.setKeyLogCapture(enabled = false)
            TlsInspectionComposition.stopForBackground()
        }
    }

    SentinelCard {
        Text(stringResource(R.string.tls_inspection_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.tls_inspection_summary), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.tls_inspection_advanced_toggle_title),
            description = stringResource(R.string.tls_inspection_advanced_toggle_description),
            checked = advancedEnabled,
            onCheckedChange = { enabled ->
                advancedEnabled = enabled
                TlsInspectionComposition.setAdvancedEnabled(enabled)
                setupConsentAcknowledged = false
                sessionConsentAcknowledged = false
                TlsInspectionComposition.setSessionConsentAcknowledged(false)
                notice = null
            },
        )
        if (!advancedEnabled) return@SentinelCard

        SentinelStatusLabel(
            label = stringResource(R.string.tls_inspection_status_unavailable),
            tone = SentinelStatusTone.REVIEW,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        Text(stringResource(R.string.tls_inspection_scope), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.tls_inspection_limitations), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.tls_inspection_package_scope), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.tls_inspection_package_selector_unavailable), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.tls_inspection_selected_app_policy), style = MaterialTheme.typography.bodySmall)
        Text(
            stringResource(R.string.tls_inspection_package_catalog_count, packageOptions.size, selectedPackages.size),
            style = MaterialTheme.typography.bodySmall,
        )
        packageOptions.forEach { option ->
            SentinelToggleRow(
                title = option.label,
                description = if (option.selectable) {
                    option.packageName
                } else {
                    context.getString(R.string.tls_inspection_package_row_excluded, option.packageName)
                },
                checked = option.packageName in selectedPackages,
                enabled = (option.selectable && selectedPackages.size < 25) || option.packageName in selectedPackages,
                onCheckedChange = { checked ->
                    selectedPackages = (if (checked) selectedPackages + option.packageName else selectedPackages - option.packageName)
                    TlsInspectionComposition.setSelectedPackages(selectedPackages)
                },
            )
        }

        Text(stringResource(R.string.tls_inspection_session_title), style = MaterialTheme.typography.titleSmall)
        Text(stringResource(R.string.tls_inspection_session_disclosure), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.tls_inspection_session_ack_title),
            description = stringResource(
                if (sessionConsentAcknowledged) {
                    R.string.tls_inspection_session_acknowledged
                } else {
                    R.string.tls_inspection_session_not_acknowledged
                },
            ),
            checked = sessionConsentAcknowledged,
            enabled = TlsInspectionUiPolicy.canRecordSessionConsent(advancedEnabled),
            onCheckedChange = {
                sessionConsentAcknowledged = it
                TlsInspectionComposition.setSessionConsentAcknowledged(it)
            },
        )
        Text(stringResource(R.string.tls_inspection_session_unavailable), style = MaterialTheme.typography.bodySmall)
        if (networkSessionActive || activeSnapshot?.mustShowProminentActiveIndicator == true) {
            SentinelStatusLabel(
                label = stringResource(R.string.tls_inspection_session_active),
                tone = SentinelStatusTone.REVIEW,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            Button(
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    NetworkMonitorController.stop(context)
                    activeSnapshot = TlsInspectionComposition.stopSessionForUser()
                },
            ) { Text(stringResource(R.string.tls_inspection_session_stop)) }
        } else {
            Text(stringResource(R.string.tls_inspection_session_idle), style = MaterialTheme.typography.bodySmall)
        }

        Text(stringResource(R.string.tls_inspection_setup_title), style = MaterialTheme.typography.titleSmall)
        Text(stringResource(R.string.tls_inspection_setup_disclosure), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.tls_inspection_setup_ack_title),
            description = stringResource(
                if (setupConsentAcknowledged) {
                    R.string.tls_inspection_setup_acknowledged
                } else {
                    R.string.tls_inspection_setup_not_acknowledged
                },
            ),
            checked = setupConsentAcknowledged,
            onCheckedChange = { setupConsentAcknowledged = it },
        )
        Button(
            modifier = Modifier.fillMaxWidth(),
            enabled = TlsInspectionUiPolicy.canPrepareCertificateSetup(
                advancedEnabled = advancedEnabled,
                setupConsentAcknowledged = setupConsentAcknowledged,
                busy = busy,
            ),
            onClick = {
                busy = true
                notice = null
                // Key generation and intent construction are both consequences
                // of this explicit user click; nothing happens on a toggle.
                scope.launch {
                    val result = withContext(Dispatchers.IO) {
                            TlsInspectionComposition.prepareSystemCertificateInstaller(
                                CertificateSetupConsent(
                                    disclosureVersion = TLS_CERTIFICATE_SETUP_DISCLOSURE_VERSION,
                                    acknowledgedAtMillis = System.currentTimeMillis(),
                                ),
                                apiLevel = Build.VERSION.SDK_INT,
                            )
                    }
                    setupConsentAcknowledged = false
                    certificateStatus = withContext(Dispatchers.IO) { TlsInspectionComposition.certificateStatus() }
                    busy = false
                    when (result) {
                        is TlsInspectionCertificateSetupResult.SystemInstallerReady ->
                            installerLauncher.launch(result.intent)
                        is TlsInspectionCertificateSetupResult.SafExportReady -> {
                            pendingExportDer?.fill(0)
                            pendingExportDer = result.certificateDer
                            installerLauncher.launch(result.intent)
                        }
                        TlsInspectionCertificateSetupResult.NotInitialized,
                        TlsInspectionCertificateSetupResult.Unavailable,
                        TlsInspectionCertificateSetupResult.UnsupportedApi ->
                            notice = context.getString(R.string.tls_inspection_setup_unavailable)
                    }
                }
            },
        ) {
            Text(stringResource(
                if (Build.VERSION.SDK_INT in 30..36) {
                    R.string.tls_inspection_setup_export_action
                } else {
                    R.string.tls_inspection_setup_action
                },
            ))
        }

        // Retaining decrypted content is the most revealing thing this app can do, so it
        // sits behind its own toggle, states what it holds, and offers an immediate erase.
        val decryptedSaver = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("text/plain"),
        ) { uri ->
            if (uri == null) {
                notice = context.getString(R.string.decrypted_session_cancelled)
            } else {
                val written = SafeDocumentWriter.useOutputStream(context, uri) { output ->
                    TlsInspectionComposition.exportDecryptedSession(output)
                }
                notice = context.getString(
                    if (written != null) R.string.decrypted_session_saved else R.string.decrypted_session_failed,
                )
            }
            decryptedSnapshot = TlsInspectionComposition.decryptedSessionSnapshot()
        }
        SentinelToggleRow(
            title = stringResource(R.string.decrypted_session_title),
            description = stringResource(R.string.decrypted_session_body),
            checked = decryptedCapture,
            onCheckedChange = { enabled ->
                decryptedCapture = enabled
                TlsInspectionComposition.setDecryptedSessionCapture(enabled)
                decryptedSnapshot = TlsInspectionComposition.decryptedSessionSnapshot()
            },
        )
        if (decryptedCapture) {
            Text(stringResource(R.string.decrypted_session_not_capture), style = MaterialTheme.typography.bodySmall)
            if (decryptedSnapshot.segmentCount == 0) {
                Text(stringResource(R.string.decrypted_session_empty), style = MaterialTheme.typography.bodySmall)
            } else {
                SentinelStatusLabel(
                    label = stringResource(
                        R.string.decrypted_session_state,
                        decryptedSnapshot.segmentCount,
                        decryptedSnapshot.retainedBytes,
                    ),
                    tone = SentinelStatusTone.REVIEW,
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.decrypted_session_save),
                    onClick = { decryptedSaver.launch("apk-sentinel-decrypted-session.txt") },
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.decrypted_session_clear),
                    onClick = {
                        TlsInspectionComposition.clearDecryptedSession()
                        decryptedSnapshot = TlsInspectionComposition.decryptedSessionSnapshot()
                        notice = context.getString(R.string.decrypted_session_cleared)
                    },
                )
            }
        }

        // A key log is what makes an exported capture readable in Wireshark. It is kept
        // separate from the decrypted-session toggle because it is a different bargain: the
        // transcript is a snapshot, whereas these keys unlock the capture for as long as it
        // exists, for anyone who holds both.
        val keyLogSaver = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("text/plain"),
        ) { uri ->
            if (uri == null) {
                notice = context.getString(R.string.key_log_cancelled)
            } else {
                val written = SafeDocumentWriter.useOutputStream(context, uri) { output ->
                    TlsInspectionComposition.exportKeyLog(output)
                }
                notice = context.getString(
                    if (written != null) R.string.key_log_saved else R.string.key_log_failed,
                )
            }
            keyLogSnapshot = TlsInspectionComposition.keyLogSnapshot()
        }
        SentinelToggleRow(
            title = stringResource(R.string.key_log_title),
            description = stringResource(R.string.key_log_body),
            checked = keyLogCapture,
            onCheckedChange = { enabled ->
                keyLogCapture = enabled
                TlsInspectionComposition.setKeyLogCapture(enabled)
                keyLogSnapshot = TlsInspectionComposition.keyLogSnapshot()
            },
        )
        if (keyLogCapture) {
            Text(stringResource(R.string.key_log_in_capture), style = MaterialTheme.typography.bodySmall)
            if (keyLogSnapshot.lineCount == 0) {
                Text(stringResource(R.string.key_log_empty), style = MaterialTheme.typography.bodySmall)
            } else {
                SentinelStatusLabel(
                    label = stringResource(R.string.key_log_state, keyLogSnapshot.lineCount),
                    tone = SentinelStatusTone.URGENT,
                )
                if (keyLogSnapshot.droppedLines > 0L) {
                    Text(
                        stringResource(R.string.key_log_dropped, keyLogSnapshot.droppedLines),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                FullWidthOutlinedAction(
                    label = stringResource(R.string.key_log_save),
                    onClick = { keyLogSaver.launch("apk-sentinel-keylog.txt") },
                )
                FullWidthOutlinedAction(
                    label = stringResource(R.string.key_log_clear),
                    onClick = {
                        TlsInspectionComposition.clearKeyLog()
                        keyLogSnapshot = TlsInspectionComposition.keyLogSnapshot()
                        notice = context.getString(R.string.key_log_cleared)
                    },
                )
            }
        }

        TlsCertificateStatus(certificateStatus)
        if (certificateStatus is TlsInspectionCertificateStatus.Prepared) {
            Text(stringResource(R.string.tls_inspection_removal_title), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(R.string.tls_inspection_removal_body), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.tls_inspection_removal_step_one), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.tls_inspection_removal_step_two), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.tls_inspection_removal_step_three), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.tls_inspection_removal_step_four), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.tls_inspection_ca_store_presence_scope), style = MaterialTheme.typography.bodySmall)
            FullWidthOutlinedAction(
                label = stringResource(R.string.tls_inspection_open_security_settings),
                onClick = {
                    val launched = runCatching {
                        context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                    }.isSuccess
                    notice = context.getString(
                        if (launched) R.string.tls_inspection_security_settings_opened
                        else R.string.tls_inspection_security_settings_unavailable,
                    )
                },
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
private fun TlsCertificateStatus(status: TlsInspectionCertificateStatus) {
    when (status) {
        TlsInspectionCertificateStatus.NotInitialized -> Text(
            stringResource(R.string.tls_inspection_certificate_loading),
            style = MaterialTheme.typography.bodySmall,
        )
        TlsInspectionCertificateStatus.Unavailable -> SentinelStatusLabel(
            label = stringResource(R.string.tls_inspection_certificate_not_prepared),
            tone = SentinelStatusTone.NEUTRAL,
        )
        is TlsInspectionCertificateStatus.Prepared -> {
            SentinelStatusLabel(
                label = stringResource(tlsCertificateInstallationStateText(status.installationState)),
                tone = when (status.installationState) {
                    CertificateInstallationState.INSTALLED -> SentinelStatusTone.GOOD
                    CertificateInstallationState.NOT_INSTALLED,
                    CertificateInstallationState.UNKNOWN -> SentinelStatusTone.REVIEW
                },
            )
            KeyValueRow(
                stringResource(R.string.tls_inspection_certificate_fingerprint),
                status.metadata.sha256Fingerprint.take(16) + "...",
            )
            KeyValueRow(
                stringResource(R.string.tls_inspection_ca_store_presence_label),
                status.caStorePresence.name,
            )
            Text(stringResource(R.string.tls_inspection_certificate_key_local), style = MaterialTheme.typography.bodySmall)
            if (status.installationState == CertificateInstallationState.UNKNOWN) {
                Text(stringResource(R.string.tls_inspection_certificate_unknown_body), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private fun tlsCertificateInstallationStateText(state: CertificateInstallationState): Int = when (
    TlsInspectionUiPolicy.certificateUiState(state)
) {
    TlsInspectionCertificateUiState.VERIFIED_INSTALLED -> R.string.tls_inspection_certificate_installed
    TlsInspectionCertificateUiState.VERIFIED_NOT_INSTALLED -> R.string.tls_inspection_certificate_not_installed
    TlsInspectionCertificateUiState.UNKNOWN -> R.string.tls_inspection_certificate_status_unknown
}
