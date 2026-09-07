package app.apksentinel.mobile

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.KeyValueRow
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelStatusLabel
import app.apksentinel.design.SentinelStatusTone
import app.apksentinel.design.SentinelToggleRow
import app.apksentinel.engine.remotestream.RemoteStreamOwnerSignal

/**
 * The remote receiver flow deliberately lives inside Network's advanced area,
 * never on Home and never in the normal monitoring start flow.
 */
@Composable
internal fun RemoteStreamAdvancedCard(monitorActive: Boolean = false) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var controlsShown by rememberSaveable { mutableStateOf(false) }
    var savedPairing by remember { mutableStateOf(RemoteStreamComposition.loadPairing(context)) }
    var address by rememberSaveable { mutableStateOf(savedPairing?.literalAddress.orEmpty()) }
    var port by rememberSaveable { mutableStateOf(savedPairing?.port?.toString().orEmpty()) }
    var keyId by rememberSaveable { mutableStateOf(savedPairing?.receiverKeyId.orEmpty()) }
    var receiverKey by rememberSaveable { mutableStateOf(savedPairing?.receiverPublicKeyBase64.orEmpty()) }
    var fingerprint by rememberSaveable { mutableStateOf(savedPairing?.receiverFingerprint.orEmpty()) }
    var pairingReviewed by rememberSaveable { mutableStateOf(false) }
    var sessionReviewed by rememberSaveable { mutableStateOf(false) }
    var notice by rememberSaveable { mutableStateOf(RemoteStreamNotice.NONE.name) }
    var snapshot by remember { mutableStateOf(RemoteStreamComposition.currentSnapshot()) }
    val scope = rememberCoroutineScope()

    LifecyclePolling { snapshot = RemoteStreamComposition.currentSnapshot() }

    SentinelCard {
        Text(
            stringResource(R.string.remote_stream_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(stringResource(R.string.remote_stream_summary), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.remote_stream_show_controls),
            description = stringResource(if (controlsShown) R.string.remote_stream_controls_shown else R.string.remote_stream_controls_hidden),
            checked = controlsShown,
            onCheckedChange = {
                controlsShown = it
                if (!it) {
                    pairingReviewed = false
                    sessionReviewed = false
                }
            },
        )
        if (!controlsShown) return@SentinelCard

        Text(stringResource(R.string.remote_stream_receiver_setup), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.remote_stream_receiver_setup_body), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(
            value = address,
            onValueChange = { address = it.filterNot(Char::isWhitespace).take(45); notice = RemoteStreamNotice.NONE.name },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.remote_stream_address_label)) },
            supportingText = { Text(stringResource(R.string.remote_stream_address_help)) },
            singleLine = true,
        )
        OutlinedTextField(
            value = port,
            onValueChange = { port = it.filter(Char::isDigit).take(5); notice = RemoteStreamNotice.NONE.name },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.remote_stream_port_label)) },
            supportingText = { Text(stringResource(R.string.remote_stream_port_help)) },
            singleLine = true,
        )
        OutlinedTextField(
            value = keyId,
            onValueChange = { keyId = it.filter { character -> character.isLetterOrDigit() || character in ".-_" }.take(64); notice = RemoteStreamNotice.NONE.name },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.remote_stream_key_id_label)) },
            supportingText = { Text(stringResource(R.string.remote_stream_key_id_help)) },
            singleLine = true,
        )
        OutlinedTextField(
            value = receiverKey,
            onValueChange = { receiverKey = it.filterNot(Char::isWhitespace).take(6_000); notice = RemoteStreamNotice.NONE.name },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.remote_stream_public_key_label)) },
            supportingText = { Text(stringResource(R.string.remote_stream_public_key_help)) },
            minLines = 2,
            maxLines = 4,
        )
        OutlinedTextField(
            value = fingerprint,
            onValueChange = { fingerprint = it.lowercase().filter { character -> character in '0'..'9' || character in 'a'..'f' }.take(64); notice = RemoteStreamNotice.NONE.name },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.remote_stream_fingerprint_label)) },
            supportingText = { Text(stringResource(R.string.remote_stream_fingerprint_help)) },
            singleLine = true,
        )
        SentinelToggleRow(
            title = stringResource(R.string.remote_stream_pairing_review),
            description = stringResource(if (pairingReviewed) R.string.remote_stream_pairing_reviewed else R.string.remote_stream_pairing_not_reviewed),
            checked = pairingReviewed,
            onCheckedChange = { pairingReviewed = it },
        )
        FullWidthOutlinedAction(
            label = stringResource(R.string.remote_stream_save_pairing),
            enabled = pairingReviewed,
            onClick = {
                when (val parsed = RemoteStreamPairingCodec.parseUserInput(address, port, keyId, receiverKey, fingerprint)) {
                    is RemoteStreamPairingInputResult.Accepted -> {
                        if (RemoteStreamComposition.savePairing(context, parsed.material)) {
                            savedPairing = parsed.material
                            notice = RemoteStreamNotice.PAIRING_SAVED.name
                        } else {
                            notice = RemoteStreamNotice.SAVE_FAILED.name
                        }
                    }
                    is RemoteStreamPairingInputResult.Rejected -> notice = when (parsed.issue) {
                        RemoteStreamPairingInputIssue.DESTINATION -> RemoteStreamNotice.INVALID_DESTINATION.name
                        RemoteStreamPairingInputIssue.RECEIVER_IDENTITY -> RemoteStreamNotice.INVALID_RECEIVER_IDENTITY.name
                        RemoteStreamPairingInputIssue.UNSUPPORTED_RECEIVER_KEY -> RemoteStreamNotice.UNSUPPORTED_RECEIVER_KEY.name
                    }
                }
            },
        )
        FullWidthOutlinedAction(
            label = stringResource(R.string.remote_stream_test_setup),
            enabled = savedPairing != null,
            onClick = {
                notice = when (val pairing = savedPairing) {
                    null -> RemoteStreamNotice.NO_PAIRING.name
                    else -> when (RemoteStreamComposition.verifySetup(context, pairing)) {
                        RemoteStreamSetupResult.INVALID_PAIRING -> RemoteStreamNotice.INVALID_RECEIVER_IDENTITY.name
                        RemoteStreamSetupResult.CLIENT_IDENTITY_UNAVAILABLE -> RemoteStreamNotice.CLIENT_IDENTITY_UNAVAILABLE.name
                        RemoteStreamSetupResult.READY -> RemoteStreamNotice.SETUP_READY.name
                        RemoteStreamSetupResult.RECEIVER_PROTOCOL_REQUIRED -> RemoteStreamNotice.RECEIVER_PROTOCOL_REQUIRED.name
                    }
                }
            },
        )
        FullWidthOutlinedAction(
            label = stringResource(R.string.remote_stream_export_client_certificate),
            enabled = savedPairing != null,
            onClick = {
                notice = if (RemoteStreamComposition.shareClientCertificate(context)) {
                    RemoteStreamNotice.CLIENT_CERTIFICATE_SHARED.name
                } else {
                    RemoteStreamNotice.CLIENT_IDENTITY_UNAVAILABLE.name
                }
            },
        )

        savedPairing?.let { pairing ->
            Text(stringResource(R.string.remote_stream_saved_receiver), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            KeyValueRow(stringResource(R.string.remote_stream_destination_value), pairing.destinationDisplayValue)
            KeyValueRow(stringResource(R.string.remote_stream_fingerprint_value), pairing.receiverFingerprint)
        }
        Text(stringResource(R.string.remote_stream_default_categories), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.remote_stream_limits), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.remote_stream_no_data_source), style = MaterialTheme.typography.bodySmall)
        SentinelToggleRow(
            title = stringResource(R.string.remote_stream_session_review),
            description = stringResource(if (sessionReviewed) R.string.remote_stream_session_reviewed else R.string.remote_stream_session_not_reviewed),
            checked = sessionReviewed,
            onCheckedChange = { sessionReviewed = it },
        )
        Button(
            onClick = {
                savedPairing?.let { pairing ->
                    notice = RemoteStreamNotice.STARTING.name
                    scope.launch(Dispatchers.IO) {
                        val result = RemoteStreamComposition.startSession(context, pairing)
                        withContext(Dispatchers.Main) {
                            notice = if (result is app.apksentinel.engine.remotestream.RemoteStreamStartResult.Started) {
                                RemoteStreamNotice.STARTED.name
                            } else {
                                RemoteStreamNotice.START_FAILED.name
                            }
                            snapshot = RemoteStreamComposition.currentSnapshot()
                        }
                    }
                }
            },
            enabled = monitorActive && savedPairing != null && pairingReviewed && sessionReviewed && snapshot?.mustShowProminentActiveIndicator != true,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.remote_stream_start)) }
        Text(stringResource(R.string.remote_stream_start_unavailable), style = MaterialTheme.typography.bodySmall)

        snapshot?.let { active ->
            SentinelStatusLabel(
                label = stringResource(if (active.mustShowProminentActiveIndicator) R.string.remote_stream_active else R.string.remote_stream_stopped),
                tone = if (active.mustShowProminentActiveIndicator) SentinelStatusTone.URGENT else SentinelStatusTone.NEUTRAL,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
            )
            KeyValueRow(stringResource(R.string.remote_stream_destination_value), active.destinationDisplayValue)
            KeyValueRow(stringResource(R.string.remote_stream_fingerprint_value), active.receiverFingerprint)
            KeyValueRow(stringResource(R.string.remote_stream_packets_value), "${active.transmittedPackets} / ${active.acceptedPackets}")
            KeyValueRow(stringResource(R.string.remote_stream_bytes_value), active.acceptedBytes.toString())
            KeyValueRow(stringResource(R.string.remote_stream_queue_value), "${active.queuedPackets} / ${active.queuedBytes}")
            if (active.mustShowStopControl) {
                Button(
                    onClick = { RemoteStreamComposition.stopForOwnerSignal(RemoteStreamOwnerSignal.PROCESS_OWNER_STOPPED) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.remote_stream_stop)) }
            }
        }
        remoteStreamNoticeText(notice.toRemoteStreamNotice())?.let { message ->
            Text(message, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }, style = MaterialTheme.typography.bodySmall)
        }
    }
}

private enum class RemoteStreamNotice {
    NONE,
    PAIRING_SAVED,
    SAVE_FAILED,
    INVALID_DESTINATION,
    INVALID_RECEIVER_IDENTITY,
    UNSUPPORTED_RECEIVER_KEY,
    NO_PAIRING,
    CLIENT_IDENTITY_UNAVAILABLE,
    SETUP_READY,
    RECEIVER_PROTOCOL_REQUIRED,
    CLIENT_CERTIFICATE_SHARED,
    STARTING,
    STARTED,
    START_FAILED,
}

private fun String.toRemoteStreamNotice(): RemoteStreamNotice =
    runCatching { RemoteStreamNotice.valueOf(this) }.getOrDefault(RemoteStreamNotice.NONE)

@Composable
private fun remoteStreamNoticeText(notice: RemoteStreamNotice): String? = when (notice) {
    RemoteStreamNotice.NONE -> null
    RemoteStreamNotice.PAIRING_SAVED -> stringResource(R.string.remote_stream_pairing_saved)
    RemoteStreamNotice.SAVE_FAILED -> stringResource(R.string.remote_stream_save_failed)
    RemoteStreamNotice.INVALID_DESTINATION -> stringResource(R.string.remote_stream_invalid_destination)
    RemoteStreamNotice.INVALID_RECEIVER_IDENTITY -> stringResource(R.string.remote_stream_invalid_receiver_identity)
    RemoteStreamNotice.UNSUPPORTED_RECEIVER_KEY -> stringResource(R.string.remote_stream_unsupported_receiver_key)
    RemoteStreamNotice.NO_PAIRING -> stringResource(R.string.remote_stream_no_pairing)
    RemoteStreamNotice.CLIENT_IDENTITY_UNAVAILABLE -> stringResource(R.string.remote_stream_client_identity_unavailable)
    RemoteStreamNotice.SETUP_READY -> stringResource(R.string.remote_stream_setup_ready)
    RemoteStreamNotice.RECEIVER_PROTOCOL_REQUIRED -> stringResource(R.string.remote_stream_receiver_protocol_required)
    RemoteStreamNotice.CLIENT_CERTIFICATE_SHARED -> stringResource(R.string.remote_stream_client_certificate_shared)
    RemoteStreamNotice.STARTING -> stringResource(R.string.remote_stream_starting)
    RemoteStreamNotice.STARTED -> stringResource(R.string.remote_stream_started)
    RemoteStreamNotice.START_FAILED -> stringResource(R.string.remote_stream_start_failed)
}
