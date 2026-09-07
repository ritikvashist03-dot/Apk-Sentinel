package app.apksentinel.mobile

import android.net.Uri
import android.os.Handler
import android.os.Looper
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
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.SentinelCard
import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.networkmonitor.OfflineAttributionFailure
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun OfflineAttributionCard() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val main = remember { Handler(Looper.getMainLooper()) }
    var state by remember { mutableStateOf(OfflineAttributionComposition.current()) }
    var payload by remember { mutableStateOf<ByteArray?>(null) }
    var selectedName by rememberSaveable { mutableStateOf<String?>(null) }
    var signature by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var selectionFailed by remember { mutableStateOf(false) }
    var updateStatus by remember { mutableStateOf<OfflineUpdateStatus?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        selectionFailed = false
        scope.launch {
            val loaded = withContext(Dispatchers.IO) {
                runCatching {
                    context.contentResolver.openInputStream(uri)?.use { it.readAtMost(OFFLINE_ATTRIBUTION_IMPORT_CAP + 1) }
                        ?.takeIf { it.size <= OFFLINE_ATTRIBUTION_IMPORT_CAP }
                        ?: error("unavailable")
                }
            }
            payload?.fill(0)
            payload = loaded.getOrNull()
            selectedName = if (loaded.isSuccess) queryDisplayName(context, uri) else null
            selectionFailed = loaded.isFailure
            busy = false
        }
    }

    SentinelCard {
        Text(stringResource(R.string.offline_attribution_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(stringResource(R.string.offline_attribution_body), style = MaterialTheme.typography.bodySmall)
        Text(stringResource(R.string.offline_update_optional_privacy), style = MaterialTheme.typography.bodySmall)
        when (val value = state) {
            is OfflineAttributionAppState.Active -> {
                Text(stringResource(R.string.offline_attribution_active, value.metadata.provider, value.metadata.version))
                Text(stringResource(R.string.offline_attribution_prefixes, value.metadata.prefixCount), style = MaterialTheme.typography.bodySmall)
            }
            OfflineAttributionAppState.Missing -> Text(stringResource(R.string.offline_attribution_missing))
            is OfflineAttributionAppState.Unavailable -> Text(
                stringResource(offlineAttributionFailureText(value.reason)),
                color = MaterialTheme.colorScheme.error,
            )
        }
        FullWidthOutlinedAction(
            label = stringResource(R.string.offline_update_check),
            onClick = {
                busy = true
                updateStatus = null
                scope.launch {
                    when (val fetched = withContext(Dispatchers.IO) {
                        SignedBundleUpdateClient.fetch(
                            endpoint = BuildConfig.OFFLINE_ATTRIBUTION_UPDATE_ENDPOINT,
                            maximumBodyBytes = OFFLINE_ATTRIBUTION_IMPORT_CAP,
                        )
                    }) {
                        is SignedBundleUpdateResult.Failure -> {
                            updateStatus = OfflineUpdateStatus.Failed
                            busy = false
                        }
                        is SignedBundleUpdateResult.Success -> {
                            OfflineAttributionComposition.installWithOutcome(
                                context.applicationContext,
                                fetched.body,
                                fetched.signatureBase64,
                            ) { outcome ->
                                main.post {
                                    fetched.body.fill(0)
                                    state = when (outcome) {
                                        is OfflineAttributionInstallOutcome.Accepted -> {
                                            updateStatus = OfflineUpdateStatus.Installed
                                            outcome.state
                                        }
                                        is OfflineAttributionInstallOutcome.Rejected -> {
                                            updateStatus = OfflineUpdateStatus.Failed
                                            outcome.retainedState
                                        }
                                    }
                                    busy = false
                                }
                            }
                        }
                    }
                }
            },
            enabled = BuildConfig.OFFLINE_ATTRIBUTION_UPDATE_ENDPOINT.isNotBlank() && !busy,
        )
        FullWidthOutlinedAction(
            label = selectedName?.let { stringResource(R.string.offline_attribution_selected, it) }
                ?: stringResource(R.string.offline_attribution_choose),
            onClick = { picker.launch(arrayOf("text/plain", "application/octet-stream")) },
            enabled = !busy,
        )
        OutlinedTextField(
            value = signature,
            onValueChange = { signature = it.filterNot(Char::isWhitespace).take(4_096) },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.offline_attribution_signature)) },
            supportingText = { Text(stringResource(R.string.offline_attribution_signature_hint)) },
            minLines = 2,
        )
        Button(
            onClick = {
                val bytes = payload ?: return@Button
                busy = true
                OfflineAttributionComposition.installWithOutcome(context.applicationContext, bytes, signature) { outcome ->
                    main.post {
                        state = when (outcome) {
                            is OfflineAttributionInstallOutcome.Accepted -> {
                                updateStatus = null
                                outcome.state
                            }
                            is OfflineAttributionInstallOutcome.Rejected -> {
                                updateStatus = OfflineUpdateStatus.Failed
                                outcome.retainedState
                            }
                        }
                        busy = false
                        payload?.fill(0)
                        payload = null
                        selectedName = null
                        signature = ""
                    }
                }
            },
            enabled = payload != null && signature.isNotBlank() && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(if (busy) R.string.offline_attribution_working else R.string.offline_attribution_verify)) }
        if (selectionFailed) Text(
            stringResource(R.string.offline_attribution_read_failed),
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            color = MaterialTheme.colorScheme.error,
        )
        updateStatus?.let { status ->
            Text(
                stringResource(if (status == OfflineUpdateStatus.Installed) R.string.offline_update_installed else R.string.offline_update_failed),
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                color = if (status == OfflineUpdateStatus.Failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(stringResource(R.string.offline_attribution_limitation), style = MaterialTheme.typography.bodySmall)
    }
}

private const val OFFLINE_ATTRIBUTION_IMPORT_CAP = 900_000

private enum class OfflineUpdateStatus { Installed, Failed }

private fun queryDisplayName(context: android.content.Context, uri: Uri): String? = runCatching {
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            SafeTextNormalizer.normalizeDisplayText(cursor.getString(0), "Selected attribution data", 96)
        } else null
    }
}.getOrNull()

private fun java.io.InputStream.readAtMost(maximum: Int): ByteArray {
    val output = ByteArrayOutputStream(minOf(maximum, 64 * 1024))
    val buffer = ByteArray(8 * 1024)
    try {
        while (output.size() < maximum) {
            val count = read(buffer, 0, minOf(buffer.size, maximum - output.size()))
            if (count < 0) break
            if (count == 0) {
                val single = read()
                if (single < 0) break
                output.write(single)
            } else {
                output.write(buffer, 0, count)
            }
        }
        return output.toByteArray()
    } finally {
        buffer.fill(0)
    }
}

private fun offlineAttributionFailureText(reason: OfflineAttributionFailure): Int = when (reason) {
    OfflineAttributionFailure.DATASET_UNAVAILABLE -> R.string.offline_attribution_failure_dataset
    OfflineAttributionFailure.PAYLOAD_SIZE -> R.string.offline_attribution_failure_size
    OfflineAttributionFailure.FORMAT -> R.string.offline_attribution_failure_format
    OfflineAttributionFailure.ENTRY_LIMIT -> R.string.offline_attribution_failure_entries
    OfflineAttributionFailure.TIME_OR_VERSION -> R.string.offline_attribution_failure_time
    OfflineAttributionFailure.EXPIRED -> R.string.offline_attribution_failure_expired
    OfflineAttributionFailure.FUTURE_DATED -> R.string.offline_attribution_failure_future
    OfflineAttributionFailure.CLOCK_ROLLBACK -> R.string.offline_attribution_failure_clock
    OfflineAttributionFailure.VERSION_ROLLBACK -> R.string.offline_attribution_failure_rollback
    OfflineAttributionFailure.KEY_UNKNOWN,
    OfflineAttributionFailure.KEY_CONFIGURATION -> R.string.offline_attribution_failure_key
    OfflineAttributionFailure.SIGNATURE_ENCODING,
    OfflineAttributionFailure.SIGNATURE_INVALID -> R.string.offline_attribution_failure_signature
    OfflineAttributionFailure.INVALID_ENTRY,
    OfflineAttributionFailure.DUPLICATE_PREFIX -> R.string.offline_attribution_failure_entry
    OfflineAttributionFailure.LOADER_UNAVAILABLE,
    OfflineAttributionFailure.LOADER_FAILED -> R.string.offline_attribution_failure_storage
}
