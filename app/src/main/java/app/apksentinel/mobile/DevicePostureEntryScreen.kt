package app.apksentinel.mobile

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import app.apksentinel.feature.device.DevicePostureScreen
import app.apksentinel.feature.device.DevicePostureSnapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

@Composable
internal fun DevicePostureEntryScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val activity = remember(context) { SafeActivityStoreController.android(context.applicationContext) }
    DevicePostureScreen(
        modifier = modifier,
        onUserCheckCompleted = { snapshot ->
            val record = snapshot.toSafeActivityRecord()
            scope.launch(Dispatchers.IO) { activity.append(record) }
        },
    )
}

private fun DevicePostureSnapshot.toSafeActivityRecord(): SafeActivityRecord {
    val limited = coverage.unknownCount > 0 || coverage.partialResultCount > 0
    return SafeActivityRecord(
        category = SafeActivityCategory.DEVICE_CHECK,
        outcome = if (coverage.attentionCount > 0) SafeActivityOutcome.ATTENTION else SafeActivityOutcome.COMPLETED,
        atMillis = generatedAtMillis,
        code = if (limited) SafeActivityCode.LIMITED_EVIDENCE else SafeActivityCode.LOCAL_CHECK,
    )
}
