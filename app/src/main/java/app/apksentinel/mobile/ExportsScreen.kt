package app.apksentinel.mobile

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelTaskRow

/**
 * A directory of everything the app can write to a file.
 *
 * Each export lives on the screen that produces it — an APK report only exists once an
 * APK has been checked — so this does not perform the save itself. It exists because the
 * export actions were otherwise buried a thousand-plus lines down inside two very long
 * scrolling screens, where nobody who wasn't already looking would find them. Each row
 * explains what the file contains in plain language and takes one tap to get there.
 */
@Composable
internal fun ExportsScreen(
    padding: PaddingValues,
    onNavigate: (Destination) -> Unit,
) = ScreenColumn(padding) {
    SentinelCard {
        Text(
            stringResource(R.string.exports_privacy_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    val chevron = painterResource(R.drawable.ic_chevron)

    ExportGroupHeading(stringResource(R.string.exports_group_apk))
    SentinelTaskRow(
        title = stringResource(R.string.exports_apk_report_title),
        supportingText = stringResource(R.string.exports_apk_report_body),
        onClick = { onNavigate(Destination.ANALYZE) },
        icon = painterResource(R.drawable.ic_nav_analyze),
        chevron = chevron,
    )
    SentinelTaskRow(
        title = stringResource(R.string.exports_apk_manifest_title),
        supportingText = stringResource(R.string.exports_apk_manifest_body),
        onClick = { onNavigate(Destination.ANALYZE) },
        icon = painterResource(R.drawable.ic_nav_analyze),
        chevron = chevron,
    )
    SentinelTaskRow(
        title = stringResource(R.string.exports_apk_artifact_title),
        supportingText = stringResource(R.string.exports_apk_artifact_body),
        onClick = { onNavigate(Destination.APPS) },
        icon = painterResource(R.drawable.ic_nav_apps),
        chevron = chevron,
    )

    ExportGroupHeading(stringResource(R.string.exports_group_network))
    SentinelTaskRow(
        title = stringResource(R.string.exports_network_flow_title),
        supportingText = stringResource(R.string.exports_network_flow_body),
        onClick = { onNavigate(Destination.NETWORK) },
        icon = painterResource(R.drawable.ic_nav_network),
        chevron = chevron,
    )
    SentinelTaskRow(
        title = stringResource(R.string.exports_network_capture_title),
        supportingText = stringResource(R.string.exports_network_capture_body),
        onClick = { onNavigate(Destination.NETWORK) },
        icon = painterResource(R.drawable.ic_nav_network),
        chevron = chevron,
    )
    SentinelTaskRow(
        title = stringResource(R.string.exports_network_settings_title),
        supportingText = stringResource(R.string.exports_network_settings_body),
        onClick = { onNavigate(Destination.NETWORK) },
        icon = painterResource(R.drawable.ic_nav_network),
        chevron = chevron,
    )
}

@Composable
private fun ExportGroupHeading(text: String) {
    Text(
        text,
        modifier = Modifier.semantics { heading() },
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary,
    )
}
