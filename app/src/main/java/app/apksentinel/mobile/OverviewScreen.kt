package app.apksentinel.mobile

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import app.apksentinel.design.SentinelFeatureTileColor
import app.apksentinel.design.SentinelFeatureTileSpec
import app.apksentinel.design.SentinelFeatureGrid

/**
 * Home is a grid of large, distinctly-coloured feature tiles — one icon, one short label,
 * one tap — modelled on the reference design the user supplied (M-Kavach 2). It deliberately
 * carries no status prose, counts, or coverage bars: those buried the one thing a
 * non-technical user needed, which action to take next, under a wall of text that a real
 * device test showed was "not understandable" and gave "no way of understanding" what
 * tapping something would do. Every tile below IS the destination name, so what is tapped
 * is what opens.
 */
@Composable
internal fun OverviewScreen(
    padding: PaddingValues,
    onNavigate: (Destination) -> Unit,
) = ScreenColumn(padding) {
    SentinelFeatureGrid(
        tiles = listOf(
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_destination_device),
                icon = painterResource(R.drawable.ic_nav_device),
                color = SentinelFeatureTileColor.BLUE,
                onClick = { onNavigate(Destination.DEVICE) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_destination_apps),
                icon = painterResource(R.drawable.ic_nav_apps),
                color = SentinelFeatureTileColor.LAVENDER,
                onClick = { onNavigate(Destination.APPS) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_home_tile_check),
                icon = painterResource(R.drawable.ic_nav_analyze),
                color = SentinelFeatureTileColor.PINK,
                onClick = { onNavigate(Destination.ANALYZE) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_destination_network),
                icon = painterResource(R.drawable.ic_nav_network),
                color = SentinelFeatureTileColor.GREEN,
                onClick = { onNavigate(Destination.NETWORK) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_destination_activity),
                icon = painterResource(R.drawable.ic_nav_activity),
                color = SentinelFeatureTileColor.PEACH,
                onClick = { onNavigate(Destination.ACTIVITY) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_home_tile_reports),
                icon = painterResource(R.drawable.ic_nav_reports),
                color = SentinelFeatureTileColor.CYAN,
                onClick = { onNavigate(Destination.EXPORTS) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_destination_privacy),
                icon = painterResource(R.drawable.ic_nav_privacy),
                color = SentinelFeatureTileColor.MINT,
                onClick = { onNavigate(Destination.PRIVACY) },
            ),
            SentinelFeatureTileSpec(
                label = stringResource(R.string.ux_destination_help),
                icon = painterResource(R.drawable.ic_nav_help),
                color = SentinelFeatureTileColor.YELLOW,
                onClick = { onNavigate(Destination.HELP) },
            ),
        ),
    )
    val context = LocalContext.current
    val versionName = remember(context) {
        runCatching {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        }.getOrNull().orEmpty()
    }
    if (versionName.isNotBlank()) {
        Spacer(Modifier.height(20.dp))
        Text(
            text = stringResource(R.string.ux_home_version, versionName),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            text = stringResource(R.string.ux_home_footer_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
