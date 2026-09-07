package app.apksentinel.mobile

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp

/** Navigation destinations are deliberately kept separate from each screen's implementation. */
internal enum class Destination(
    val labelResource: Int,
    val compactResource: Int,
    val iconResource: Int? = null,
    val showInPrimaryNavigation: Boolean = true,
) {
    // The four primary tabs each map to one of the three reference products, plus Home:
    //   Checkup -> M-Kavach 2, Apps -> APK Analyzer, Network -> PCAPdroid.
    // Phone checkup was previously hidden behind an inline link on Home despite being
    // M-Kavach's headline outcome, which is why it is promoted here. "Check APK or link"
    // loses its tab but keeps its icon and stays one tap away from Home, Apps and the
    // drawer, so nothing became less reachable.
    HOME(R.string.ux_destination_overview, R.string.ux_destination_home, R.drawable.ic_nav_home),
    DEVICE(R.string.ux_destination_device, R.string.ux_destination_device, R.drawable.ic_nav_device),
    APPS(R.string.ux_destination_installed_apps, R.string.ux_destination_apps, R.drawable.ic_nav_apps),
    ANALYZE(
        R.string.ux_destination_analyze_apk,
        R.string.ux_destination_analyze,
        R.drawable.ic_nav_analyze,
        showInPrimaryNavigation = false,
    ),
    NETWORK(R.string.ux_destination_network, R.string.ux_destination_network, R.drawable.ic_nav_network),
    ACTIVITY(R.string.ux_destination_activity, R.string.ux_destination_activity, R.drawable.ic_nav_activity, showInPrimaryNavigation = false),
    EXPORTS(R.string.ux_destination_exports, R.string.ux_destination_exports_short, R.drawable.ic_nav_reports, showInPrimaryNavigation = false),
    PRIVACY(R.string.ux_destination_privacy_settings, R.string.ux_destination_privacy, R.drawable.ic_nav_privacy, showInPrimaryNavigation = false),
    HELP(R.string.ux_destination_help, R.string.ux_destination_help, R.drawable.ic_nav_help, showInPrimaryNavigation = false),
    LEGAL(R.string.ux_destination_terms_list, R.string.ux_destination_terms, R.drawable.ic_nav_terms, showInPrimaryNavigation = false),
}

internal fun restoredDestinationOrHome(name: String): Destination =
    Destination.entries.firstOrNull { it.name == name } ?: Destination.HOME

/**
 * The shell deliberately keeps a small, saved origin stack instead of trying to
 * recreate an arbitrary browser history.  It is a list of route names (rather
 * than [Destination] values) so the saved state remains compatible with the
 * existing rememberSaveable contract.
 */
internal const val MAX_DESTINATION_BACK_STACK = 16

internal data class DestinationBackResult(
    val destination: Destination,
    val remainingRouteNames: List<String>,
)

internal fun sanitizeDestinationBackStack(routeNames: List<String>): List<String> =
    routeNames
        .mapNotNull { routeName -> Destination.entries.firstOrNull { it.name == routeName }?.name }
        .fold(emptyList<String>()) { sanitized, routeName ->
            if (sanitized.lastOrNull() == routeName) sanitized else sanitized + routeName
        }
        .takeLast(MAX_DESTINATION_BACK_STACK)

internal fun pushDestinationBackStack(
    routeNames: List<String>,
    current: Destination,
    next: Destination,
): List<String> {
    if (next == Destination.HOME) return emptyList()
    if (current == next) return sanitizeDestinationBackStack(routeNames)
    return (sanitizeDestinationBackStack(routeNames) + current.name)
        .takeLast(MAX_DESTINATION_BACK_STACK)
}

internal fun popDestinationBackStack(
    routeNames: List<String>,
    currentName: String,
): DestinationBackResult {
    val current = restoredDestinationOrHome(currentName)
    if (current.name != currentName) {
        return DestinationBackResult(Destination.HOME, emptyList())
    }
    val sanitized = sanitizeDestinationBackStack(routeNames)
    val previous = sanitized.lastOrNull()?.let(::restoredDestinationOrHome) ?: Destination.HOME
    return DestinationBackResult(
        destination = previous,
        remainingRouteNames = sanitized.dropLast(1),
    )
}

@Composable
internal fun SentinelBottomNavigation(
    destination: Destination,
    onDestinationSelected: (Destination) -> Unit,
) {
    val context = LocalContext.current
    NavigationBar {
        Destination.entries.filter { it.showInPrimaryNavigation }.forEach { item ->
            NavigationBarItem(
                selected = item == destination,
                onClick = { onDestinationSelected(item) },
                icon = { Icon(painterResource(requireNotNull(item.iconResource)), contentDescription = null) },
                label = { Text(stringResource(item.compactResource)) },
                modifier = Modifier.semantics {
                    contentDescription = context.getString(item.labelResource)
                    stateDescription = context.getString(
                        if (item == destination) R.string.ux_navigation_selected else R.string.ux_navigation_not_selected,
                    )
                },
            )
        }
    }
}

@Composable
internal fun SentinelRailNavigation(
    destination: Destination,
    onDestinationSelected: (Destination) -> Unit,
) {
    val context = LocalContext.current
    Surface(tonalElevation = 1.dp, modifier = Modifier.fillMaxHeight()) {
        NavigationRail(modifier = Modifier.padding(vertical = 8.dp)) {
            Destination.entries.filter { it.showInPrimaryNavigation }.forEach { item ->
                NavigationRailItem(
                    selected = item == destination,
                    onClick = { onDestinationSelected(item) },
                    icon = { Icon(painterResource(requireNotNull(item.iconResource)), contentDescription = null) },
                    label = { Text(stringResource(item.compactResource)) },
                    modifier = Modifier.semantics {
                        contentDescription = context.getString(item.labelResource)
                        stateDescription = context.getString(
                            if (item == destination) R.string.ux_navigation_selected else R.string.ux_navigation_not_selected,
                        )
                    },
                )
            }
        }
    }
}

@Composable
internal fun SentinelNetworkStopSurface(
    activeLabel: String,
    onStop: () -> Unit,
) {
    val stackAction = LocalDensity.current.fontScale >= 1.3f
    Surface(
        color = MaterialTheme.colorScheme.primaryContainer,
        contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        modifier = Modifier.fillMaxWidth(),
    ) {
        if (stackAction) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(6.dp),
            ) {
                Text(activeLabel, style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = onStop) {
                    Text(stringResource(R.string.ux_stop))
                }
            }
        } else {
            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                Text(activeLabel, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = onStop) { Text(stringResource(R.string.ux_stop)) }
            }
        }
    }
}
