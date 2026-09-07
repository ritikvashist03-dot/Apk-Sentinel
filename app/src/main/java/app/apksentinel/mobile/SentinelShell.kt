package app.apksentinel.mobile

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.tween
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import app.apksentinel.design.LocalSentinelMotion
import app.apksentinel.feature.apps.InstalledAppsScreen
import app.apksentinel.networkmonitor.MonitorLifecycleState
import app.apksentinel.networkmonitor.NetworkMonitorController
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import app.apksentinel.networkmonitor.RawPcapngCaptureState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SentinelShell(
    highContrast: Boolean,
    reduceMotion: Boolean,
    onHighContrastChanged: (Boolean) -> Unit,
    onReduceMotionChanged: (Boolean) -> Unit,
    notificationRoute: NotificationRoute? = null,
    onNotificationRouteHandled: () -> Unit = {},
) {
    val context = LocalContext.current
    val onboardingPreferences = remember(context) { context.getSharedPreferences("onboarding", Context.MODE_PRIVATE) }
    var onboardingComplete by rememberSaveable {
        mutableStateOf(onboardingPreferences.getBoolean("completed_v1", false))
    }
    if (!onboardingComplete) {
        // Outside the Scaffold, so system-bar insets have to be applied here or the title
        // renders underneath the status bar clock.
        OnboardingScreen(
            onComplete = {
                onboardingPreferences.edit().putBoolean("completed_v1", true).apply()
                onboardingComplete = true
            },
        )
        return
    }
    var destinationName by rememberSaveable { mutableStateOf(Destination.HOME.name) }
    var destinationBackStack by rememberSaveable { mutableStateOf<List<String>>(emptyList()) }
    var installedPackageToAnalyze by rememberSaveable { mutableStateOf<String?>(null) }
    var globalNetworkStatus by remember { mutableStateOf(NetworkMonitorRuntime.currentStatus()) }
    var globalRawCaptureStatus by remember { mutableStateOf(AppRawPcapngDocumentCoordinator.status()) }
    LaunchedEffect(notificationRoute) {
        notificationRoute?.let {
            destinationName = when (it) { NotificationRoute.HOME -> Destination.HOME.name; NotificationRoute.DEVICE -> Destination.DEVICE.name; NotificationRoute.NETWORK -> Destination.NETWORK.name }
            // A notification is an external entry point, not an origin to replay.
            destinationBackStack = emptyList()
            onNotificationRouteHandled()
        }
    }
    // Status polling is bound to the resumed lifecycle. A backgrounded app must not keep
    // waking to re-read monitor state and recompose the whole shell.
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                globalNetworkStatus = NetworkMonitorRuntime.currentStatus()
                globalRawCaptureStatus = AppRawPcapngDocumentCoordinator.status()
                delay(1_000)
            }
        }
    }
    // Saved-state values can survive an app update. Treat removed/unknown destinations as Home.
    val destination = restoredDestinationOrHome(destinationName)
    LaunchedEffect(destinationName, destination) {
        if (destination.name != destinationName) {
            destinationName = destination.name
            destinationBackStack = emptyList()
        } else {
            val sanitized = if (destination == Destination.HOME) {
                emptyList()
            } else {
                sanitizeDestinationBackStack(destinationBackStack)
            }
            if (sanitized != destinationBackStack) {
                destinationBackStack = sanitized
            }
        }
    }
    fun navigateTo(next: Destination) {
        if (next == destination) return
        destinationBackStack = pushDestinationBackStack(destinationBackStack, destination, next)
        destinationName = next.name
    }
    fun goBack() {
        if (destination == Destination.HOME) return
        val result = popDestinationBackStack(destinationBackStack, destinationName)
        destinationBackStack = result.remainingRouteNames
        destinationName = result.destination.name
    }
    val usesNavigationRail = LocalConfiguration.current.screenWidthDp >= 600
    val motion = LocalSentinelMotion.current
    val saveableStateHolder = rememberSaveableStateHolder()
    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val drawerScope = rememberCoroutineScope()
    // An app-level BackHandler outranks the drawer's own, so without this Back navigates
    // the screen underneath while the drawer stays open on top of it.
    BackHandler(enabled = drawerState.isOpen || destination != Destination.HOME) {
        if (drawerState.isOpen) drawerScope.launch { drawerState.close() } else goBack()
    }
    DisposableEffect(destination) {
        val window = context.findActivity()?.window
        if (destination in setOf(
                Destination.APPS,
                Destination.ANALYZE,
                Destination.NETWORK,
                Destination.ACTIVITY,
                Destination.EXPORTS,
                Destination.PRIVACY,
                Destination.HELP,
                Destination.LEGAL,
            )
        ) {
            window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    val hasActiveNetworkSession = globalNetworkStatus.state in setOf(
        MonitorLifecycleState.STARTING,
        MonitorLifecycleState.ACTIVE,
        MonitorLifecycleState.STOPPING,
    )
    val hasActiveRawCapture = globalRawCaptureStatus.state in setOf(
        RawPcapngCaptureState.RUNNING,
        RawPcapngCaptureState.STOPPING,
    ) || AppRawPcapngDocumentCoordinator.ownsDocumentStream()
    val stopNetworkSession = {
        AppRawPcapngDocumentCoordinator.onMonitoringStopped()
        NetworkMonitorController.stop(context)
        globalNetworkStatus = NetworkMonitorRuntime.currentStatus()
    }
    val stopActiveSurface = {
        if (hasActiveRawCapture) {
            AppRawPcapngDocumentCoordinator.requestStopAndClose()
            globalRawCaptureStatus = AppRawPcapngDocumentCoordinator.status()
        } else {
            stopNetworkSession()
        }
    }
    val activeSurfaceLabel = when {
        hasActiveRawCapture && globalRawCaptureStatus.state == RawPcapngCaptureState.STOPPING ->
            stringResource(R.string.raw_capture_global_stopping)
        hasActiveRawCapture -> stringResource(R.string.raw_capture_global_running)
        globalNetworkStatus.state == MonitorLifecycleState.STARTING -> stringResource(R.string.network_starting)
        globalNetworkStatus.state == MonitorLifecycleState.STOPPING -> stringResource(R.string.network_stopping)
        else -> stringResource(R.string.network_active)
    }
    ModalNavigationDrawer(
        drawerState = drawerState,
        // A rail already shows the primary destinations, so the drawer stays reachable
        // from the top bar there but must not swallow horizontal drags.
        gesturesEnabled = !usesNavigationRail,
        drawerContent = {
            SentinelDrawerContent(
                current = destination,
                onSelect = { next ->
                    drawerScope.launch { drawerState.close() }
                    navigateTo(next)
                },
            )
        },
    ) {
    Row(Modifier.fillMaxSize()) {
        if (usesNavigationRail) {
            SentinelRailNavigation(destination, ::navigateTo)
        }
        Scaffold(
            modifier = Modifier.weight(1f),
            topBar = {
                Column {
                    TopAppBar(
                        title = {
                            Text(
                                stringResource(destination.labelResource),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        },
                        navigationIcon = {
                            // Material convention: a top-level destination opens the menu,
                            // a detail destination goes back. Never both in the same slot.
                            if (destination.showInPrimaryNavigation) {
                                IconButton(onClick = { drawerScope.launch { drawerState.open() } }) {
                                    Icon(
                                        painterResource(R.drawable.ic_menu),
                                        contentDescription = stringResource(R.string.ux_open_menu),
                                    )
                                }
                            } else {
                                IconButton(onClick = ::goBack) {
                                    Icon(
                                        painterResource(R.drawable.ic_back),
                                        contentDescription = stringResource(R.string.ux_back),
                                    )
                                }
                            }
                        },
                    )
                    if (hasActiveRawCapture || hasActiveNetworkSession) {
                        SentinelNetworkStopSurface(activeLabel = activeSurfaceLabel, onStop = stopActiveSurface)
                    }
                }
            },
            bottomBar = {
                if (!usesNavigationRail) {
                    SentinelBottomNavigation(destination, ::navigateTo)
                }
            },
        ) { padding ->
            AnimatedContent(
                targetState = destination,
                transitionSpec = {
                    if (motion.reducedMotion) {
                        EnterTransition.None togetherWith ExitTransition.None
                    } else {
                        fadeIn(tween(motion.contentChangeDurationMillis)) togetherWith
                            fadeOut(tween(motion.contentChangeDurationMillis))
                    }
                },
            ) { currentDestination ->
                saveableStateHolder.SaveableStateProvider(currentDestination.name) {
                    when (currentDestination) {
                        Destination.HOME -> OverviewScreen(
                            padding = padding,
                            onNavigate = ::navigateTo,
                        )
                        Destination.DEVICE -> DevicePostureEntryScreen(Modifier.padding(padding))
                        Destination.APPS -> InstalledAppsScreen(
                            modifier = Modifier.padding(padding),
                            onAnalyzePackage = { packageName ->
                                installedPackageToAnalyze = packageName
                                navigateTo(Destination.ANALYZE)
                            },
                            onInventoryLoaded = { apps ->
                                FindingsComposition.recordInstalledApps(apps, System.currentTimeMillis())
                            },
                        )
                        Destination.ANALYZE -> AnalyzeEntryScreen(
                            padding = padding,
                            installedPackageName = installedPackageToAnalyze,
                            onInstalledPackageHandled = { installedPackageToAnalyze = null },
                        )
                        Destination.NETWORK -> NetworkEntryScreen(padding)
                        Destination.ACTIVITY -> ActivityScreen(padding, onRunCheckup = { navigateTo(Destination.DEVICE) })
                        Destination.EXPORTS -> ExportsScreen(padding, onNavigate = ::navigateTo)
                        Destination.PRIVACY -> PrivacyScreen(
                            padding = padding,
                            highContrast = highContrast,
                            reduceMotion = reduceMotion,
                            onHighContrastChanged = onHighContrastChanged,
                            onReduceMotionChanged = onReduceMotionChanged,
                            onOpenTerms = { navigateTo(Destination.LEGAL) },
                        )
                        Destination.HELP -> HelpScreen(padding)
                        Destination.LEGAL -> TermsScreen(padding, onBack = ::goBack)
                    }
                }
            }
        }
    }
    }
}

/**
 * Every destination, grouped by what the user is trying to do rather than by which
 * module implements it. Secondary surfaces used to be reachable only through an inline
 * link on one particular screen; from here they are one tap from any top-level screen.
 */
@Composable
private fun SentinelDrawerContent(
    current: Destination,
    onSelect: (Destination) -> Unit,
) {
    ModalDrawerSheet {
        Column(Modifier.verticalScroll(rememberScrollState())) {
            Spacer(Modifier.height(12.dp))
            SentinelDrawerGroup(
                titleResource = R.string.ux_drawer_group_check,
                destinations = listOf(Destination.HOME, Destination.DEVICE, Destination.APPS, Destination.ANALYZE),
                current = current,
                onSelect = onSelect,
            )
            HorizontalDivider(Modifier.padding(horizontal = 28.dp, vertical = 8.dp))
            SentinelDrawerGroup(
                titleResource = R.string.ux_drawer_group_monitor,
                destinations = listOf(Destination.NETWORK),
                current = current,
                onSelect = onSelect,
            )
            HorizontalDivider(Modifier.padding(horizontal = 28.dp, vertical = 8.dp))
            SentinelDrawerGroup(
                titleResource = R.string.ux_drawer_group_data,
                destinations = listOf(Destination.ACTIVITY, Destination.EXPORTS, Destination.PRIVACY),
                current = current,
                onSelect = onSelect,
            )
            HorizontalDivider(Modifier.padding(horizontal = 28.dp, vertical = 8.dp))
            SentinelDrawerGroup(
                titleResource = R.string.ux_drawer_group_about,
                destinations = listOf(Destination.HELP, Destination.LEGAL),
                current = current,
                onSelect = onSelect,
            )
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun SentinelDrawerGroup(
    titleResource: Int,
    destinations: List<Destination>,
    current: Destination,
    onSelect: (Destination) -> Unit,
) {
    Text(
        stringResource(titleResource),
        modifier = Modifier.padding(horizontal = 28.dp, vertical = 8.dp),
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    destinations.forEach { item ->
        val iconResource = item.iconResource
        NavigationDrawerItem(
            label = { Text(stringResource(item.labelResource)) },
            selected = item == current,
            onClick = { onSelect(item) },
            icon = if (iconResource != null) {
                { Icon(painterResource(iconResource), contentDescription = null) }
            } else {
                null
            },
            modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
        )
    }
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}
