package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SentinelNavigationTest {
    @Test fun knownHiddenDestinationsRestoreWithoutEnteringPrimaryNavigation() {
        assertEquals(Destination.PRIVACY, restoredDestinationOrHome(Destination.PRIVACY.name))
        assertEquals(Destination.HELP, restoredDestinationOrHome(Destination.HELP.name))
        assertEquals(Destination.LEGAL, restoredDestinationOrHome(Destination.LEGAL.name))
        assertEquals(Destination.ACTIVITY, restoredDestinationOrHome(Destination.ACTIVITY.name))
        assertEquals(false, Destination.HELP.showInPrimaryNavigation)
        assertEquals(false, Destination.ACTIVITY.showInPrimaryNavigation)
    }

    @Test fun removedOrMalformedDestinationFallsBackToHome() {
        assertEquals(Destination.HOME, restoredDestinationOrHome("OLD_SETTINGS_ROUTE"))
        assertEquals(Destination.HOME, restoredDestinationOrHome(""))
    }

    @Test fun primaryNavigationContainsExactlyTheFourBeginnerTasks() {
        // One tab per reference product, plus Home: Checkup covers the M-Kavach outcomes,
        // Apps the APK Analyzer ones, Network the PCAPdroid ones. DEVICE replaced ANALYZE
        // here because phone checkup was previously reachable only through an inline link
        // on Home; "Check APK or link" is still one tap away from Home, Apps and the drawer.
        assertEquals(
            listOf(Destination.HOME, Destination.DEVICE, Destination.APPS, Destination.NETWORK),
            Destination.entries.filter { it.showInPrimaryNavigation },
        )
    }

    @Test fun everyPrimaryDestinationCanRenderAnIcon() {
        // The bottom bar calls requireNotNull on this, so a missing icon is a crash.
        assertTrue(Destination.entries.filter { it.showInPrimaryNavigation }.all { it.iconResource != null })
    }
    @Test fun navigationBackUsesTheInvokingOriginAndDoesNotDuplicateConsecutiveRoutes() {
        val fromHome = pushDestinationBackStack(emptyList(), Destination.HOME, Destination.APPS)
        val fromApps = pushDestinationBackStack(fromHome, Destination.APPS, Destination.ANALYZE)

        assertEquals(listOf(Destination.HOME.name, Destination.APPS.name), fromApps)
        assertEquals(
            Destination.APPS,
            popDestinationBackStack(fromApps, Destination.ANALYZE.name).destination,
        )
        assertEquals(
            listOf(Destination.HOME.name),
            popDestinationBackStack(fromApps, Destination.ANALYZE.name).remainingRouteNames,
        )
        assertEquals(
            fromApps,
            pushDestinationBackStack(fromApps, Destination.ANALYZE, Destination.ANALYZE),
        )
    }

    @Test fun malformedAndOversizedSavedHistoryIsSanitizedAndBounded() {
        val malformed = listOf(
            "OLD_ROUTE",
            Destination.HOME.name,
            Destination.APPS.name,
            Destination.APPS.name,
            Destination.PRIVACY.name,
        )
        assertEquals(
            listOf(Destination.HOME.name, Destination.APPS.name, Destination.PRIVACY.name),
            sanitizeDestinationBackStack(malformed),
        )

        val oversized = (0..MAX_DESTINATION_BACK_STACK + 4).map { index ->
            if (index % 2 == 0) Destination.APPS.name else Destination.NETWORK.name
        }
        assertEquals(MAX_DESTINATION_BACK_STACK, sanitizeDestinationBackStack(oversized).size)
    }

    @Test fun unknownCurrentRouteFallsBackToHomeAndDropsSavedOrigins() {
        assertEquals(
            DestinationBackResult(Destination.HOME, emptyList()),
            popDestinationBackStack(listOf(Destination.APPS.name), "REMOVED_ROUTE"),
        )
    }
}
