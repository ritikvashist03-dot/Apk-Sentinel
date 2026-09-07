package app.apksentinel.mobile

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberUpdatedState
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay

/**
 * Polls [onTick] only while the app is actually in front of the user.
 *
 * Several surfaces here refresh engine state on a timer. Written as a bare
 * `LaunchedEffect(Unit) { while (true) { …; delay(n) } }`, that loop keeps running for as
 * long as the composable stays in composition — and backgrounding the app does not leave
 * composition, so the polling (and the recomposition it causes) continued indefinitely
 * with the screen off. Binding to [Lifecycle.State.RESUMED] stops each loop at ON_PAUSE
 * and restarts it on resume.
 *
 * [onTick] is held through [rememberUpdatedState] so a caller can pass a lambda closing
 * over current state without restarting the timer on every recomposition.
 */
@Composable
internal fun LifecyclePolling(
    intervalMillis: Long = 1_000L,
    onTick: () -> Unit,
) {
    val currentTick = rememberUpdatedState(onTick)
    val lifecycleOwner = LocalLifecycleOwner.current
    LaunchedEffect(lifecycleOwner, intervalMillis) {
        lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                currentTick.value()
                delay(intervalMillis)
            }
        }
    }
}
