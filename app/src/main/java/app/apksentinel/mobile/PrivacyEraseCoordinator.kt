package app.apksentinel.mobile

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Owns the "erase all local data" job for the lifetime of the process.
 *
 * This deliberately does NOT run on the screen's `rememberCoroutineScope()`. The erase
 * performs roughly fifteen independent deletions and waits up to ten seconds on the
 * encrypted network history alone, so it is comfortably long enough for a rotation to
 * land in the middle of it. A composition-scoped job is cancelled by that recreation,
 * which left some data categories erased, others not, the receipt never written, and the
 * button back at its resting state with no error — a privacy-focused user was told
 * nothing happened when something partially had.
 *
 * State is exposed as Compose state so the recreated composition re-reads the real
 * progress instead of assuming idle. Snapshot state is safe to write off the main thread;
 * recomposition is still scheduled on it.
 */
internal object PrivacyEraseCoordinator {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** True while an erase is running, across Activity recreation. */
    var inProgress by mutableStateOf(false)
        private set

    /** The most recent completed receipt, or null if none has completed this process. */
    var lastReceipt by mutableStateOf<PrivacyDeletionReceipt?>(null)
        private set

    /** True when the last erase ended without producing a receipt. */
    var lastRunFailed by mutableStateOf(false)
        private set

    /** Increments on every completion so a screen can react to a repeat erase. */
    var completionCount by mutableIntStateOf(0)
        private set

    /**
     * Starts an erase unless one is already running. [block] must be self-contained and
     * must not capture an Activity: it outlives the screen that requested it.
     */
    fun start(block: suspend () -> PrivacyDeletionReceipt?) {
        if (inProgress) return
        inProgress = true
        lastRunFailed = false
        scope.launch {
            var receipt: PrivacyDeletionReceipt? = null
            try {
                receipt = block()
            } finally {
                lastReceipt = receipt
                lastRunFailed = receipt == null
                completionCount++
                inProgress = false
            }
        }
    }
}
