package app.apksentinel.mobile

import android.content.Context
import android.os.Handler
import android.os.Looper
import app.apksentinel.networkmonitor.AndroidEncryptedNetworkHistoryFactory
import app.apksentinel.networkmonitor.DurableHistoryLimits
import app.apksentinel.networkmonitor.DurableHistoryReadState
import app.apksentinel.networkmonitor.DurableHistoryRetentionPolicy
import app.apksentinel.networkmonitor.DurableHistorySnapshot
import app.apksentinel.networkmonitor.EncryptedNetworkHistoryController
import app.apksentinel.networkmonitor.MonitorLifecycleState
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean

internal data class HistoryClearResult(
    val snapshot: DurableHistorySnapshot?,
    val confirmed: Boolean,
)

internal data class HistoryPolicyChangeResult(
    val snapshot: DurableHistorySnapshot?,
    val confirmed: Boolean,
)

internal data class HistoryPrivacyEraseResult(
    val snapshot: DurableHistorySnapshot?,
    val confirmed: Boolean,
)

/**
 * Process-scoped composition for encrypted, metadata-only history.
 * All preferences, Keystore, and storage access stays on [worker]. A sink is installed only
 * for later monitor sessions; an active session is never switched to a different sink.
 */
object NetworkHistoryComposition {
    private val lock = Any()
    private val worker = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "apk-sentinel-history-composition").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())
    private val operationInProgress = AtomicBoolean(false)

    @Volatile private var controller: EncryptedNetworkHistoryController? = null
    @Volatile private var policy: DurableHistoryRetentionPolicy = DurableHistoryRetentionPolicy.SEVEN_DAYS

    fun isOperationInProgress(): Boolean = operationInProgress.get()

    /** Prepares durable history for future sessions. Safe to call from app startup and UI. */
    fun initialize(context: Context, onReady: (DurableHistorySnapshot) -> Unit = {}) {
        val application = context.applicationContext
        if (!beginOperation {
                val selected = readPolicy(application)
                val active = synchronized(lock) {
                    controller ?: create(application, selected).also { created ->
                        policy = selected
                        controller = created
                        NetworkMonitorRuntime.installDurableHistoryForFutureSessions(created)
                    }
                }
                active.requestLoad()
                active.flush(LOAD_WAIT_MILLIS)
                deliver { onReady(active.snapshot()) }
            }
        ) controller?.let { active -> deliver { onReady(active.snapshot()) } }
    }

    /**
     * Applies a persisted policy only while stopped. Persistence is committed first; an
     * unsuccessful commit leaves the existing controller and visible selection unchanged.
     */
    internal fun changePolicy(
        context: Context,
        value: DurableHistoryRetentionPolicy,
        onComplete: (HistoryPolicyChangeResult) -> Unit,
    ) {
        val application = context.applicationContext
        if (!beginOperation {
                val before = controller?.snapshot()
                if (!isMonitorStopped()) {
                    deliver { onComplete(HistoryPolicyChangeResult(before, confirmed = false)) }
                    return@beginOperation
                }

                val previous = synchronized(lock) {
                    val old = controller
                    NetworkMonitorRuntime.installDurableHistoryForFutureSessions(null)
                    controller = null
                    old
                }
                // Start can race an external caller. Reinstall the still-open sink before
                // freezing it and report no policy change.
                if (!isMonitorStopped()) {
                    synchronized(lock) {
                        controller = previous
                        NetworkMonitorRuntime.installDurableHistoryForFutureSessions(previous)
                    }
                    deliver { onComplete(HistoryPolicyChangeResult(previous?.snapshot(), confirmed = false)) }
                    return@beginOperation
                }
                if (!persistPolicy(application, value)) {
                    synchronized(lock) {
                        controller = previous
                        NetworkMonitorRuntime.installDurableHistoryForFutureSessions(previous)
                    }
                    deliver { onComplete(HistoryPolicyChangeResult(previous?.snapshot(), confirmed = false)) }
                    return@beginOperation
                }

                previous?.freeze()
                previous?.flush(RECONFIGURE_FLUSH_MILLIS)
                previous?.close()
                val created = create(application, value)
                created.requestLoad()
                created.flush(LOAD_WAIT_MILLIS)
                synchronized(lock) {
                    policy = value
                    controller = created
                    NetworkMonitorRuntime.installDurableHistoryForFutureSessions(created)
                }
                deliver { onComplete(HistoryPolicyChangeResult(created.snapshot(), confirmed = true)) }
            }
        ) deliver { onComplete(HistoryPolicyChangeResult(controller?.snapshot(), confirmed = false)) }
    }

    fun requestLoad(onComplete: (DurableHistorySnapshot) -> Unit) {
        val active = controller ?: return
        if (!beginOperation {
                active.requestLoad()
                active.flush(LOAD_WAIT_MILLIS)
                deliver { onComplete(active.snapshot()) }
            }
        ) deliver { onComplete(active.snapshot()) }
    }

    fun snapshot(): DurableHistorySnapshot? = controller?.snapshot()
    fun currentPolicy(): DurableHistoryRetentionPolicy = policy

    /** Category-only clear: erase old ciphertext/key, then install a fresh empty sink. */
    internal fun clearHistory(context: Context, onComplete: (HistoryClearResult) -> Unit) {
        val application = context.applicationContext
        if (!beginOperation {
                if (!isMonitorStopped()) {
                    deliver { onComplete(HistoryClearResult(controller?.snapshot(), confirmed = false)) }
                    return@beginOperation
                }
                val active = synchronized(lock) {
                    val old = controller
                    NetworkMonitorRuntime.installDurableHistoryForFutureSessions(null)
                    controller = null
                    old
                }
                if (!isMonitorStopped()) {
                    synchronized(lock) {
                        controller = active
                        NetworkMonitorRuntime.installDurableHistoryForFutureSessions(active)
                    }
                    deliver { onComplete(HistoryClearResult(active?.snapshot(), confirmed = false)) }
                    return@beginOperation
                }
                active?.freeze()
                active?.flush(RECONFIGURE_FLUSH_MILLIS)
                val erased = active?.erase(ERASE_WAIT_MILLIS)
                active?.close()
                if (erased == null || erased.state != DurableHistoryReadState.ERASED) {
                    deliver { onComplete(HistoryClearResult(erased, confirmed = false)) }
                    return@beginOperation
                }
                val selected = readPolicy(application)
                val replacement = create(application, selected)
                replacement.requestLoad()
                replacement.flush(LOAD_WAIT_MILLIS)
                synchronized(lock) {
                    policy = selected
                    controller = replacement
                    NetworkMonitorRuntime.installDurableHistoryForFutureSessions(replacement)
                }
                deliver { onComplete(HistoryClearResult(replacement.snapshot(), confirmed = true)) }
            }
        ) deliver { onComplete(HistoryClearResult(controller?.snapshot(), confirmed = false)) }
    }

    /** Privacy erase leaves history uninstalled and resets retention to the default/unconfigured state. */
    internal fun eraseForPrivacy(context: Context, onComplete: (HistoryPrivacyEraseResult) -> Unit) {
        val application = context.applicationContext
        if (!beginOperation {
                val active = synchronized(lock) {
                    val old = controller
                    NetworkMonitorRuntime.installDurableHistoryForFutureSessions(null)
                    controller = null
                    old
                }
                active?.freeze()
                active?.flush(RECONFIGURE_FLUSH_MILLIS)
                val erased = active?.erase(ERASE_WAIT_MILLIS)
                active?.close()
                val policyCleared = clearPersistedPolicy(application)
                policy = DurableHistoryRetentionPolicy.SEVEN_DAYS
                deliver {
                    onComplete(
                        HistoryPrivacyEraseResult(
                            snapshot = erased,
                            confirmed = erased?.state == DurableHistoryReadState.ERASED && policyCleared,
                        ),
                    )
                }
            }
        ) deliver { onComplete(HistoryPrivacyEraseResult(controller?.snapshot(), confirmed = false)) }
    }

    private fun isMonitorStopped(): Boolean =
        NetworkMonitorRuntime.currentStatus().state == MonitorLifecycleState.STOPPED

    private fun create(context: Context, value: DurableHistoryRetentionPolicy): EncryptedNetworkHistoryController =
        AndroidEncryptedNetworkHistoryFactory.create(context, value, DurableHistoryLimits())

    private fun readPolicy(context: Context): DurableHistoryRetentionPolicy {
        return NetworkHistoryPolicyStore.load(context)
    }

    private fun persistPolicy(context: Context, value: DurableHistoryRetentionPolicy): Boolean =
        NetworkHistoryPolicyStore.save(context, value)

    private fun clearPersistedPolicy(context: Context): Boolean =
        NetworkHistoryPolicyStore.clear(context)

    private fun beginOperation(task: () -> Unit): Boolean {
        if (!operationInProgress.compareAndSet(false, true)) return false
        if (!submit {
                try {
                    task()
                } finally {
                    operationInProgress.set(false)
                }
            }
        ) operationInProgress.set(false)
        return true
    }

    private fun submit(task: () -> Unit): Boolean = try {
        worker.execute(task)
        true
    } catch (_: RejectedExecutionException) {
        false
    }

    private fun deliver(callback: () -> Unit) {
        try {
            main.post(callback)
        } catch (_: RejectedExecutionException) {
            // UI is tearing down; never call UI code from the storage worker.
        }
    }

    private const val LOAD_WAIT_MILLIS = 1_500L
    private const val RECONFIGURE_FLUSH_MILLIS = 1_500L
    private const val ERASE_WAIT_MILLIS = 2_000L
}
