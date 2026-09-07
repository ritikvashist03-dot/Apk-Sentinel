package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.engine.rootcapture.ExecutorRootCaptureRuntime
import app.apksentinel.engine.rootcapture.RootCaptureCapabilityResult
import app.apksentinel.engine.rootcapture.RootCaptureConsent
import app.apksentinel.engine.rootcapture.RootCaptureController
import app.apksentinel.engine.rootcapture.RootCaptureEraseResult
import app.apksentinel.engine.rootcapture.RootCaptureExportRequest
import app.apksentinel.engine.rootcapture.RootCaptureExportResult
import app.apksentinel.engine.rootcapture.RootCaptureSessionSnapshot
import app.apksentinel.engine.rootcapture.RootCaptureStartRequest
import app.apksentinel.engine.rootcapture.RootCaptureStartResult
import app.apksentinel.engine.rootcapture.RootCaptureScope
import app.apksentinel.engine.rootcapture.android.AndroidPrivateRootCaptureOutputStore
import app.apksentinel.engine.rootcapture.android.AndroidProcessBuilderRootRunner
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * App-owned lifetime for the strictly bounded rooted diagnostic option.
 *
 * Initialization only clears abandoned app-cache output. It never probes root,
 * opens a root manager, or starts capture. Those operations stay behind the
 * separately consented UI actions below and always run off the main thread.
 */
object RootCaptureComposition {
    private val lock = Any()
    private var runtime: ExecutorRootCaptureRuntime? = null
    private var controller: RootCaptureController? = null
    private val latestSessionId = AtomicReference<String?>(null)

    fun initialize(context: Context) {
        synchronized(lock) {
            if (controller != null) return
            val ownedRuntime = ExecutorRootCaptureRuntime()
            val ownedController = RootCaptureController(
                runner = AndroidProcessBuilderRootRunner(),
                outputStore = AndroidPrivateRootCaptureOutputStore(context.applicationContext),
                scheduler = ownedRuntime,
                pumpExecutor = ownedRuntime,
            )
            // Cache content is never restored after a process death.
            ownedController.eraseAll()
            runtime = ownedRuntime
            controller = ownedController
        }
    }

    suspend fun checkCapability(
        consent: RootCaptureConsent,
        apiLevel: Int,
        scope: RootCaptureScope = RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
    ): RootCaptureCapabilityResult? = withContext(Dispatchers.IO) {
        synchronized(lock) { controller }?.checkCapability(consent, apiLevel, scope)
    }

    suspend fun start(consent: RootCaptureConsent, request: RootCaptureStartRequest): RootCaptureStartResult? =
        withContext(Dispatchers.IO) {
            synchronized(lock) { controller }?.start(consent, request)?.also { result ->
                if (result is RootCaptureStartResult.Started) latestSessionId.set(result.session.sessionId)
            }
        }

    fun snapshot(): RootCaptureSessionSnapshot? = latestSessionId.get()?.let { sessionId ->
        synchronized(lock) { controller }?.snapshot(sessionId)
    }

    suspend fun stop(): RootCaptureSessionSnapshot? = withContext(Dispatchers.IO) {
        latestSessionId.get()?.let { sessionId -> synchronized(lock) { controller }?.stop(sessionId) }
    }

    fun prepareExport(): RootCaptureExportResult = latestSessionId.get()?.let { sessionId ->
        synchronized(lock) { controller }?.prepareExport(RootCaptureExportRequest(sessionId))
    } ?: RootCaptureExportResult.Rejected(app.apksentinel.engine.rootcapture.RootCaptureExportRejection.SESSION_UNKNOWN)

    suspend fun export(destination: OutputStream): RootCaptureExportResult = withContext(Dispatchers.IO) {
        val sessionId = latestSessionId.get()
            ?: return@withContext RootCaptureExportResult.Rejected(
                app.apksentinel.engine.rootcapture.RootCaptureExportRejection.SESSION_UNKNOWN,
            )
        synchronized(lock) { controller }?.exportToUserChosenDestination(RootCaptureExportRequest(sessionId), destination)
            ?.also { if (it is RootCaptureExportResult.ExportedAndErased) latestSessionId.set(null) }
            ?: RootCaptureExportResult.Rejected(app.apksentinel.engine.rootcapture.RootCaptureExportRejection.SESSION_UNKNOWN)
    }

    /** Blocking cleanup is called from the existing IO privacy erase transaction. */
    fun eraseForPrivacy(): Boolean {
        latestSessionId.set(null)
        return when (synchronized(lock) { controller }?.eraseAll()) {
            RootCaptureEraseResult.Erased, RootCaptureEraseResult.NothingToErase -> true
            RootCaptureEraseResult.CleanupIncomplete, null -> false
        }
    }

    /** Explicit Sensitive Advanced clear action; it erases temporary output and stops capture. */
    fun eraseTemporaryOutput(): Boolean = eraseForPrivacy()

    /** Capture is never kept running while the product is in the background. */
    fun stopForBackground() {
        val sessionId = latestSessionId.get() ?: return
        Thread({ synchronized(lock) { controller }?.stop(sessionId) }, "apk-sentinel-root-capture-stop").apply {
            isDaemon = true
            start()
        }
    }

    fun shutdown() {
        eraseForPrivacy()
        synchronized(lock) {
            runtime?.shutdown()
            runtime = null
            controller = null
        }
    }
}
