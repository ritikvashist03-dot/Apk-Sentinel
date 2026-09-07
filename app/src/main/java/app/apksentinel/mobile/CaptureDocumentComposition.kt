package app.apksentinel.mobile

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import app.apksentinel.networkmonitor.AndroidCaptureDocumentMetadataReader
import app.apksentinel.networkmonitor.AndroidEncryptedCaptureMetadataStore
import app.apksentinel.networkmonitor.CaptureDocumentFormat
import app.apksentinel.networkmonitor.CaptureDocumentInspector
import app.apksentinel.networkmonitor.CaptureDocumentLibrary
import app.apksentinel.networkmonitor.CaptureDocumentRecord
import app.apksentinel.networkmonitor.CaptureInspectionFailure
import app.apksentinel.networkmonitor.CaptureInspectionLimits
import app.apksentinel.networkmonitor.CaptureInspectionResult
import app.apksentinel.networkmonitor.CaptureMetadataPersistenceState
import app.apksentinel.networkmonitor.CaptureMetadataWriteOutcome
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** A bounded, payload-free view model for SAF-selected capture documents. */
internal data class CaptureDocumentInspectionState(
    val uri: String,
    val record: CaptureDocumentRecord?,
    val result: CaptureInspectionResult?,
    val busy: Boolean,
    val catalogState: CaptureMetadataPersistenceState = CaptureMetadataPersistenceState.READY,
)

/**
 * Process-scoped composition. SAF I/O and PCAP parsing are always performed on
 * [worker]; the UI receives only bounded summaries and stable reason codes.
 */
internal object CaptureDocumentComposition {
    private val lock = Any()
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "apk-sentinel-capture-inspector").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var library: CaptureDocumentLibrary? = null
    @Volatile private var encryptedStore: AndroidEncryptedCaptureMetadataStore? = null
    @Volatile private var currentState: CaptureDocumentInspectionState? = null

    fun initialize(context: Context) {
        val application = context.applicationContext
        synchronized(lock) {
            if (library == null) {
                encryptedStore = AndroidEncryptedCaptureMetadataStore(application)
                library = CaptureDocumentLibrary(requireNotNull(encryptedStore))
            }
        }
    }

    fun snapshot(context: Context): List<CaptureDocumentRecord> {
        initialize(context)
        return library?.snapshot().orEmpty()
    }

    fun currentInspection(): CaptureDocumentInspectionState? = currentState

    fun persistenceState(context: Context): CaptureMetadataPersistenceState {
        initialize(context)
        return library?.persistenceState() ?: CaptureMetadataPersistenceState.UNAVAILABLE
    }

    fun openAndInspect(
        context: Context,
        uri: Uri,
        onComplete: (CaptureDocumentInspectionState) -> Unit,
    ) {
        initialize(context)
        val application = context.applicationContext
        val uriText = uri.toString()
        currentState = CaptureDocumentInspectionState(uriText, null, null, busy = true, catalogState = persistenceState(context))
        submit {
            val active = requireNotNull(library)
            val reader = AndroidCaptureDocumentMetadataReader(application.contentResolver)
            var record = active.recordOpenedOutcome(uriText, reader).record
            val inspection = inspect(application, uri)
            if (inspection is CaptureInspectionResult.Opened) {
                record = active.updateFormat(uriText, inspection.summary.format.let {
                    when (it) {
                        app.apksentinel.networkmonitor.CaptureInspectionFormat.PCAP -> CaptureDocumentFormat.PCAP
                        app.apksentinel.networkmonitor.CaptureInspectionFormat.PCAPNG -> CaptureDocumentFormat.PCAPNG
                    }
                }) ?: record
            }
            val state = CaptureDocumentInspectionState(uriText, record, inspection, busy = false, catalogState = active.persistenceState())
            currentState = state
            deliver { onComplete(state) }
        }
    }

    /** Records a user-created raw capture without pretending it was inspected yet. */
    fun recordCreated(context: Context, uri: Uri, onComplete: (CaptureMetadataWriteOutcome) -> Unit = {}) {
        initialize(context)
        val application = context.applicationContext
        submit {
            val outcome = library?.recordCreatedOutcome(uri.toString(), AndroidCaptureDocumentMetadataReader(application.contentResolver))
            deliver { onComplete(outcome?.outcome ?: CaptureMetadataWriteOutcome.UNAVAILABLE) }
        }
    }

    fun refresh(context: Context, onComplete: (List<CaptureDocumentRecord>) -> Unit) {
        initialize(context)
        val application = context.applicationContext
        submit {
            val rows = library?.refreshOutcome(AndroidCaptureDocumentMetadataReader(application.contentResolver))?.records.orEmpty()
            deliver { onComplete(rows) }
        }
    }

    fun forget(context: Context, record: CaptureDocumentRecord, onComplete: (Boolean) -> Unit) {
        initialize(context)
        val resolver = context.applicationContext.contentResolver
        submit {
            val removed = library?.forget(record.uri) { value ->
                runCatching { resolver.releasePersistableUriPermission(Uri.parse(value), android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            } == true
            deliver { onComplete(removed) }
        }
    }

    fun erase(context: Context, onComplete: (Int) -> Unit) {
        initialize(context)
        val resolver = context.applicationContext.contentResolver
        submit {
            val removed = library?.erase { value ->
                runCatching { resolver.releasePersistableUriPermission(Uri.parse(value), android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            } ?: 0
            deliver { onComplete(removed) }
        }
    }

    /** Used by the privacy transaction; bounded so a provider cannot hold the UI forever. */
    fun eraseBlocking(context: Context, timeoutMillis: Long = 2_000L): Boolean {
        initialize(context)
        val resolver = context.applicationContext.contentResolver
        val done = CountDownLatch(1)
        var confirmed = false
        submit {
            val erased = library?.eraseOutcome { value ->
                runCatching { resolver.releasePersistableUriPermission(Uri.parse(value), android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            }
            val keyRemoved = if (erased?.outcome == app.apksentinel.networkmonitor.CaptureMetadataRemoveOutcome.REMOVED) {
                encryptedStore?.eraseEncryptionKey() ?: false
            } else false
            confirmed = erased?.outcome == app.apksentinel.networkmonitor.CaptureMetadataRemoveOutcome.REMOVED && keyRemoved
            done.countDown()
        }
        return runCatching { done.await(timeoutMillis, TimeUnit.MILLISECONDS) && confirmed }.getOrDefault(false)
    }

    private fun inspect(context: Context, uri: Uri): CaptureInspectionResult {
        val stream = runCatching { context.contentResolver.openInputStream(uri) }.getOrNull()
            ?: return CaptureInspectionResult.Rejected(CaptureInspectionFailure.ENCRYPTED_OR_OPAQUE)
        return stream.use { CaptureDocumentInspector.inspect(it, CaptureInspectionLimits()) }
    }

    private fun submit(task: () -> Unit) {
        runCatching { worker.execute(task) }
    }

    private fun deliver(task: () -> Unit) {
        runCatching { main.post(task) }
    }
}
