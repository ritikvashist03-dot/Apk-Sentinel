package app.apksentinel.inspector.internal

import app.apksentinel.inspector.InspectionCancellation
import app.apksentinel.inspector.InspectionCancelledException
import app.apksentinel.inspector.InspectionProgress
import app.apksentinel.inspector.InspectionProgressListener
import app.apksentinel.inspector.InspectionProgressCode
import app.apksentinel.inspector.InspectionStage

internal class InspectionControl(
    private val cancellation: InspectionCancellation,
    private val progressListener: InspectionProgressListener,
) {
    fun ensureActive() {
        if (cancellation.isCancelled()) {
            throw InspectionCancelledException()
        }
    }

    fun report(
        stage: InspectionStage,
        code: InspectionProgressCode,
        bytesProcessed: Long? = null,
        bytesLimit: Long? = null,
        entriesProcessed: Int? = null,
    ) {
        ensureActive()
        progressListener.onProgress(
            InspectionProgress(
                stage = stage,
                code = code,
                bytesProcessed = bytesProcessed,
                bytesLimit = bytesLimit,
                entriesProcessed = entriesProcessed,
            ),
        )
    }
}
