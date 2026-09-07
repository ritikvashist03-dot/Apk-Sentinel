package app.apksentinel.inspector.internal

import android.content.ContentResolver
import android.net.Uri
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.InspectionStage
import app.apksentinel.inspector.InspectionFailure
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.SourceArtifact
import app.apksentinel.inspector.SourceSizeLimitExceeded
import app.apksentinel.inspector.SourceUnavailable
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

internal class TemporaryArtifactCopier(
    private val contentResolver: ContentResolver,
    private val cacheDirectory: File,
) {
    fun copy(
        uri: Uri,
        limits: InspectionLimits,
        control: InspectionControl,
    ): TempCopyOutcome {
        val tempFile = try {
            File.createTempFile("apk-inspector-", ".zip", cacheDirectory)
        } catch (error: IOException) {
            return TempCopyOutcome.Failure(
                SourceUnavailable(
                    code = InspectionFailureCode.TEMP_FILE_CREATION_FAILED,
                ),
            )
        }

        var completed = false
        try {
            val source = try {
                contentResolver.openInputStream(uri)
            } catch (error: SecurityException) {
                return TempCopyOutcome.Failure(
                    SourceUnavailable(
                        code = InspectionFailureCode.SOURCE_PERMISSION_DENIED,
                    ),
                )
            } catch (error: IOException) {
                return TempCopyOutcome.Failure(
                    SourceUnavailable(
                        code = InspectionFailureCode.SOURCE_OPEN_FAILED,
                    ),
                )
            }

            if (source == null) {
                return TempCopyOutcome.Failure(
                    SourceUnavailable(
                        code = InspectionFailureCode.SOURCE_NOT_FOUND,
                    ),
                )
            }

            val copied = source.use { input ->
                BufferedOutputStream(FileOutputStream(tempFile)).use { output ->
                    BoundedStreamCopier.copy(
                        input = BufferedInputStream(input),
                        output = output,
                        maximumBytes = limits.maxInputBytes,
                        control = control,
                    )
                }
            }
            completed = true
            return TempCopyOutcome.Success(
                file = tempFile,
                source = SourceArtifact(
                    byteCount = copied.byteCount,
                    sha256 = copied.sha256,
                ),
            )
        } catch (limit: ByteLimitExceededException) {
            return TempCopyOutcome.Failure(
                SourceSizeLimitExceeded(
                    observedBytes = limit.observedBytes,
                    maximumBytes = limits.maxInputBytes,
                ),
            )
        } catch (error: IOException) {
            return TempCopyOutcome.Failure(
                SourceUnavailable(
                    code = InspectionFailureCode.SOURCE_COPY_FAILED,
                ),
            )
        } finally {
            if (!completed && tempFile.exists()) {
                tempFile.delete()
            }
        }
    }
}

internal sealed interface TempCopyOutcome {
    data class Success(
        val file: File,
        val source: SourceArtifact,
    ) : TempCopyOutcome

    data class Failure(val failure: InspectionFailure) : TempCopyOutcome
}

internal data class DigestCopyResult(
    val byteCount: Long,
    val sha256: String,
)

internal class ByteLimitExceededException(
    val observedBytes: Long,
) : IOException("Input exceeded a configured byte limit.")

internal object BoundedStreamCopier {
    private const val BUFFER_SIZE = 32 * 1024
    private const val PROGRESS_INTERVAL_BYTES = 512 * 1024L

    fun copy(
        input: InputStream,
        output: OutputStream,
        maximumBytes: Long,
        control: InspectionControl,
    ): DigestCopyResult {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0L
        var nextProgress = PROGRESS_INTERVAL_BYTES

        while (true) {
            control.ensureActive()
            val read = input.read(buffer)
            if (read < 0) {
                break
            }
            if (read == 0) {
                continue
            }

            val nextTotal = total + read
            if (nextTotal > maximumBytes) {
                throw ByteLimitExceededException(nextTotal)
            }

            output.write(buffer, 0, read)
            digest.update(buffer, 0, read)
            total = nextTotal

            if (total >= nextProgress) {
                control.report(
                    stage = InspectionStage.COPY_INPUT,
                    code = app.apksentinel.inspector.InspectionProgressCode.COPYING_PRIVATE_ARTIFACT,
                    bytesProcessed = total,
                    bytesLimit = maximumBytes,
                )
                nextProgress = total + PROGRESS_INTERVAL_BYTES
            }
        }

        output.flush()
        return DigestCopyResult(
            byteCount = total,
            sha256 = digest.digest().toHex(),
        )
    }
}

private fun ByteArray.toHex(): String =
    joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
