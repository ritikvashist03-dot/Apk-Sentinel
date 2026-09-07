package app.apksentinel.engine.rootcapture.android

import android.content.Context
import app.apksentinel.engine.rootcapture.RootCaptureCommand
import app.apksentinel.engine.rootcapture.RootCaptureCommandAvailability
import app.apksentinel.engine.rootcapture.RootCaptureOutputCreate
import app.apksentinel.engine.rootcapture.RootCaptureOutputStore
import app.apksentinel.engine.rootcapture.RootCapturePrivilegeRunner
import app.apksentinel.engine.rootcapture.RootCaptureProcessLaunch
import app.apksentinel.engine.rootcapture.RootCaptureProcessTermination
import app.apksentinel.engine.rootcapture.RootCaptureRootAvailability
import app.apksentinel.engine.rootcapture.RootCaptureRunningProcess
import app.apksentinel.engine.rootcapture.RootCaptureSafeShellSerializer
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit

/**
 * Android adapter for a user-approved root manager. It never calls this class
 * on its own; [RootCapturePrivilegeRunner] is reached only through the
 * consent-gated controller. No root binary or capture tool is bundled.
 */
class AndroidProcessBuilderRootRunner : RootCapturePrivilegeRunner {
    override fun rootAvailability(): RootCaptureRootAvailability {
        val probe = runForProbe(RootCaptureCommand("id", listOf("-u")))
        return when {
            probe.launchFailure -> RootCaptureRootAvailability.SU_UNAVAILABLE
            probe.completed && probe.exitCode == 0 && probe.stdout.trim() == "0" -> RootCaptureRootAvailability.AVAILABLE
            probe.completed -> RootCaptureRootAvailability.ACCESS_DENIED
            else -> RootCaptureRootAvailability.PROBE_FAILED
        }
    }

    override fun commandAvailability(command: RootCaptureCommand): RootCaptureCommandAvailability {
        val probe = runForProbe(command)
        return when {
            probe.launchFailure -> RootCaptureCommandAvailability.UNAVAILABLE
            // tcpdump commonly returns either 0 or 1 after printing its fixed help text.
            probe.completed && probe.exitCode in 0..1 -> RootCaptureCommandAvailability.AVAILABLE
            probe.completed -> RootCaptureCommandAvailability.UNAVAILABLE
            else -> RootCaptureCommandAvailability.PROBE_FAILED
        }
    }

    override fun start(command: RootCaptureCommand): RootCaptureProcessLaunch = try {
        val process = ProcessBuilder("su", "-c", RootCaptureSafeShellSerializer.serialize(command))
            .redirectInput(ProcessBuilder.Redirect.PIPE)
            .start()
        RootCaptureProcessLaunch.Started(AndroidRunningProcess(process))
    } catch (_: Exception) {
        RootCaptureProcessLaunch.Rejected
    }

    private fun runForProbe(command: RootCaptureCommand): ProbeResult = try {
        val process = ProcessBuilder("su", "-c", RootCaptureSafeShellSerializer.serialize(command)).start()
        val completed = process.waitFor(2L, TimeUnit.SECONDS)
        if (!completed) {
            process.destroyForcibly()
            return ProbeResult(completed = false, exitCode = -1, stdout = "", launchFailure = false)
        }
        val output = process.inputStream.use { input -> input.readBoundedText(64) }
        ProbeResult(completed, if (completed) process.exitValue() else -1, output, launchFailure = false)
    } catch (_: Exception) {
        ProbeResult(completed = false, exitCode = -1, stdout = "", launchFailure = true)
    }

    private data class ProbeResult(
        val completed: Boolean,
        val exitCode: Int,
        val stdout: String,
        val launchFailure: Boolean,
    )
}

private class AndroidRunningProcess(private val process: Process) : RootCaptureRunningProcess {
    @Volatile private var stoppedByHost = false

    override fun stdout(): InputStream = process.inputStream

    override fun stop() {
        stoppedByHost = true
        runCatching {
            process.destroy()
            if (!process.waitFor(750L, TimeUnit.MILLISECONDS)) process.destroyForcibly()
        }
    }

    override fun setTerminationListener(listener: (RootCaptureProcessTermination) -> Unit) {
        Thread({
            val exit = runCatching { process.waitFor() }.getOrDefault(-1)
            listener(
                if (stoppedByHost || exit == 0) RootCaptureProcessTermination.EXITED else RootCaptureProcessTermination.DIED,
            )
        }, "apk-sentinel-root-capture-exit").apply {
            isDaemon = true
            start()
        }
        Thread({
            // Avoid a privileged process blocking on diagnostic output. Diagnostics are never logged or exported.
            runCatching { process.errorStream.use { input -> input.drainBounded() } }
        }, "apk-sentinel-root-capture-stderr").apply {
            isDaemon = true
            start()
        }
    }
}

/** App-private cache only. A host exports through SAF by passing an already-open destination stream. */
class AndroidPrivateRootCaptureOutputStore(context: Context) : RootCaptureOutputStore {
    private val directory = File(context.cacheDir, "root-capture")

    override fun create(sessionId: String): RootCaptureOutputCreate = try {
        if (!sessionId.matches(Regex("^[0-9a-f-]{36}$"))) return RootCaptureOutputCreate.Unavailable
        if (!directory.exists() && !directory.mkdirs()) return RootCaptureOutputCreate.Unavailable
        directory.setReadable(true, true)
        directory.setWritable(true, true)
        directory.setExecutable(true, true)
        val file = fileFor(sessionId) ?: return RootCaptureOutputCreate.Unavailable
        if (file.exists() && !file.delete()) return RootCaptureOutputCreate.Unavailable
        val stream = FileOutputStream(file, false)
        file.setReadable(true, true)
        file.setWritable(true, true)
        RootCaptureOutputCreate.Ready(stream)
    } catch (_: Exception) {
        RootCaptureOutputCreate.Unavailable
    }

    override fun erase(sessionId: String): Boolean = fileFor(sessionId)?.let { file ->
        if (!file.exists()) true else secureEraseAndDelete(file)
    } ?: false

    override fun eraseAll(): Boolean {
        if (!directory.exists()) return true
        return runCatching {
            val root = directory.canonicalFile
            val children = directory.listFiles() ?: return false
            children.filter {
                it.isFile && it.parentFile?.canonicalFile == root && it.canonicalFile.parentFile == root
            }.all { secureEraseAndDelete(it) }
        }.getOrDefault(false)
    }

    override fun copyTo(sessionId: String, destination: OutputStream, maximumBytes: Long): Boolean {
        val file = fileFor(sessionId)?.takeIf { it.isFile && it.length() <= maximumBytes } ?: return false
        val buffer = ByteArray(4 * 1_024)
        return try {
            FileInputStream(file).use { input ->
                var copied = 0L
                while (true) {
                    val remaining = maximumBytes - copied
                    if (remaining <= 0L) break
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                    if (count < 0) break
                    if (count == 0) continue
                    destination.write(buffer, 0, count)
                    copied += count.toLong()
                }
                destination.flush()
            }
            true
        } catch (_: Exception) {
            false
        } finally {
            buffer.fill(0)
        }
    }

    private fun fileFor(sessionId: String): File? {
        if (!sessionId.matches(Regex("^[0-9a-f-]{36}$"))) return null
        return File(directory, "$sessionId.pcap").takeIf {
            runCatching { it.parentFile?.canonicalFile == directory.canonicalFile && it.canonicalFile.parentFile == directory.canonicalFile }
                .getOrDefault(false)
        }
    }

    /** Best-effort zeroization before deletion; the app never claims forensic disk erasure. */
    private fun secureEraseAndDelete(file: File): Boolean = runCatching {
        if (file.isFile) {
            val length = file.length()
            FileOutputStream(file, false).use { output ->
                val zeros = ByteArray(4 * 1_024)
                var remaining = minOf(length, 8L * 1024L * 1024L)
                while (remaining > 0L) {
                    val count = minOf(remaining, zeros.size.toLong()).toInt()
                    output.write(zeros, 0, count)
                    remaining -= count.toLong()
                }
                output.fd.sync()
                zeros.fill(0)
            }
        }
        file.delete()
    }.getOrDefault(false)
}

private fun InputStream.readBoundedText(limit: Int): String {
    val bytes = ByteArray(limit)
    val count = read(bytes, 0, limit).coerceAtLeast(0)
    return bytes.copyOf(count).toString(Charsets.US_ASCII)
}

private fun InputStream.drainBounded() {
    val bytes = ByteArray(1_024)
    var remaining = 8 * 1_024
    while (remaining > 0) {
        val read = read(bytes, 0, minOf(bytes.size, remaining))
        if (read < 0) break
        remaining -= read
    }
    bytes.fill(0)
}
