package app.apksentinel.engine.tlsinspection

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsKeyLogRecorderTest {

    @Test
    fun retainsNothingUntilExplicitlyConsented() {
        val recorder = TlsKeyLogRecorder()
        recorder.record(listOf(tls12Secrets()))

        val snapshot = recorder.snapshot()
        assertFalse(snapshot.enabledForSession)
        assertEquals(0, snapshot.lineCount)
        assertNull(recorder.drainPendingBlock())
        assertEquals(0L, recorder.exportTo(ByteArrayOutputStream()))
    }

    @Test
    fun aConsentedRecorderExportsNssKeyLogText() {
        val recorder = TlsKeyLogRecorder(activeConfiguration())
        recorder.record(listOf(tls12Secrets()))

        val output = ByteArrayOutputStream()
        val written = recorder.exportTo(output)
        val text = output.toString("US-ASCII")

        assertTrue(written > 0)
        assertTrue(text.startsWith("CLIENT_RANDOM "))
        assertTrue(text.endsWith("\n"))
        assertEquals(1, recorder.snapshot().lineCount)
    }

    @Test
    fun drainingReturnsOnlyWhatIsNewSoACaptureIsNotGivenDuplicateKeys() {
        val recorder = TlsKeyLogRecorder(activeConfiguration())
        recorder.record(listOf(tls12Secrets(0x11)))

        val first = recorder.drainPendingBlock()
        assertTrue(first != null && first.isNotEmpty())
        assertNull("A second drain with nothing new must yield nothing", recorder.drainPendingBlock())

        recorder.record(listOf(tls12Secrets(0x22)))
        val second = requireNotNull(recorder.drainPendingBlock())
        assertEquals(1, second.toString(Charsets.US_ASCII).trim().lines().size)
    }

    @Test
    fun theLineBoundStopsAcceptingRatherThanEvicting() {
        // Evicting would decrypt an arbitrary subset of the capture with no way to tell
        // which part went missing, which is harder to interpret than a reported cut-off.
        val recorder = TlsKeyLogRecorder(activeConfiguration(maximumLines = 2))
        repeat(5) { recorder.record(listOf(tls12Secrets(it.toByte()))) }

        val snapshot = recorder.snapshot()
        assertEquals(2, snapshot.lineCount)
        assertEquals(3L, snapshot.droppedLines)
    }

    @Test
    fun aTls13SessionContributesOneLinePerTrafficSecret() {
        val recorder = TlsKeyLogRecorder(activeConfiguration())
        recorder.record(
            listOf(
                TlsKeyLogSecrets(
                    clientRandom = ByteArray(32) { 1 },
                    clientHandshakeTrafficSecret = ByteArray(32) { 2 },
                    serverHandshakeTrafficSecret = ByteArray(32) { 3 },
                ),
                TlsKeyLogSecrets(
                    clientRandom = ByteArray(32) { 1 },
                    clientApplicationTrafficSecret = ByteArray(32) { 4 },
                    serverApplicationTrafficSecret = ByteArray(32) { 5 },
                ),
            ),
        )

        assertEquals(4, recorder.snapshot().lineCount)
        val text = ByteArrayOutputStream().also { recorder.exportTo(it) }.toString("US-ASCII")
        assertTrue(text.contains(TlsKeyLog.LABEL_CLIENT_APPLICATION))
        assertTrue(text.contains(TlsKeyLog.LABEL_SERVER_APPLICATION))
    }

    @Test
    fun clearingLeavesNothingExportable() {
        val recorder = TlsKeyLogRecorder(activeConfiguration())
        val secrets = tls12Secrets(0x7f)
        recorder.record(listOf(secrets))
        recorder.clear()

        assertEquals(0, recorder.snapshot().lineCount)
        assertEquals(0L, recorder.exportTo(ByteArrayOutputStream()))
        // Zeroized in place, not merely dereferenced.
        assertTrue(secrets.masterSecret!!.all { it.toInt() == 0 })
    }

    @Test
    fun anEmptySecretContributesNoLineRatherThanABlankOne() {
        val recorder = TlsKeyLogRecorder(activeConfiguration())
        recorder.record(listOf(TlsKeyLogSecrets(clientRandom = ByteArray(32))))

        assertEquals(0, recorder.snapshot().lineCount)
        assertNull(recorder.drainPendingBlock())
    }

    private fun activeConfiguration(maximumLines: Int = 4_096) = TlsKeyLogConfiguration(
        enabled = true,
        consent = TlsKeyLogConsent("tls-key-log-test", 1L),
        maximumLines = maximumLines,
    )

    private fun tls12Secrets(fill: Byte = 0x33) = TlsKeyLogSecrets(
        clientRandom = ByteArray(32) { fill },
        masterSecret = ByteArray(48) { fill },
    )
}
