package app.apksentinel.engine.tlsinspection

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DecryptedSessionRecorderTest {

    @Test
    fun retainsNothingUntilExplicitlyConsented() {
        val recorder = DecryptedSessionRecorder()
        recorder.record(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, segment("GET /a"), 1L)

        val snapshot = recorder.snapshot()
        assertFalse(snapshot.enabledForSession)
        assertEquals(0, snapshot.segmentCount)
        assertEquals(0, snapshot.retainedBytes)
    }

    @Test
    fun aConsentedSessionIsRetainedAndExportable() {
        val recorder = DecryptedSessionRecorder(activeConfiguration())
        recorder.record(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, segment("GET /a HTTP/1.1"), 10L)
        recorder.record(TlsInspectionPlaintextDirection.UPSTREAM_TO_CLIENT, segment("HTTP/1.1 200 OK"), 20L)

        assertEquals(2, recorder.snapshot().segmentCount)
        val output = ByteArrayOutputStream()
        val written = recorder.exportTo(output)

        val text = output.toString("UTF-8")
        assertTrue(written > 0)
        assertTrue(text.contains("GET /a HTTP/1.1"))
        assertTrue(text.contains("HTTP/1.1 200 OK"))
        assertTrue(text.contains("CLIENT_TO_UPSTREAM"))
        // Must not claim to be a capture container.
        assertTrue(text.contains("not a packet capture"))
    }

    @Test
    fun aSegmentLargerThanThePerSegmentBoundIsTruncatedNotDropped() {
        val recorder = DecryptedSessionRecorder(activeConfiguration(maximumSegmentBytes = 256))
        recorder.record(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, segment("x".repeat(1_000)), 1L)

        assertEquals(1, recorder.snapshot().segmentCount)
        assertEquals(256, recorder.snapshot().retainedBytes)
        assertTrue(recorder.exportTo(ByteArrayOutputStream()) > 0)
    }

    @Test
    fun theSegmentCountStaysBoundedAndEvictsOldestFirst() {
        val recorder = DecryptedSessionRecorder(activeConfiguration(maximumSegments = 3))
        repeat(6) { index ->
            recorder.record(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, segment("body$index"), index.toLong())
        }

        val snapshot = recorder.snapshot()
        assertEquals(3, snapshot.segmentCount)
        assertTrue(snapshot.droppedSegments >= 3L)
        val text = ByteArrayOutputStream().also { recorder.exportTo(it) }.toString("UTF-8")
        assertFalse(text.contains("body0"))
        assertTrue(text.contains("body5"))
    }

    @Test
    fun theTotalByteBoundIsRespected() {
        val recorder = DecryptedSessionRecorder(
            activeConfiguration(maximumTotalBytes = 2_048, maximumSegmentBytes = 512),
        )
        repeat(20) { index ->
            recorder.record(TlsInspectionPlaintextDirection.UPSTREAM_TO_CLIENT, segment("y".repeat(512)), index.toLong())
        }
        assertTrue(recorder.snapshot().retainedBytes <= 2_048)
    }

    @Test
    fun clearingZeroizesRatherThanJustDroppingReferences() {
        val recorder = DecryptedSessionRecorder(activeConfiguration())
        recorder.record(TlsInspectionPlaintextDirection.CLIENT_TO_UPSTREAM, segment("secret-token"), 1L)
        recorder.clear()

        val snapshot = recorder.snapshot()
        assertEquals(0, snapshot.segmentCount)
        assertEquals(0, snapshot.retainedBytes)
        val text = ByteArrayOutputStream().also { recorder.exportTo(it) }.toString("UTF-8")
        assertFalse(text.contains("secret-token"))
    }

    private fun activeConfiguration(
        maximumSegments: Int = 256,
        maximumTotalBytes: Int = 512 * 1_024,
        maximumSegmentBytes: Int = 16 * 1_024,
    ) = DecryptedSessionConfiguration(
        enabled = true,
        consent = DecryptedSessionConsent("decrypted-session-test", 1L),
        maximumSegments = maximumSegments,
        maximumTotalBytes = maximumTotalBytes,
        maximumSegmentBytes = maximumSegmentBytes,
    )

    private fun segment(text: String): EphemeralTlsDecryptedSegment {
        val bytes = text.toByteArray(Charsets.UTF_8)
        return EphemeralTlsDecryptedSegment(bytes, bytes.size)
    }
}
