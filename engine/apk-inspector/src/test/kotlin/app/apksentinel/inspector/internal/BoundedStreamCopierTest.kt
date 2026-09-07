package app.apksentinel.inspector.internal

import app.apksentinel.inspector.InspectionCancellation
import app.apksentinel.inspector.InspectionCancelledException
import app.apksentinel.inspector.InspectionProgressListener
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class BoundedStreamCopierTest {
    @Test
    fun copiesOnlyThroughTheBoundedStreamAndCalculatesSha256() {
        val output = ByteArrayOutputStream()

        val result = BoundedStreamCopier.copy(
            input = ByteArrayInputStream("abc".toByteArray()),
            output = output,
            maximumBytes = 3,
            control = control(),
        )

        assertEquals("abc", output.toString())
        assertEquals(3, result.byteCount)
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            result.sha256,
        )
    }

    @Test
    fun rejectsInputBeforeWritingPastTheConfiguredLimit() {
        val output = ByteArrayOutputStream()

        try {
            BoundedStreamCopier.copy(
                input = ByteArrayInputStream(ByteArray(8) { 0x41 }),
                output = output,
                maximumBytes = 4,
                control = control(),
            )
        } catch (error: ByteLimitExceededException) {
            assertTrue(error.observedBytes > 4)
            assertEquals(0, output.size())
            return
        }

        throw AssertionError("Expected a ByteLimitExceededException")
    }

    @Test
    fun checksTheCallerCancellationSignalBeforeReading() {
        try {
            BoundedStreamCopier.copy(
                input = ByteArrayInputStream(byteArrayOf(1)),
                output = ByteArrayOutputStream(),
                maximumBytes = 1,
                control = control(InspectionCancellation { true }),
            )
        } catch (error: InspectionCancelledException) {
            return
        }

        throw AssertionError("Expected inspection cancellation")
    }

    private fun control(
        cancellation: InspectionCancellation = InspectionCancellation.None,
    ): InspectionControl = InspectionControl(
        cancellation = cancellation,
        progressListener = InspectionProgressListener { },
    )
}
