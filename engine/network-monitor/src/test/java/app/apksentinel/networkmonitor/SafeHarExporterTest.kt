package app.apksentinel.networkmonitor

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SafeHarExporterTest {
    @Test
    fun writesHarJsonAndRedactsCredentialHeadersUrlUserInfoAndQuerySecrets() {
        val output = ByteArrayOutputStream()
        val result = SafeHarExporter.write(
            listOf(
                observation(
                    url = "https://user:password@example.test/path?token=top-secret&safe=ok#fragment",
                    requestHeaders = mapOf("Authorization" to "Bearer private", "X-Safe" to "yes"),
                    responseHeaders = mapOf("Set-Cookie" to "session=private"),
                    complete = true,
                ),
            ),
            output,
        )
        val json = output.toString(Charsets.UTF_8.name())

        assertEquals(1, result.entriesWritten)
        assertFalse(result.truncated)
        assertTrue(json.startsWith("{\"log\":{\"version\":\"1.2\""))
        assertTrue(json.endsWith("]}}"))
        assertTrue(json.contains("https://example.test/path?token=[REDACTED]&safe=ok"))
        assertTrue(json.contains("\"value\":\"[REDACTED]\""))
        assertFalse(json.contains("top-secret"))
        assertFalse(json.contains("Bearer private"))
        assertFalse(json.contains("session=private"))
        assertFalse(json.contains("user:password"))
    }

    @Test
    fun omitsTextAndBinaryBodiesWhileRecordingBoundedSize() {
        val bytes = byteArrayOf(0, 1, 2, 0x7F, 0xFF.toByte())
        val output = ByteArrayOutputStream()
        val result = SafeHarExporter.write(listOf(observation(body = bytes, bodyIsBinary = true, complete = true)), output)
        val json = output.toString(Charsets.UTF_8.name())

        assertEquals(bytes.size.toLong(), result.bodyBytesWritten)
        assertTrue(json.contains("\"_apkSentinelBodyOmitted\":true"))
        assertFalse(json.contains("\"text\":"))
        assertFalse(json.contains("encoding"))
    }

    @Test
    fun boundsEntriesBodiesAndHeadersWithoutFalsePositiveAtExactEntryLimit() {
        val exactOutput = ByteArrayOutputStream()
        val exact = SafeHarExporter.write(
            listOf(observation(body = ByteArray(1_024), complete = true)),
            exactOutput,
            HarExportLimits(maximumEntries = 1, maximumBodyBytes = 1_024, maximumHeaderCount = 1),
        )
        assertFalse(exact.truncated)

        val output = ByteArrayOutputStream()
        val result = SafeHarExporter.write(
            listOf(
                observation(
                    body = ByteArray(1_025) { 4 },
                    requestHeaders = mapOf("one" to "1", "two" to "2"),
                    complete = true,
                ),
                observation(complete = true),
            ),
            output,
            HarExportLimits(maximumEntries = 1, maximumBodyBytes = 1_024, maximumHeaderCount = 1),
        )
        val json = output.toString(Charsets.UTF_8.name())
        assertEquals(1, result.entriesWritten)
        assertEquals(1_024L, result.bodyBytesWritten)
        assertTrue(result.truncated)
        assertFalse(json.contains("\"name\":\"two\""))
    }

    @Test
    fun redactsBroadCredentialHeadersAndDoesNotAddEmptyQueryMarker() {
        val output = ByteArrayOutputStream()
        SafeHarExporter.write(
            listOf(
                observation(
                    url = "https://example.test/path?",
                    requestHeaders = mapOf(
                        "X-Api-Key" to "key-value",
                        "X-Amz-Security-Token" to "cloud-token",
                        "X-Trace-Id" to "safe-id",
                        "Client-Password-Reset" to "password-value",
                    ),
                    body = "password=secret&token=private".encodeToByteArray(),
                    complete = true,
                ),
            ),
            output,
        )
        val json = output.toString(Charsets.UTF_8.name())

        assertTrue(json.contains("https://example.test/path\""))
        assertFalse(json.contains("https://example.test/path?\""))
        assertFalse(json.contains("key-value"))
        assertFalse(json.contains("cloud-token"))
        assertFalse(json.contains("password-value"))
        assertTrue(json.contains("safe-id"))
        assertFalse(json.contains("password=secret"))
    }

    @Test
    fun streamsAdversarialIterableAndStopsAtEntryAndOutputBudgets() {
        val output = ByteArrayOutputStream()
        var requested = 0
        val infinite = Iterable {
            object : Iterator<HttpPayloadObservation> {
                override fun hasNext(): Boolean = true
                override fun next(): HttpPayloadObservation {
                    requested++
                    return observation(url = "https://example.test/$requested", complete = true)
                }
            }
        }

        val result = SafeHarExporter.write(
            infinite,
            output,
            HarExportLimits(maximumEntries = 3, maximumBodyBytes = 1_024, maximumHeaderCount = 1, maximumOutputBytes = 32 * 1_024),
        )

        assertEquals(3, result.entriesWritten)
        assertTrue(result.truncated)
        assertTrue(requested <= 3)
        assertTrue(output.size() <= 32 * 1_024)
        assertTrue(output.toString(Charsets.UTF_8.name()).endsWith("]}}"))
    }

    @Test
    fun marksIncompleteObservationsAndPreservesEscapedJsonValues() {
        val output = ByteArrayOutputStream()
        val result = SafeHarExporter.write(
            listOf(observation(method = "M\"ET", url = "https://example.test/a\nb", complete = false)),
            output,
        )
        val json = output.toString(Charsets.UTF_8.name())

        assertTrue(result.truncated)
        assertTrue(json.contains("\"_apkSentinelComplete\":false"))
        assertTrue(json.contains("M\\\"ET"))
        assertTrue(json.contains("a\\nb"))
    }

    private fun observation(
        url: String = "https://example.test/",
        method: String = "GET",
        requestHeaders: Map<String, String> = emptyMap(),
        responseHeaders: Map<String, String> = emptyMap(),
        body: ByteArray? = null,
        bodyIsBinary: Boolean = false,
        complete: Boolean,
    ): HttpPayloadObservation = HttpPayloadObservation(
        url = url,
        method = method,
        status = 200,
        requestHeaders = requestHeaders,
        responseHeaders = responseHeaders,
        body = body,
        bodyMimeType = "application/octet-stream",
        bodyIsBinary = bodyIsBinary,
        startedAtMillis = 1_700_000_000_000L,
        durationMillis = 12L,
        complete = complete,
    )
}
