package app.apksentinel.networkmonitor

import java.io.OutputStream

data class HarExportLimits(
    val maximumEntries: Int = 512,
    val maximumBodyBytes: Int = 512 * 1_024,
    val maximumHeaderCount: Int = 64,
    val maximumOutputBytes: Int = 2 * 1_024 * 1_024,
) {
    init {
        require(maximumEntries in 1..10_000)
        require(maximumBodyBytes in 1_024..8 * 1_024 * 1_024)
        require(maximumHeaderCount in 1..256)
        require(maximumOutputBytes in 1_024..8 * 1_024 * 1_024)
    }
}

data class HttpPayloadObservation(
    val url: String,
    val method: String,
    val status: Int? = null,
    val requestHeaders: Map<String, String> = emptyMap(),
    val responseHeaders: Map<String, String> = emptyMap(),
    val body: ByteArray? = null,
    val bodyMimeType: String? = null,
    val bodyIsBinary: Boolean = false,
    val startedAtMillis: Long,
    val durationMillis: Long = 0L,
    val complete: Boolean = false,
) {
    init { require(url.length in 1..8_192); require(method.length in 1..32); require(status == null || status in 100..599); require(startedAtMillis >= 0L); require(durationMillis >= 0L) }
}

data class HarExportResult(val entriesWritten: Int, val bodyBytesWritten: Long, val truncated: Boolean)

/** HAR 1.2 writer. Only observations supplied by the host are exported. */
object SafeHarExporter {
    const val MIME_TYPE = "application/json"
    private val sensitiveQueryKeys = setOf(
        "token", "access_token", "refresh_token", "password", "secret", "key", "auth",
        "api_key", "apikey", "client_secret", "credential", "credentials", "signature", "sig",
    )
    private val sensitiveHeaderNames = setOf(
        "authorization", "proxy-authorization", "cookie", "set-cookie", "www-authenticate",
        "x-api-key", "api-key", "x-amz-security-token", "x-amz-credential", "x-amz-signature",
        "x-goog-api-key", "x-goog-signature", "x-goog-credential", "x-ms-credential", "x-ms-signature",
    )
    private val sensitiveHeaderTokenPattern = Regex(
        "(^|[-_])(token|secret|password|passwd|auth|cookie|credential|credentials|api[-_]?key|access[-_]?key|signature)([-_]|$)",
    )

    fun write(observations: Iterable<HttpPayloadObservation>, output: OutputStream, limits: HarExportLimits = HarExportLimits()): HarExportResult {
        val prefix = "{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"APK Sentinel\",\"version\":\"1\"},\"entries\":["
        val suffix = "]}}"
        val budget = limits.maximumOutputBytes.toLong()
        var outputBytes = 0L
        fun writeWithinBudget(value: ByteArray, reserve: Int = suffix.length): Boolean {
            if (outputBytes + value.size + reserve > budget) return false
            output.write(value)
            outputBytes += value.size
            return true
        }
        // The prefix itself is bounded by the constructor's phone-sized output minimum.
        writeWithinBudget(prefix.encodeToByteArray(), reserve = suffix.length)
        val iterator = observations.iterator()
        var entries = 0
        var bytes = 0L
        var truncated = false
        var incomplete = false
        while (entries < limits.maximumEntries && iterator.hasNext()) {
            val observation = iterator.next()
            if (!observation.complete) incomplete = true
            val bodySize = observation.body?.size?.toLong() ?: -1L
            val accountedBodyBytes = if (bodySize < 0L) 0L else minOf(bodySize, limits.maximumBodyBytes.toLong())
            bytes += accountedBodyBytes
            if (bodySize > limits.maximumBodyBytes) truncated = true
            val started = java.time.Instant.ofEpochMilli(observation.startedAtMillis).toString()
            val requestHeaders = headers(observation.requestHeaders, limits.maximumHeaderCount)
            val responseHeaders = headers(observation.responseHeaders, limits.maximumHeaderCount)
            truncated = truncated || requestHeaders.truncated || responseHeaders.truncated
            val request = "{\"method\":${json(observation.method)},\"url\":${json(redactUrl(observation.url))},\"httpVersion\":\"HTTP/1.1\",\"headers\":${requestHeaders.json},\"queryString\":[],\"cookies\":[],\"headersSize\":-1,\"bodySize\":$bodySize}"
            val response = "{\"status\":${observation.status ?: 0},\"statusText\":\"\",\"httpVersion\":\"HTTP/1.1\",\"headers\":${responseHeaders.json},\"cookies\":[],\"content\":${content(bodySize, observation.bodyMimeType)},\"redirectURL\":\"\",\"headersSize\":-1,\"bodySize\":$bodySize}"
            val entry = ("{\"startedDateTime\":${json(started)},\"time\":${observation.durationMillis},\"request\":$request,\"response\":$response,\"cache\":{},\"timings\":{\"send\":0,\"wait\":${observation.durationMillis},\"receive\":0},\"_apkSentinelComplete\":${observation.complete}}" ).encodeToByteArray()
            val comma = if (entries == 0) ByteArray(0) else byteArrayOf(','.code.toByte())
            if (!writeWithinBudget(comma + entry)) {
                truncated = true
                break
            }
            entries++
        }
        if (entries >= limits.maximumEntries && iterator.hasNext()) truncated = true
        writeWithinBudget(suffix.encodeToByteArray(), reserve = 0)
        output.flush()
        return HarExportResult(entries, bytes, truncated || incomplete)
    }

    private data class HeaderResult(val json: String, val truncated: Boolean)

    private fun headers(values: Map<String, String>, max: Int): HeaderResult {
        val selected = values.entries.take(max)
        return HeaderResult(
            selected.joinToString(prefix = "[", postfix = "]") { (name, value) ->
                val safeValue = if (isSensitiveHeaderName(name)) "[REDACTED]" else value.take(4_096)
                "{\"name\":${json(name.take(256))},\"value\":${json(safeValue)}}"
            },
            truncated = values.size > selected.size || selected.any { it.value.length > 4_096 },
        )
    }
    private fun content(bodySize: Long, mime: String?): String = if (bodySize < 0L) {
        "{\"size\":-1,\"mimeType\":${json((mime ?: "").take(128))},\"_apkSentinelBodyOmitted\":true}"
    } else {
        // Payloads are intentionally never copied into HAR. This applies equally to text,
        // JSON/forms, and binary observations; only a bounded observed size is retained.
        "{\"size\":$bodySize,\"mimeType\":${json((mime ?: "").take(128))},\"_apkSentinelBodyOmitted\":true}"
    }
    private fun isSensitiveHeaderName(value: String): Boolean {
        val key = value.trim().lowercase()
        if (key in sensitiveHeaderNames) return true
        return sensitiveHeaderTokenPattern.containsMatchIn(key)
    }
    private fun redactUrl(value: String): String = runCatching {
        val withoutFragment = value.substringBefore('#')
        val queryStart = withoutFragment.indexOf('?')
        val base = (if (queryStart >= 0) withoutFragment.substring(0, queryStart) else withoutFragment)
            .replaceUserInfo()
        if (queryStart < 0) return@runCatching base.take(8_192)
        val rawQuery = withoutFragment.substring(queryStart + 1)
        if (rawQuery.isEmpty()) return@runCatching base.take(8_192)
        val query = rawQuery.split('&').joinToString("&") { part ->
            val key = part.substringBefore('=')
            if (isSensitiveQueryKey(key)) "$key=[REDACTED]" else part.take(512)
        }.take(4_096)
        "$base?$query".take(8_192)
    }.getOrDefault(redactOpaqueUrl(value).take(8_192))

    private fun String.replaceUserInfo(): String {
        val schemeSeparator = indexOf("://")
        if (schemeSeparator < 0) return this
        val authorityStart = schemeSeparator + 3
        val authorityEnd = indexOfAny(charArrayOf('/', '?'), authorityStart).let { if (it < 0) length else it }
        val authority = substring(authorityStart, authorityEnd)
        val at = authority.lastIndexOf('@')
        if (at < 0) return this
        return substring(0, authorityStart) + authority.substring(at + 1) + substring(authorityEnd)
    }
    private fun isSensitiveQueryKey(value: String): Boolean {
        val key = value.trim().lowercase()
        return key in sensitiveQueryKeys || key.contains("token") || key.contains("secret") ||
            key.contains("password") || key.contains("auth") || key.endsWith("key")
    }
    private fun redactOpaqueUrl(value: String): String = value
        .replace(Regex("(?i)://[^/?#@]+@"), "://[REDACTED]@")
        .replace(Regex("(?i)([?&](?:token|secret|password|auth|api[_-]?key|signature|credential|cookie)=)[^&#]*"), "$1[REDACTED]")
        .replace(Regex("\\?$"), "")
    private fun json(value: String): String = buildString(value.length + 2) { append('"'); value.forEach { char -> when (char) { '\\' -> append("\\\\"); '"' -> append("\\\""); '\n' -> append("\\n"); '\r' -> append("\\r"); '\t' -> append("\\t"); else -> if (char.code < 0x20) append("\\u%04x".format(char.code)) else append(char) } }; append('"') }
}
