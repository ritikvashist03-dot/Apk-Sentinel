package app.apksentinel.mobile

import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.util.Base64
import javax.net.ssl.HttpsURLConnection

/**
 * Small, opt-in transport for publisher-signed local data. It has no scheduler,
 * credentials, cookies, inventory, or capture access. The caller must invoke it
 * from an explicit user action and must verify the returned bytes before use.
 */
internal object SignedBundleUpdateClient {
    const val SIGNATURE_HEADER = "X-APK-Sentinel-Signature"
    const val MAX_SIGNATURE_HEADER_CHARS = 4_096
    const val MAX_CONNECT_TIMEOUT_MILLIS = 15_000
    const val MAX_READ_TIMEOUT_MILLIS = 15_000

    fun fetch(
        endpoint: String,
        maximumBodyBytes: Int,
        connectTimeoutMillis: Int = 8_000,
        readTimeoutMillis: Int = 8_000,
    ): SignedBundleUpdateResult {
        if (maximumBodyBytes !in 1..MAX_SUPPORTED_BODY_BYTES) {
            return SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.RESPONSE_LIMIT)
        }
        val uri = validateEndpoint(endpoint)
            ?: return SignedBundleUpdateResult.Failure(
                if (endpoint.isBlank()) SignedBundleUpdateFailure.ENDPOINT_UNCONFIGURED
                else SignedBundleUpdateFailure.INVALID_ENDPOINT,
            )
        if (connectTimeoutMillis !in 1..MAX_CONNECT_TIMEOUT_MILLIS ||
            readTimeoutMillis !in 1..MAX_READ_TIMEOUT_MILLIS
        ) {
            return SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.RESPONSE_LIMIT)
        }

        val connection = try {
            uri.toURL().openConnection() as? HttpsURLConnection
        } catch (_: Exception) {
            null
        } ?: return SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.NETWORK)

        return try {
            configure(connection, connectTimeoutMillis, readTimeoutMillis)
            val status = connection.responseCode
            if (status in 300..399) {
                SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.REDIRECT)
            } else if (status != HttpURLConnection.HTTP_OK) {
                SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.HTTP_STATUS)
            } else {
                val signature = parseDetachedSignature(connection.headerFields)
                    ?: return SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.SIGNATURE_HEADER)
                val declaredLength = connection.contentLengthLong
                if (declaredLength > maximumBodyBytes.toLong()) {
                    return SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.RESPONSE_LIMIT)
                }
                val body = try {
                    connection.inputStream.use { it.readBounded(maximumBodyBytes) }
                } catch (_: Exception) {
                    null
                } ?: return SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.RESPONSE_LIMIT)
                SignedBundleUpdateResult.Success(body, signature)
            }
        } catch (_: Exception) {
            SignedBundleUpdateResult.Failure(SignedBundleUpdateFailure.NETWORK)
        } finally {
            connection.disconnect()
        }
    }

    /** Endpoint policy is deliberately stricter than generic URL parsing. */
    fun validateEndpoint(raw: String): URI? = runCatching {
        if (raw.isBlank() || raw.length > MAX_ENDPOINT_CHARS || raw.any(Char::isWhitespace)) return@runCatching null
        val uri = URI(raw)
        if (!uri.scheme.equals("https", ignoreCase = true) || uri.host.isNullOrBlank()) return@runCatching null
        if (uri.userInfo != null || uri.fragment != null || uri.query != null) return@runCatching null
        if (uri.port != -1 && uri.port != 443) return@runCatching null
        if (uri.rawAuthority != uri.host && uri.rawAuthority != "${uri.host}:443") return@runCatching null
        uri
    }.getOrNull()

    /** Exposed for deterministic JVM tests; duplicate headers are never accepted. */
    fun parseDetachedSignature(headers: Map<String?, List<String>?>): String? {
        val values = headers.entries
            .filter { it.key?.equals(SIGNATURE_HEADER, ignoreCase = true) == true }
            .flatMap { it.value.orEmpty() }
        if (values.size != 1) return null
        val value = values.single()
        if (value.length !in 1..MAX_SIGNATURE_HEADER_CHARS || value.any { it.code > 0x7f || it.isWhitespace() }) return null
        return runCatching {
            val decoded = Base64.getDecoder().decode(value)
            decoded.takeIf { it.isNotEmpty() && it.size <= MAX_SIGNATURE_HEADER_CHARS &&
                Base64.getEncoder().encodeToString(it) == value
            }?.let { decoded.fill(0); value }
        }.getOrNull()
    }

    /** Reads at most the configured cap plus one byte, never allocating beyond it. */
    fun InputStream.readBounded(maximumBytes: Int): ByteArray? {
        if (maximumBytes !in 1..MAX_SUPPORTED_BODY_BYTES) return null
        val buffer = ByteArray(maximumBytes + 1)
        var size = 0
        var zeroProgressReads = 0
        return try {
            while (true) {
                val remaining = maximumBytes - size
                val count = read(buffer, size, minOf(buffer.size - size, remaining + 1))
                if (count < 0) break
                if (count == 0) {
                    zeroProgressReads += 1
                    if (zeroProgressReads > MAX_ZERO_PROGRESS_READS) return null
                    continue
                }
                zeroProgressReads = 0
                if (count > remaining) return null
                size += count
            }
            buffer.copyOf(size)
        } finally {
            buffer.fill(0)
        }
    }

    private fun configure(connection: HttpsURLConnection, connectTimeoutMillis: Int, readTimeoutMillis: Int) {
        connection.requestMethod = "GET"
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        connection.instanceFollowRedirects = false
        connection.useCaches = false
        connection.doInput = true
        connection.setRequestProperty("Accept", "application/octet-stream")
        connection.setRequestProperty("Cache-Control", "no-cache")
        connection.setRequestProperty("Cookie", "")
        connection.setRequestProperty("Connection", "close")
    }

    private const val MAX_ENDPOINT_CHARS = 2_048
    private const val MAX_SUPPORTED_BODY_BYTES = 2_000_000
    private const val MAX_ZERO_PROGRESS_READS = 4
}

internal sealed interface SignedBundleUpdateResult {
    data class Success(val body: ByteArray, val signatureBase64: String) : SignedBundleUpdateResult
    data class Failure(val reason: SignedBundleUpdateFailure) : SignedBundleUpdateResult
}

internal enum class SignedBundleUpdateFailure {
    ENDPOINT_UNCONFIGURED,
    INVALID_ENDPOINT,
    REDIRECT,
    HTTP_STATUS,
    SIGNATURE_HEADER,
    RESPONSE_LIMIT,
    NETWORK,
}
