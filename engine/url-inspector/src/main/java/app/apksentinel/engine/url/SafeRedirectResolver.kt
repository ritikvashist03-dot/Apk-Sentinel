package app.apksentinel.engine.url

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class RedirectHop(
    val url: String,
    val statusCode: Int,
    val displayHost: String,
)

enum class RedirectResolutionReason {
    INVALID_HTTP_URL,
    MISSING_HOSTNAME,
    HOSTNAME_UNRESOLVED,
    UNSAFE_NETWORK_TARGET,
    DESTINATION_CHECK_FAILED,
    REDIRECT_LOCATION_MISSING,
    REDIRECT_HOP_LIMIT_EXCEEDED,
    INVALID_REDIRECT_TARGET,
    REDIRECT_CHAIN_INCOMPLETE,
}

sealed interface RedirectResolution {
    data class Resolved(
        val finalUrl: String,
        val finalDisplayHost: String,
        val hops: List<RedirectHop>,
    ) : RedirectResolution

    data class Rejected(val reason: RedirectResolutionReason) : RedirectResolution
    data class Failed(val reason: RedirectResolutionReason, val hops: List<RedirectHop>) : RedirectResolution
}

/** The small, testable transport boundary used by [SafeRedirectResolver]. */
interface PinnedHttpConnector {
    /**
     * Sends a HEAD request to exactly [address]. Implementations must not resolve [hostname].
     * For HTTPS, [hostname] is still used for TLS SNI and certificate verification.
     */
    fun head(
        uri: URI,
        hostname: String,
        address: InetAddress,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): PinnedHeadResponse
}

data class PinnedHeadResponse(
    val statusCode: Int,
    val headers: Map<String, String>,
)

/**
 * Explicit, blocking online redirect resolution. Callers must run it off the
 * main thread and show that the full URL is sent to each destination host.
 *
 * DNS is resolved once per redirect hop and the TCP socket is connected to that
 * already-checked address. This avoids a second hostname lookup by a URL stack
 * between validation and connect (the DNS-rebinding window).
 */
class SafeRedirectResolver(
    private val maxRedirects: Int = 5,
    private val connectTimeoutMillis: Int = 5_000,
    private val readTimeoutMillis: Int = 5_000,
    private val addressResolver: (String) -> Array<InetAddress> = { host -> InetAddress.getAllByName(host) },
    private val pinnedConnector: PinnedHttpConnector = SocketPinnedHttpConnector,
) {
    init {
        require(maxRedirects in 0..10)
        require(connectTimeoutMillis in 500..30_000)
        require(readTimeoutMillis in 500..30_000)
    }

    fun resolve(normalizedHttpUrl: String): RedirectResolution {
        var current = canonicalUri(normalizedHttpUrl)
            ?: return RedirectResolution.Rejected(RedirectResolutionReason.INVALID_HTTP_URL)
        val hops = mutableListOf<RedirectHop>()
        repeat(maxRedirects + 1) { index ->
            val host = current.host ?: return RedirectResolution.Rejected(RedirectResolutionReason.MISSING_HOSTNAME)
            val addresses = runCatching { addressResolver(host) }.getOrElse {
                return RedirectResolution.Failed(RedirectResolutionReason.HOSTNAME_UNRESOLVED, hops)
            }
            if (addresses.isEmpty() || addresses.any { !PublicNetworkTargetPolicy.isPublic(it) }) {
                return RedirectResolution.Rejected(RedirectResolutionReason.UNSAFE_NETWORK_TARGET)
            }

            // Pick a result that has already passed policy. The connector is deliberately
            // given the address, not a URL, so it cannot trigger another DNS resolution.
            val response = runCatching {
                pinnedConnector.head(
                    uri = current,
                    hostname = host,
                    address = addresses.first(),
                    connectTimeoutMillis = connectTimeoutMillis,
                    readTimeoutMillis = readTimeoutMillis,
                )
            }.getOrElse {
                return RedirectResolution.Failed(RedirectResolutionReason.DESTINATION_CHECK_FAILED, hops)
            }
            val displayHost = runCatching { IDN.toUnicode(host).lowercase(Locale.ROOT) }.getOrDefault(host)
            hops += RedirectHop(current.toASCIIString(), response.statusCode, displayHost)
            if (response.statusCode !in REDIRECT_CODES) {
                return RedirectResolution.Resolved(current.toASCIIString(), displayHost, hops)
            }
            val location = response.headers["location"]
            if (location.isNullOrBlank()) return RedirectResolution.Failed(RedirectResolutionReason.REDIRECT_LOCATION_MISSING, hops)
            if (index == maxRedirects) return RedirectResolution.Failed(RedirectResolutionReason.REDIRECT_HOP_LIMIT_EXCEEDED, hops)
            current = canonicalUri(runCatching { current.resolve(location).toASCIIString() }.getOrNull().orEmpty())
                ?: return RedirectResolution.Rejected(RedirectResolutionReason.INVALID_REDIRECT_TARGET)
        }
        return RedirectResolution.Failed(RedirectResolutionReason.REDIRECT_CHAIN_INCOMPLETE, hops)
    }

    private fun canonicalUri(raw: String): URI? = runCatching {
        val uri = URI(raw)
        require(uri.scheme?.lowercase(Locale.ROOT) in setOf("http", "https"))
        require(uri.userInfo == null)
        val host = IDN.toASCII(requireNotNull(uri.host).lowercase(Locale.ROOT), IDN.USE_STD3_ASCII_RULES)
        URI(uri.scheme.lowercase(Locale.ROOT), null, host, uri.port, uri.rawPath.ifBlank { "/" }, uri.rawQuery, null)
    }.getOrNull()

    private companion object {
        val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
    }
}

/** Standard-library socket transport. No URLConnection is used after DNS validation. */
internal object SocketPinnedHttpConnector : PinnedHttpConnector {
    private const val MAX_HEADER_BYTES = 16 * 1024

    override fun head(
        uri: URI,
        hostname: String,
        address: InetAddress,
        connectTimeoutMillis: Int,
        readTimeoutMillis: Int,
    ): PinnedHeadResponse {
        val port = when {
            uri.port != -1 -> uri.port
            uri.scheme.equals("https", ignoreCase = true) -> 443
            else -> 80
        }
        require(port in 1..65_535)
        val socket = Socket().apply {
            connect(InetSocketAddress(address, port), connectTimeoutMillis)
            soTimeout = readTimeoutMillis
        }
        return try {
            val connectedSocket = if (uri.scheme.equals("https", ignoreCase = true)) {
                secureSocket(socket, hostname, address, port, readTimeoutMillis)
            } else {
                socket
            }
            connectedSocket.use { transport ->
                writeHeadRequest(transport, hostname, port, uri)
                readHeadResponse(transport.getInputStream())
            }
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun secureSocket(
        socket: Socket,
        hostname: String,
        address: InetAddress,
        port: Int,
        readTimeoutMillis: Int,
    ): SSLSocket {
        // The socket is already connected to the policy-checked address. Passing that
        // numeric peer value here makes the layered TLS factory independent of hostname DNS.
        val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
            .createSocket(socket, address.hostAddress, port, true) as SSLSocket
        tls.soTimeout = readTimeoutMillis
        if (!isIpLiteral(hostname)) {
            val parameters = tls.sslParameters
            parameters.serverNames = listOf(SNIHostName(hostname))
            tls.sslParameters = parameters
        }
        tls.startHandshake()
        check(HttpsURLConnection.getDefaultHostnameVerifier().verify(hostname, tls.session)) {
            "The TLS certificate does not match the requested hostname."
        }
        return tls
    }

    private fun writeHeadRequest(socket: Socket, hostname: String, port: Int, uri: URI) {
        val requestTarget = buildString {
            append(uri.rawPath.ifBlank { "/" })
            uri.rawQuery?.let { append('?').append(it) }
        }
        val request = buildString {
            append("HEAD ").append(requestTarget).append(" HTTP/1.1\r\n")
            append("Host: ").append(hostHeader(hostname, port, uri.scheme)).append("\r\n")
            append("User-Agent: APK-Sentinel-Redirect-Check/1.0\r\n")
            append("Accept: */*\r\n")
            append("Connection: close\r\n\r\n")
        }
        // Do not close the stream here: on Socket, closing the output stream closes the
        // socket before the bounded response headers can be read.
        socket.getOutputStream().apply {
            write(request.toByteArray(StandardCharsets.ISO_8859_1))
            flush()
        }
    }

    private fun readHeadResponse(input: InputStream): PinnedHeadResponse {
        val rawHeaders = ByteArrayOutputStream()
        var terminatorProgress = 0
        while (rawHeaders.size() < MAX_HEADER_BYTES) {
            val next = input.read()
            if (next == -1) throw IllegalStateException("The response ended before HTTP headers were complete.")
            rawHeaders.write(next)
            terminatorProgress = when {
                terminatorProgress == 0 && next == '\r'.code -> 1
                terminatorProgress == 1 && next == '\n'.code -> 2
                terminatorProgress == 2 && next == '\r'.code -> 3
                terminatorProgress == 3 && next == '\n'.code -> 4
                next == '\r'.code -> 1
                else -> 0
            }
            if (terminatorProgress == 4) break
        }
        check(terminatorProgress == 4) { "HTTP response headers exceeded the allowed size." }
        val lines = rawHeaders.toString(StandardCharsets.ISO_8859_1.name()).split("\r\n")
        val statusCode = lines.firstOrNull()
            ?.split(' ', limit = 3)
            ?.getOrNull(1)
            ?.toIntOrNull()
            ?.takeIf { it in 100..599 }
            ?: throw IllegalStateException("The destination did not return a valid HTTP status line.")
        val headers = linkedMapOf<String, String>()
        lines.drop(1).takeWhile { it.isNotEmpty() }.forEach { line ->
            val divider = line.indexOf(':')
            if (divider <= 0) throw IllegalStateException("The destination returned an invalid HTTP header.")
            val name = line.substring(0, divider).trim().lowercase(Locale.ROOT)
            val value = line.substring(divider + 1).trim()
            headers.putIfAbsent(name, value)
        }
        return PinnedHeadResponse(statusCode = statusCode, headers = headers)
    }

    private fun hostHeader(hostname: String, port: Int, scheme: String): String {
        val bareHost = hostname.removePrefix("[").removeSuffix("]")
        val renderedHost = if (bareHost.contains(':')) "[$bareHost]" else bareHost
        val defaultPort = if (scheme.equals("https", ignoreCase = true)) 443 else 80
        return if (port == defaultPort) renderedHost else "$renderedHost:$port"
    }

    private fun isIpLiteral(host: String): Boolean =
        host.matches(Regex("\\d{1,3}(?:\\.\\d{1,3}){3}")) || host.contains(':')
}

internal object PublicNetworkTargetPolicy {
    fun isPublic(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress || address.isMulticastAddress) return false
        val bytes = address.address.map { it.toInt() and 0xff }
        if (address is Inet4Address) return isPublicIpv4(bytes)
        if (address is Inet6Address) {
            val mappedIpv4 = bytes.take(10).all { it == 0 } && bytes[10] == 0xff && bytes[11] == 0xff
            if (mappedIpv4) return isPublicIpv4(bytes.takeLast(4))
            val documentation = bytes.take(4) == listOf(0x20, 0x01, 0x0d, 0xb8)
            val discardOnly = bytes.take(8) == listOf(0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            return !documentation && !discardOnly && bytes.firstOrNull()?.and(0xfe) != 0xfc
        }
        return false
    }

    private fun isPublicIpv4(bytes: List<Int>): Boolean {
        val a = bytes[0]
        val b = bytes[1]
        return when {
            a == 0 || a == 10 || a == 127 || a >= 224 -> false
            a == 100 && b in 64..127 -> false
            a == 169 && b == 254 -> false
            a == 172 && b in 16..31 -> false
            // 192.0.0.0/24 (IETF protocol assignments), NOT 192.0.0.0/16. Without the
            // third-octet check this rejected 192.0.1.0-192.0.255.255, which are ordinary
            // public addresses, and it also made the 192.0.2.0/24 branch below unreachable.
            a == 192 && b == 0 && bytes[2] == 0 -> false
            a == 192 && b == 168 -> false
            a == 198 && b in 18..19 -> false
            a == 192 && b == 0 && bytes[2] == 2 -> false
            a == 198 && b == 51 && bytes[2] == 100 -> false
            a == 203 && b == 0 && bytes[2] == 113 -> false
            else -> true
        }
    }
}
