package app.apksentinel.networkmonitor

import app.apksentinel.core.security.HostValidation
import java.util.ArrayDeque
import java.util.LinkedHashMap
import java.util.Locale

/** A fresh, user-visible acknowledgement required for each protocol-evidence session. */
data class ProtocolEvidenceConsent(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
) {
    init {
        require(disclosureVersion.isNotBlank()) { "A protocol-evidence disclosure version is required." }
        require(acknowledgedAtMillis > 0L) { "A protocol-evidence acknowledgement time must be positive." }
    }
}

/**
 * Opt-in, in-memory settings for the narrow protocol-evidence parser.
 *
 * This is deliberately off by default. Enabling it authorizes parsing only of
 * TCP payload bytes that the local forwarder already holds briefly while it is
 * forwarding them. It does not authorize TLS decryption, TCP reassembly,
 * payload retention, remote upload, or a payload UI.
 */
data class ProtocolEvidenceConfiguration(
    val enabled: Boolean = false,
    val consent: ProtocolEvidenceConsent? = null,
    val inspectTlsClientHelloSni: Boolean = false,
    val inspectCleartextHttp: Boolean = false,
    /**
     * Retains the HTTP request target and Host, which together form a URL.
     *
     * Off by default and separately consented, because a request target is a different
     * class of data from a method: even without a query string it can carry a token,
     * an account identifier, or a document name. Enabling it is what makes URL evidence
     * and HAR export possible at all; leaving it off preserves the previous behaviour
     * exactly.
     */
    val captureRequestTargets: Boolean = false,
    val maximumTrackedFlows: Int = 64,
    val maximumObservations: Int = 128,
    val maximumObservationsPerFlowDirection: Int = 2,
) {
    init {
        require(!enabled || consent != null) { "Enabled protocol evidence requires separate session consent." }
        require(!captureRequestTargets || consent != null) {
            "Capturing request targets requires separate session consent."
        }
        require(!captureRequestTargets || inspectCleartextHttp) {
            "Request targets can only come from cleartext HTTP inspection."
        }
        require(maximumTrackedFlows in 1..256) { "Protocol evidence tracks between 1 and 256 flows." }
        require(maximumObservations in 1..512) { "Protocol evidence retains between 1 and 512 observations." }
        require(maximumObservationsPerFlowDirection in 1..4) {
            "Protocol evidence retains between 1 and 4 observations per flow direction."
        }
    }

    val isActive: Boolean
        get() = enabled && consent != null && (inspectTlsClientHelloSni || inspectCleartextHttp)
}

enum class ProtocolEvidenceSource {
    TLS_CLIENT_HELLO_SNI,
    CLEARTEXT_HTTP_REQUEST,
    CLEARTEXT_HTTP_RESPONSE,
}

/** A complete, bounded parse is high confidence; all other outcomes remain explicit. */
enum class ProtocolEvidenceConfidence {
    HIGH,
    LIMITED,
}

enum class ProtocolEvidenceLimitation {
    /** The session did not opt in, so no protocol payload was inspected. */
    DISABLED_BY_SESSION,
    /** The initial bytes did not contain one complete message; no reassembly is attempted. */
    FRAGMENTED_OR_INCOMPLETE,
    /** A declared or captured message exceeded this parser's small bound. */
    OVERSIZED,
    /** Lengths, fields, or framing were invalid. */
    MALFORMED,
    /** A TLS server name was not a safe ASCII DNS name, so it was omitted. */
    UNSAFE_OR_UNSUPPORTED_NAME,
    /** HTTP request bodies and response bodies are never represented. */
    BODY_NOT_CAPTURED,
    /** Credential-bearing HTTP headers were recognized but neither names nor values are retained. */
    SENSITIVE_HEADERS_OMITTED,
    /** The bytes are encrypted, opaque, or not one of the narrow formats recognized here. */
    OPAQUE_OR_UNSUPPORTED,
}

sealed interface ProtocolEvidenceValue {
    data class TlsServerName(val hostname: String) : ProtocolEvidenceValue {
        init {
            require(HostValidation.isValidDomain(hostname)) { "TLS server name must be a safe ASCII DNS name." }
        }
    }

    data class HttpRequest(
        val method: String,
        val version: String,
        /** Request target, retained only under [ProtocolEvidenceConfiguration.captureRequestTargets]. */
        val target: String? = null,
        /** Host header value, retained under the same consent. Port is kept when present. */
        val host: String? = null,
    ) : ProtocolEvidenceValue {
        init {
            require(target == null || target.length in 1..MAX_TARGET_LENGTH) { "Request target is out of range." }
            require(host == null || host.length in 1..MAX_HOST_LENGTH) { "Host is out of range." }
        }

        /**
         * An absolute URL when both halves were captured. The scheme is http because this
         * evidence only ever comes from a CLEARTEXT observation — a decrypted TLS stream
         * would need to say so itself rather than borrow this.
         */
        val absoluteUrl: String?
            get() = if (host != null && target != null && target.startsWith("/")) "http://$host$target" else null

        private companion object {
            const val MAX_TARGET_LENGTH = 2_048
            const val MAX_HOST_LENGTH = 255
        }
    }

    data class HttpResponse(
        val statusCode: Int,
        val version: String,
    ) : ProtocolEvidenceValue {
        init {
            require(statusCode in 100..599) { "HTTP status code is out of range." }
        }
    }
}

/**
 * Bounded result. [value] is null for a conservative failure or limitation.
 *
 * No instance ever contains raw payload bytes, message bodies, cookies, credentials, or
 * any credential-bearing header — those remain excluded unconditionally.
 *
 * One exception exists and is opt-in: with
 * [ProtocolEvidenceConfiguration.captureRequestTargets] enabled, an
 * [ProtocolEvidenceValue.HttpRequest] also carries the request target and Host header,
 * because a URL cannot be reconstructed without them. That flag requires its own consent
 * and is off by default, so the default result is still metadata only.
 */
data class ProtocolEvidenceObservation(
    val source: ProtocolEvidenceSource,
    val direction: PacketDirection,
    val observedAtMillis: Long,
    val confidence: ProtocolEvidenceConfidence,
    val value: ProtocolEvidenceValue?,
    val limitations: Set<ProtocolEvidenceLimitation>,
) {
    init {
        require(observedAtMillis >= 0L) { "Observation time must not be negative." }
        require(
            (confidence == ProtocolEvidenceConfidence.HIGH && value != null) ||
                (confidence == ProtocolEvidenceConfidence.LIMITED && value == null && limitations.isNotEmpty()),
        ) { "Protocol evidence must be either a complete value or an explicit limited outcome." }
    }
}

data class ProtocolEvidenceSnapshot(
    val enabledForSession: Boolean = false,
    val observations: List<ProtocolEvidenceObservation> = emptyList(),
    val droppedObservations: Long = 0L,
    /** Stable session-level capability state; default snapshots are explicitly disabled. */
    val sessionLimitations: Set<ProtocolEvidenceLimitation> = setOf(ProtocolEvidenceLimitation.DISABLED_BY_SESSION),
) {
    init {
        require(droppedObservations >= 0L) { "Dropped observation count must not be negative." }
        require(enabledForSession || ProtocolEvidenceLimitation.DISABLED_BY_SESSION in sessionLimitations) {
            "A disabled protocol-evidence snapshot must declare its disabled state."
        }
    }
}

/** Internal flow key only; it is never exposed in a [ProtocolEvidenceObservation]. */
internal data class ProtocolEvidenceFlowKey(
    val sourceAddress: String,
    val sourcePort: Int,
    val destinationAddress: String,
    val destinationPort: Int,
)

/**
 * Bounded, synchronized, metadata-only collector. It never buffers TCP bytes:
 * each parser invocation sees just the single already-present forwarding
 * payload. A split TLS/HTTP message therefore yields an explicit limited
 * observation instead of a guessed hostname or reconstructed request.
 */
internal class BoundedProtocolEvidenceCollector(
    private val configuration: ProtocolEvidenceConfiguration,
) {
    private val lock = Any()
    private val perFlowDirections = object : LinkedHashMap<ProtocolEvidenceFlowKey, MutableMap<PacketDirection, Int>>(
        configuration.maximumTrackedFlows,
        0.75f,
        false,
    ) {
        override fun removeEldestEntry(
            eldest: MutableMap.MutableEntry<ProtocolEvidenceFlowKey, MutableMap<PacketDirection, Int>>?,
        ): Boolean = size > configuration.maximumTrackedFlows
    }
    private val observations = ArrayDeque<ProtocolEvidenceObservation>()
    private var dropped = 0L

    fun observeTcpPayload(
        flow: ProtocolEvidenceFlowKey,
        direction: PacketDirection,
        payload: ByteArray,
        observedAtMillis: Long,
    ) {
        if (!configuration.isActive || payload.isEmpty() || observedAtMillis < 0L) return
        val candidates = ArrayList<ProtocolEvidenceObservation>(2)
        if (configuration.inspectTlsClientHelloSni && looksLikeTlsHandshake(payload)) {
            candidates += TlsClientHelloEvidenceParser.parse(payload, direction, observedAtMillis)
        }
        if (configuration.inspectCleartextHttp) {
            CleartextHttpEvidenceParser.parse(
                payload = payload,
                direction = direction,
                observedAtMillis = observedAtMillis,
                captureRequestTargets = configuration.captureRequestTargets,
            )?.let { candidates += it }
        }
        if (candidates.isEmpty()) return
        synchronized(lock) {
            val byDirection = perFlowDirections.getOrPut(flow) { mutableMapOf() }
            candidates.forEach { candidate ->
                val current = byDirection[candidate.direction] ?: 0
                if (current >= configuration.maximumObservationsPerFlowDirection) {
                    dropped = saturatingIncrement(dropped)
                    return@forEach
                }
                byDirection[candidate.direction] = current + 1
                if (observations.size == configuration.maximumObservations) {
                    observations.removeFirst()
                    dropped = saturatingIncrement(dropped)
                }
                observations.addLast(candidate)
            }
        }
    }

    fun snapshot(): ProtocolEvidenceSnapshot = synchronized(lock) {
        ProtocolEvidenceSnapshot(
            enabledForSession = configuration.isActive,
            observations = observations.toList(),
            droppedObservations = dropped,
            sessionLimitations = if (configuration.isActive) emptySet() else {
                setOf(ProtocolEvidenceLimitation.DISABLED_BY_SESSION)
            },
        )
    }

    fun clear() = synchronized(lock) {
        perFlowDirections.clear()
        observations.clear()
        dropped = 0L
    }
}

private object TlsClientHelloEvidenceParser {
    private const val TLS_RECORD_HEADER_BYTES = 5
    private const val TLS_HANDSHAKE_HEADER_BYTES = 4
    private const val TLS_CONTENT_TYPE_HANDSHAKE = 22
    private const val TLS_HANDSHAKE_CLIENT_HELLO = 1
    private const val TLS_EXTENSION_SERVER_NAME = 0
    private const val MAX_TLS_RECORD_BYTES = 16 * 1024
    private const val MAX_TLS_EXTENSIONS = 64

    fun parse(
        payload: ByteArray,
        direction: PacketDirection,
        observedAtMillis: Long,
    ): ProtocolEvidenceObservation {
        fun limited(vararg limitations: ProtocolEvidenceLimitation) = ProtocolEvidenceObservation(
            source = ProtocolEvidenceSource.TLS_CLIENT_HELLO_SNI,
            direction = direction,
            observedAtMillis = observedAtMillis,
            confidence = ProtocolEvidenceConfidence.LIMITED,
            value = null,
            limitations = limitations.toSet(),
        )
        if (payload.size < TLS_RECORD_HEADER_BYTES) return limited(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE)
        if (u8(payload, 0) != TLS_CONTENT_TYPE_HANDSHAKE) return limited(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED)
        if (!isTlsLegacyVersion(u8(payload, 1), u8(payload, 2))) {
            return limited(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED)
        }
        val recordBytes = u16(payload, 3)
        if (recordBytes > MAX_TLS_RECORD_BYTES) return limited(ProtocolEvidenceLimitation.OVERSIZED)
        val recordEnd = TLS_RECORD_HEADER_BYTES.toLong() + recordBytes.toLong()
        if (recordEnd > payload.size.toLong()) return limited(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE)
        if (recordBytes < TLS_HANDSHAKE_HEADER_BYTES) return limited(ProtocolEvidenceLimitation.MALFORMED)
        val recordLimit = recordEnd.toInt()
        if (u8(payload, TLS_RECORD_HEADER_BYTES) != TLS_HANDSHAKE_CLIENT_HELLO) {
            return limited(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED)
        }
        val helloBytes = u24(payload, TLS_RECORD_HEADER_BYTES + 1)
        val helloStart = TLS_RECORD_HEADER_BYTES + TLS_HANDSHAKE_HEADER_BYTES
        if (helloBytes > MAX_TLS_RECORD_BYTES) return limited(ProtocolEvidenceLimitation.OVERSIZED)
        if (helloBytes.toLong() > (recordLimit - helloStart).toLong()) {
            return limited(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE)
        }
        val helloLimit = helloStart + helloBytes
        val reader = SafeByteReader(payload, helloStart, helloLimit)
        val helloMajor = reader.u8() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        val helloMinor = reader.u8() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        if (!isTlsLegacyVersion(helloMajor, helloMinor)) return limited(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED)
        if (!reader.skip(32)) return limited(ProtocolEvidenceLimitation.MALFORMED)
        val sessionIdBytes = reader.u8() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        if (sessionIdBytes > 32 || !reader.skip(sessionIdBytes)) return limited(ProtocolEvidenceLimitation.MALFORMED)
        val cipherBytes = reader.u16() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        if (cipherBytes == 0 || cipherBytes % 2 != 0 || !reader.skip(cipherBytes)) return limited(ProtocolEvidenceLimitation.MALFORMED)
        val compressionBytes = reader.u8() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        if (compressionBytes == 0 || !reader.skip(compressionBytes)) return limited(ProtocolEvidenceLimitation.MALFORMED)
        if (reader.remaining == 0) return limited(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED)
        val extensionsBytes = reader.u16() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        if (extensionsBytes != reader.remaining) return limited(ProtocolEvidenceLimitation.MALFORMED)

        var extensionCount = 0
        while (reader.remaining > 0) {
            if (++extensionCount > MAX_TLS_EXTENSIONS) return limited(ProtocolEvidenceLimitation.OVERSIZED)
            val type = reader.u16() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
            val extensionBytes = reader.u16() ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
            val extension = reader.subReader(extensionBytes) ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
            if (type != TLS_EXTENSION_SERVER_NAME) continue
            val hostname = parseServerName(extension)
                ?: return limited(ProtocolEvidenceLimitation.UNSAFE_OR_UNSUPPORTED_NAME)
            return ProtocolEvidenceObservation(
                source = ProtocolEvidenceSource.TLS_CLIENT_HELLO_SNI,
                direction = direction,
                observedAtMillis = observedAtMillis,
                confidence = ProtocolEvidenceConfidence.HIGH,
                value = ProtocolEvidenceValue.TlsServerName(hostname),
                limitations = emptySet(),
            )
        }
        return limited(ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED)
    }

    private fun parseServerName(reader: SafeByteReader): String? {
        val listBytes = reader.u16() ?: return null
        if (listBytes != reader.remaining || listBytes == 0) return null
        while (reader.remaining > 0) {
            val nameType = reader.u8() ?: return null
            val nameBytes = reader.u16() ?: return null
            val raw = reader.bytes(nameBytes) ?: return null
            if (nameType == 0) {
                val value = raw.decodeToStringOrNull() ?: return null
                return value.lowercase(Locale.ROOT).takeIf { HostValidation.isValidDomain(it) }
            }
        }
        return null
    }
}

private object CleartextHttpEvidenceParser {
    private const val MAX_HEADER_BYTES = 8 * 1024
    private const val MAX_START_LINE_BYTES = 1_024
    private val requestMethod = Regex("[A-Z]{1,16}")
    private val version = Regex("HTTP/1\\.[01]")
    private val sensitiveHeaderNames = setOf(
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
    )

    fun parse(
        payload: ByteArray,
        direction: PacketDirection,
        observedAtMillis: Long,
        captureRequestTargets: Boolean = false,
    ): ProtocolEvidenceObservation? {
        val source = when {
            payload.startsWithAscii("HTTP/") -> ProtocolEvidenceSource.CLEARTEXT_HTTP_RESPONSE
            looksLikeHttpRequest(payload) -> ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST
            else -> return null
        }
        fun limited(vararg limitations: ProtocolEvidenceLimitation) = ProtocolEvidenceObservation(
            source = source,
            direction = direction,
            observedAtMillis = observedAtMillis,
            confidence = ProtocolEvidenceConfidence.LIMITED,
            value = null,
            limitations = limitations.toSet(),
        )
        if (payload.size >= MAX_HEADER_BYTES && findHeaderEnd(payload, MAX_HEADER_BYTES) < 0) {
            return limited(ProtocolEvidenceLimitation.OVERSIZED)
        }
        val headerEnd = findHeaderEnd(payload, minOf(payload.size, MAX_HEADER_BYTES))
        if (headerEnd < 0) return limited(ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE)
        if (!isSafeHttpHeader(payload, headerEnd + 4)) return limited(ProtocolEvidenceLimitation.MALFORMED)
        val firstLineEnd = findCrlf(payload, 0, headerEnd)
        if (firstLineEnd <= 0 || firstLineEnd > MAX_START_LINE_BYTES) return limited(ProtocolEvidenceLimitation.MALFORMED)
        val firstLine = ascii(payload, 0, firstLineEnd) ?: return limited(ProtocolEvidenceLimitation.MALFORMED)
        val limitations = linkedSetOf(ProtocolEvidenceLimitation.BODY_NOT_CAPTURED)
        if (containsSensitiveHeader(payload, firstLineEnd + 2, headerEnd + 2)) {
            limitations += ProtocolEvidenceLimitation.SENSITIVE_HEADERS_OMITTED
        }
        return when (source) {
            ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST -> parseRequest(
                firstLine = firstLine,
                direction = direction,
                observedAtMillis = observedAtMillis,
                limitations = limitations,
                payload = payload,
                headersStart = firstLineEnd + 2,
                headersEnd = headerEnd + 2,
                captureRequestTargets = captureRequestTargets,
            )
            ProtocolEvidenceSource.CLEARTEXT_HTTP_RESPONSE -> parseResponse(firstLine, direction, observedAtMillis, limitations)
            else -> null
        }
    }

    private fun parseRequest(
        firstLine: String,
        direction: PacketDirection,
        observedAtMillis: Long,
        limitations: Set<ProtocolEvidenceLimitation>,
        payload: ByteArray,
        headersStart: Int,
        headersEnd: Int,
        captureRequestTargets: Boolean,
    ): ProtocolEvidenceObservation {
        val fields = firstLine.split(' ')
        if (fields.size != 3 || !requestMethod.matches(fields[0]) || !version.matches(fields[2])) {
            return limitedRequest(direction, observedAtMillis, ProtocolEvidenceLimitation.MALFORMED)
        }
        // The target and Host are retained ONLY under the separate request-target consent.
        // With it off, this behaves exactly as before: a method and a version, nothing that
        // could carry a token, an account id, or a document name.
        val target = if (captureRequestTargets) safeRequestTarget(fields[1]) else null
        val host = if (captureRequestTargets) readHostHeader(payload, headersStart, headersEnd) else null
        return ProtocolEvidenceObservation(
            source = ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST,
            direction = direction,
            observedAtMillis = observedAtMillis,
            confidence = ProtocolEvidenceConfidence.HIGH,
            value = ProtocolEvidenceValue.HttpRequest(fields[0], fields[2], target, host),
            limitations = limitations,
        )
    }

    /**
     * Accepts only an origin-form path or an asterisk-form target. Absolute-form and
     * authority-form are refused rather than normalised: they can carry credentials in the
     * authority, and rejecting an unusual target costs one observation while accepting a
     * malformed one puts attacker-controlled text into a URL the UI will render.
     */
    private fun safeRequestTarget(value: String): String? {
        if (value.length !in 1..2_048) return null
        if (value.any { it.code !in 0x21..0x7e }) return null
        if (value == "*") return value
        if (!value.startsWith('/')) return null
        return value
    }

    /** Reads the Host header value, keeping any port. Returns null when absent or unsafe. */
    private fun readHostHeader(payload: ByteArray, start: Int, end: Int): String? {
        var lineStart = start
        while (lineStart < end) {
            val lineEnd = findCrlf(payload, lineStart, end).takeIf { it >= 0 } ?: end
            val line = ascii(payload, lineStart, lineEnd) ?: return null
            val separator = line.indexOf(':')
            if (separator > 0 && line.substring(0, separator).trim().equals("host", ignoreCase = true)) {
                val raw = line.substring(separator + 1).trim()
                if (raw.isEmpty() || raw.length > 255) return null
                if (raw.any { it.code !in 0x21..0x7e }) return null
                val hostOnly = raw.substringBefore(':')
                // allowIpv4Literal: an HTTP Host header may legitimately be a bare IPv4 literal
                // (e.g. "http://192.168.1.1/"), unlike a TLS SNI or a firewall domain rule.
                return if (HostValidation.isValidDomain(hostOnly, allowIpv4Literal = true)) raw else null
            }
            lineStart = lineEnd + 2
        }
        return null
    }

    private fun parseResponse(
        firstLine: String,
        direction: PacketDirection,
        observedAtMillis: Long,
        limitations: Set<ProtocolEvidenceLimitation>,
    ): ProtocolEvidenceObservation {
        val fields = firstLine.split(' ', limit = 3)
        val status = fields.getOrNull(1)?.toIntOrNull()
        if (fields.size < 2 || !version.matches(fields[0]) || status == null || status !in 100..599) {
            return ProtocolEvidenceObservation(
                source = ProtocolEvidenceSource.CLEARTEXT_HTTP_RESPONSE,
                direction = direction,
                observedAtMillis = observedAtMillis,
                confidence = ProtocolEvidenceConfidence.LIMITED,
                value = null,
                limitations = setOf(ProtocolEvidenceLimitation.MALFORMED),
            )
        }
        return ProtocolEvidenceObservation(
            source = ProtocolEvidenceSource.CLEARTEXT_HTTP_RESPONSE,
            direction = direction,
            observedAtMillis = observedAtMillis,
            confidence = ProtocolEvidenceConfidence.HIGH,
            value = ProtocolEvidenceValue.HttpResponse(status, fields[0]),
            limitations = limitations,
        )
    }

    private fun limitedRequest(
        direction: PacketDirection,
        observedAtMillis: Long,
        limitation: ProtocolEvidenceLimitation,
    ) = ProtocolEvidenceObservation(
        source = ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST,
        direction = direction,
        observedAtMillis = observedAtMillis,
        confidence = ProtocolEvidenceConfidence.LIMITED,
        value = null,
        limitations = setOf(limitation),
    )

    private fun containsSensitiveHeader(bytes: ByteArray, from: Int, headerEnd: Int): Boolean {
        var offset = from
        while (offset < headerEnd) {
            val lineEnd = findCrlf(bytes, offset, headerEnd)
            if (lineEnd < offset) return false
            val colon = indexOf(bytes, ':'.code.toByte(), offset, lineEnd)
            if (colon > offset) {
                val name = ascii(bytes, offset, colon)?.lowercase(Locale.ROOT)
                if (name in sensitiveHeaderNames || name?.containsCredentialIndicator() == true) return true
            }
            offset = lineEnd + 2
        }
        return false
    }
}

private fun String.containsCredentialIndicator(): Boolean =
    contains("auth") || contains("token") || contains("secret") || contains("credential") || contains("api-key") || contains("apikey")

private class SafeByteReader(
    private val bytes: ByteArray,
    private var offset: Int,
    private val limit: Int,
) {
    val remaining: Int get() = limit - offset

    fun u8(): Int? = if (remaining >= 1) u8(bytes, offset++) else null

    fun u16(): Int? {
        if (remaining < 2) return null
        val value = u16(bytes, offset)
        offset += 2
        return value
    }

    fun skip(count: Int): Boolean {
        if (count < 0 || count > remaining) return false
        offset += count
        return true
    }

    fun bytes(count: Int): ByteArray? {
        if (count < 0 || count > remaining) return null
        return bytes.copyOfRange(offset, offset + count).also { offset += count }
    }

    fun subReader(count: Int): SafeByteReader? {
        if (count < 0 || count > remaining) return null
        val result = SafeByteReader(bytes, offset, offset + count)
        offset += count
        return result
    }
}

private fun looksLikeTlsHandshake(bytes: ByteArray): Boolean = bytes.isNotEmpty() && u8(bytes, 0) == 22

private fun looksLikeHttpRequest(bytes: ByteArray): Boolean {
    val firstSpace = indexOf(bytes, ' '.code.toByte(), 0, minOf(bytes.size, 17))
    return firstSpace in 1..16 && bytes.copyOfRange(0, firstSpace).all { it in 'A'.code.toByte()..'Z'.code.toByte() }
}

private fun ByteArray.startsWithAscii(prefix: String): Boolean =
    size >= prefix.length && prefix.indices.all { index -> this[index] == prefix[index].code.toByte() }

private fun findHeaderEnd(bytes: ByteArray, limit: Int): Int {
    val maxStart = limit - 4
    for (index in 0..maxStart) {
        if (bytes[index] == '\r'.code.toByte() && bytes[index + 1] == '\n'.code.toByte() &&
            bytes[index + 2] == '\r'.code.toByte() && bytes[index + 3] == '\n'.code.toByte()
        ) return index
    }
    return -1
}

private fun findCrlf(bytes: ByteArray, from: Int, limit: Int): Int {
    for (index in from until limit - 1) {
        if (bytes[index] == '\r'.code.toByte() && bytes[index + 1] == '\n'.code.toByte()) return index
    }
    return -1
}

private fun indexOf(bytes: ByteArray, target: Byte, from: Int, until: Int): Int {
    for (index in from until until) if (bytes[index] == target) return index
    return -1
}

private fun isSafeHttpHeader(bytes: ByteArray, exclusiveEnd: Int): Boolean {
    for (index in 0 until exclusiveEnd) {
        val value = u8(bytes, index)
        if (value == '\r'.code || value == '\n'.code) continue
        if (value !in 0x20..0x7e) return false
    }
    return true
}

private fun ascii(bytes: ByteArray, from: Int, until: Int): String? {
    if (from < 0 || until < from || until > bytes.size) return null
    val output = StringBuilder(until - from)
    for (index in from until until) {
        val value = u8(bytes, index)
        if (value !in 0x20..0x7e) return null
        output.append(value.toChar())
    }
    return output.toString()
}

private fun ByteArray.decodeToStringOrNull(): String? {
    if (any { byte -> (byte.toInt() and 0xff) !in 0x21..0x7e }) return null
    return String(this, Charsets.US_ASCII)
}

private fun isTlsLegacyVersion(major: Int, minor: Int): Boolean = major == 3 && minor in 0..4


private fun u8(bytes: ByteArray, offset: Int): Int = bytes[offset].toInt() and 0xff

private fun u16(bytes: ByteArray, offset: Int): Int = (u8(bytes, offset) shl 8) or u8(bytes, offset + 1)

private fun u24(bytes: ByteArray, offset: Int): Int =
    (u8(bytes, offset) shl 16) or (u8(bytes, offset + 1) shl 8) or u8(bytes, offset + 2)

private fun saturatingIncrement(value: Long): Long = if (value == Long.MAX_VALUE) value else value + 1L
