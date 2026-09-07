package app.apksentinel.networkmonitor

/**
 * Process-local bridge supplied by the host app.  The service intent carries
 * only bounded, user-visible session configuration; this interface is where a
 * host keeps its non-exportable CA handle and normal system-trust context.
 */
interface TlsInspectionRoute {
    fun openSession(configuration: TlsInspectionSessionConfiguration): TlsInspectionRouteSession?
}

data class TlsInspectionSessionConfiguration(
    val selectedPackages: Set<String>,
    val sessionConsentVersion: String,
    val sessionConsentAcknowledgedAtMillis: Long,
    val sessionConsentNonce: String,
    val maximumSessionBytes: Int = 128 * 1_024,
    val maximumBytesPerFlow: Int = 64 * 1_024,
    val maximumDurationMillis: Long = 5 * 60 * 1_000L,
) {
    init {
        require(selectedPackages.isNotEmpty() && selectedPackages.size <= 25)
        require(selectedPackages.all { ANDROID_PACKAGE_NAME.matches(it) })
        require(sessionConsentVersion.isNotBlank())
        require(sessionConsentAcknowledgedAtMillis > 0L)
        require(sessionConsentNonce.isNotBlank())
        require(maximumSessionBytes in 4 * 1_024..512 * 1_024)
        require(maximumBytesPerFlow in 4 * 1_024..256 * 1_024)
        require(maximumBytesPerFlow <= maximumSessionBytes)
        require(maximumDurationMillis in 5_000L..30 * 60 * 1_000L)
    }
}

interface TlsInspectionRouteSession {
    fun openTcpFlow(attribution: AppAttribution, remotePort: Int): TlsInspectionFlowDecision

    /** Selected UDP/443 is rejected: the route never treats QUIC as HTTPS. */
    fun rejectUdpFlow(attribution: AppAttribution, remotePort: Int): Boolean

    /** Bounded diagnostic counters; implementations must not retain plaintext. */
    fun failureCounts(): Map<TlsInspectionRouteFailure, Long> = emptyMap()

    fun stop()
}

sealed interface TlsInspectionFlowDecision {
    data object Bypass : TlsInspectionFlowDecision
    data class Intercept(val flow: TlsInspectionFlow) : TlsInspectionFlowDecision
    data class Reject(val reason: TlsInspectionRouteFailure) : TlsInspectionFlowDecision
}

interface TlsInspectionFlow {
    fun onClientCiphertext(ciphertext: ByteArray): TlsInspectionFlowResult
    fun onUpstreamCiphertext(ciphertext: ByteArray): TlsInspectionFlowResult
    fun onClientClosed(): TlsInspectionFlowResult = TlsInspectionFlowResult.closed()
    fun onUpstreamClosed(): TlsInspectionFlowResult = TlsInspectionFlowResult.closed()
    fun close()
}

enum class TlsInspectionRouteFailure {
    UNKNOWN_ATTRIBUTION,
    SHARED_UID,
    QUIC_UNSUPPORTED,
    NO_SNI,
    MALFORMED_CLIENT_HELLO,
    OVERSIZE,
    UNSUPPORTED_PROTOCOL,
    TLS_PROVIDER_UNAVAILABLE,
    UPSTREAM_TRUST_REJECTED,
    USER_CA_REJECTED,
    CERTIFICATE_PINNING_REJECTED,
    NON_HTTP,
    HANDSHAKE_TIMEOUT,
    BUFFER_LIMIT,
    CLOSED,
}

enum class TlsInspectionFlowState { PROGRESSED, NEED_MORE_INPUT, CLOSED, FAILED }

data class TlsInspectionFlowResult(
    val state: TlsInspectionFlowState = TlsInspectionFlowState.PROGRESSED,
    val toUpstream: ByteArray = ByteArray(0),
    val toClient: ByteArray = ByteArray(0),
    val failure: TlsInspectionRouteFailure? = null,
) {
    init {
        require(toUpstream.size <= MAX_OUTPUT_BYTES)
        require(toClient.size <= MAX_OUTPUT_BYTES)
    }

    companion object {
        const val MAX_OUTPUT_BYTES = 64 * 1_024
        fun failed(reason: TlsInspectionRouteFailure) = TlsInspectionFlowResult(
            state = TlsInspectionFlowState.FAILED,
            failure = reason,
        )
        fun closed() = TlsInspectionFlowResult(state = TlsInspectionFlowState.CLOSED)
    }
}

private val ANDROID_PACKAGE_NAME = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")
