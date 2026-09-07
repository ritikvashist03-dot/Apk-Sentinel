package app.apksentinel.engine.tlsinspection

import java.nio.ByteBuffer
import java.util.ArrayDeque

enum class TlsInspectionLifecycleState { DISABLED, ACTIVE, STOPPED, EXPIRED, FAILED, LIMIT_REACHED }

enum class TlsInspectionFailureReason {
    CLOCK_UNAVAILABLE,
    INVALID_CLOCK,
    CLOCK_ROLLBACK,
    LOCAL_CONSUMER_FAILURE,
}

enum class TlsInspectionStopReason { USER_STOPPED, DURATION_EXPIRED, SESSION_BYTE_LIMIT, FAILURE }

enum class TlsInspectionSegmentResult {
    DELIVERED,
    DROPPED_NOT_ACTIVE,
    DROPPED_PACKAGE_NOT_ALLOWED,
    DROPPED_EMPTY_OR_TOO_LARGE,
    DROPPED_SESSION_LIMIT,
    DROPPED_UNSUPPORTED_PROTOCOL,
    FAILED_CLOSED,
}

/** This foundation accepts only the future-reviewed HTTP over TLS 1.2 bridge. */
enum class TlsInspectionProtocol { TLS_1_2 }

enum class TlsInspectionHttpProtocol { HTTP_1_1, HTTP_2 }

/**
 * Safe, non-content metadata. There are deliberately no fields for hostname,
 * request path, header, credential, body, endpoint, packet, or raw TLS data.
 */
data class TlsInspectionMetadata(
    val tlsProtocol: TlsInspectionProtocol,
    val httpProtocol: TlsInspectionHttpProtocol,
    val plaintextByteCount: Int,
) {
    init {
        require(plaintextByteCount > 0) { "Plaintext byte count must be positive." }
    }
}

/** Metadata retained in a bounded in-memory ring only. It contains no plaintext. */
data class TlsInspectionMetadataEvent(
    val sequence: Long,
    val packageName: String,
    val observedAtMillis: Long,
    val tlsProtocol: TlsInspectionProtocol,
    val httpProtocol: TlsInspectionHttpProtocol,
    val deliveredByteCount: Int,
) {
    init {
        require(sequence > 0L && observedAtMillis >= 0L && deliveredByteCount > 0) {
            "TLS inspection metadata event is invalid."
        }
    }
}

/**
 * A short-lived, read-only view over a copied segment. It can be used only in
 * the callback and is zeroized immediately afterwards. A consumer must not
 * copy, persist, log, export, or transmit its data.
 */
class EphemeralTlsDecryptedSegment internal constructor(
    private val bytes: ByteArray,
    private val length: Int = bytes.size,
) {
    init {
        require(length in 0..bytes.size)
    }
    private var closed = false

    val size: Int get() = if (closed) 0 else length

    fun <T> useReadOnlyBytes(block: (ByteBuffer) -> T): T {
        check(!closed) { "TLS segment has already been zeroized." }
        return block(ByteBuffer.wrap(bytes, 0, length).slice().asReadOnlyBuffer())
    }

    internal fun zeroize() {
        bytes.fill(0, 0, length)
        closed = true
    }
}

/**
 * Runs inside the device process only. The contract intentionally exposes no
 * disk, export, telemetry, network, or content-logging callback.
 */
fun interface InMemoryTlsDecryptedSegmentConsumer {
    fun inspect(segment: EphemeralTlsDecryptedSegment)
}

fun interface TlsInspectionMetadataConsumer {
    fun onMetadata(event: TlsInspectionMetadataEvent)
}

fun interface TlsInspectionLifecycleConsumer {
    fun onLifecycle(snapshot: TlsInspectionSnapshot)
}

data class TlsInspectionSnapshot(
    val state: TlsInspectionLifecycleState,
    val startedAtMillis: Long? = null,
    val stoppedAtMillis: Long? = null,
    val stopReason: TlsInspectionStopReason? = null,
    val failureReason: TlsInspectionFailureReason? = null,
    val deliveredBytes: Long = 0L,
    val deliveredSegments: Long = 0L,
    val metadataEvents: List<TlsInspectionMetadataEvent> = emptyList(),
    val limitations: Set<TlsInspectionLimitation>,
) {
    /** A host must present this state prominently, with an immediately available Stop control. */
    val mustShowProminentActiveIndicator: Boolean get() = state == TlsInspectionLifecycleState.ACTIVE
    val mustShowStopControl: Boolean get() = state == TlsInspectionLifecycleState.ACTIVE
}

sealed interface TlsInspectionStartResult {
    data class Started(val session: TlsInspectionSession) : TlsInspectionStartResult
    data class Rejected(val reason: TlsInspectionStartRejection) : TlsInspectionStartResult
}

/**
 * Strict factory. It cannot start a session until all containment gates pass:
 * separate session consent, an explicitly reviewed narrow bridge, a bounded
 * non-sensitive allowlist, a usable clock/key/certificate, and confirmed CA
 * installation. UNKNOWN certificate state fails closed.
 */
class TlsInspectionSessionFactory(
    private val credentialProvider: TlsCaCredentialProvider,
    private val installationVerifier: CertificateInstallationVerifier = UnknownCertificateInstallationVerifier,
    private val clock: TlsInspectionClock = SystemTlsInspectionClock,
) {
    fun start(
        request: TlsInspectionStartRequest,
        decryptedSegmentConsumer: InMemoryTlsDecryptedSegmentConsumer,
        metadataConsumer: TlsInspectionMetadataConsumer = TlsInspectionMetadataConsumer { },
        lifecycleConsumer: TlsInspectionLifecycleConsumer = TlsInspectionLifecycleConsumer { },
    ): TlsInspectionStartResult {
        if (!request.configuration.isRequested) return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.DISABLED_BY_DEFAULT)
        val capability = AndroidTlsInspectionCapabilityMatrix.forApi(request.androidApiLevel)
            ?: return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.UNSUPPORTED_ANDROID_API)
        if (request.dataPlaneReadiness != TlsInspectionDataPlaneReadiness.REVIEWED_HTTP_TLS12_ONLY) {
            return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.DATA_PLANE_UNAVAILABLE)
        }
        val scope = when (val result = TlsInspectionPackageScope.create(request.selectedPackages)) {
            is TlsInspectionPackageScopeResult.Allowed -> result.scope
            is TlsInspectionPackageScopeResult.Rejected -> return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.PACKAGE_SCOPE_REJECTED)
        }
        val startedAt = safeNow() ?: return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.CLOCK_UNAVAILABLE)
        if (startedAt <= 0L) return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.INVALID_CLOCK)
        val credential = credentialProvider.existingMetadata()
        val metadata = (credential as? TlsCaCredentialLookup.Available)?.metadata
            ?: return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.CA_CREDENTIAL_UNAVAILABLE)
        if (metadata.notBeforeMillis > startedAt || metadata.notAfterMillis <= startedAt) {
            return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.CA_CREDENTIAL_UNAVAILABLE)
        }
        val verification = try {
            installationVerifier.verify(metadata)
        } catch (_: RuntimeException) {
            return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.CERTIFICATE_VERIFICATION_FAILED)
        }
        when (verification.state) {
            CertificateInstallationState.INSTALLED -> Unit
            CertificateInstallationState.NOT_INSTALLED -> return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.CERTIFICATE_NOT_INSTALLED)
            CertificateInstallationState.UNKNOWN -> return TlsInspectionStartResult.Rejected(TlsInspectionStartRejection.CERTIFICATE_INSTALLATION_UNKNOWN)
        }
        return TlsInspectionStartResult.Started(
            TlsInspectionSession(
                configuration = request.configuration,
                scope = scope,
                startedAtMillis = startedAt,
                clock = clock,
                decryptedSegmentConsumer = decryptedSegmentConsumer,
                metadataConsumer = metadataConsumer,
                lifecycleConsumer = lifecycleConsumer,
                limitations = capability.limitations,
            ),
        )
    }

    private fun safeNow(): Long? = try {
        clock.nowMillis()
    } catch (_: RuntimeException) {
        null
    }
}

/**
 * Active state exists only in memory. Raw plaintext is copied to a bounded
 * ephemeral buffer, sent to one local callback, and zeroized in `finally`.
 * The session stores only the bounded metadata events below.
 */
class TlsInspectionSession internal constructor(
    private val configuration: TlsInspectionConfiguration,
    private val scope: TlsInspectionPackageScope,
    private val startedAtMillis: Long,
    private val clock: TlsInspectionClock,
    private val decryptedSegmentConsumer: InMemoryTlsDecryptedSegmentConsumer,
    private val metadataConsumer: TlsInspectionMetadataConsumer,
    private val lifecycleConsumer: TlsInspectionLifecycleConsumer,
    private val limitations: Set<TlsInspectionLimitation>,
) {
    private val lock = Any()
    private val events = ArrayDeque<TlsInspectionMetadataEvent>()
    private var state = TlsInspectionLifecycleState.ACTIVE
    private var stoppedAtMillis: Long? = null
    private var stopReason: TlsInspectionStopReason? = null
    private var failureReason: TlsInspectionFailureReason? = null
    private var deliveredBytes = 0L
    private var deliveredSegments = 0L
    private var nextSequence = 1L

    init {
        notifyLifecycle(snapshot())
    }

    fun offerDecryptedHttpTls12Segment(
        packageName: String,
        metadata: TlsInspectionMetadata,
        plaintext: ByteArray,
    ): TlsInspectionSegmentResult = synchronized(lock) {
        if (state != TlsInspectionLifecycleState.ACTIVE) return TlsInspectionSegmentResult.DROPPED_NOT_ACTIVE
        val now = safeNowOrFailLocked() ?: return TlsInspectionSegmentResult.FAILED_CLOSED
        if (now < startedAtMillis) {
            failLocked(TlsInspectionFailureReason.CLOCK_ROLLBACK)
            return TlsInspectionSegmentResult.FAILED_CLOSED
        }
        if (now - startedAtMillis >= configuration.maximumDurationMillis) {
            stopLocked(TlsInspectionLifecycleState.EXPIRED, TlsInspectionStopReason.DURATION_EXPIRED, now)
            return TlsInspectionSegmentResult.DROPPED_NOT_ACTIVE
        }
        if (!scope.contains(packageName)) return TlsInspectionSegmentResult.DROPPED_PACKAGE_NOT_ALLOWED
        if (plaintext.isEmpty() || plaintext.size > configuration.maximumBytesPerSegment || plaintext.size != metadata.plaintextByteCount) {
            return TlsInspectionSegmentResult.DROPPED_EMPTY_OR_TOO_LARGE
        }
        if (deliveredBytes > configuration.maximumSessionBytes - plaintext.size.toLong()) {
            stopLocked(TlsInspectionLifecycleState.LIMIT_REACHED, TlsInspectionStopReason.SESSION_BYTE_LIMIT, now)
            return TlsInspectionSegmentResult.DROPPED_SESSION_LIMIT
        }

        val copied = plaintext.copyOf()
        val copiedSize = copied.size
        val ephemeral = EphemeralTlsDecryptedSegment(copied)
        try {
            try {
                decryptedSegmentConsumer.inspect(ephemeral)
            } catch (_: RuntimeException) {
                failLocked(TlsInspectionFailureReason.LOCAL_CONSUMER_FAILURE)
                return TlsInspectionSegmentResult.FAILED_CLOSED
            }

            val event = TlsInspectionMetadataEvent(
                sequence = nextSequence++,
                packageName = packageName,
                observedAtMillis = now,
                tlsProtocol = metadata.tlsProtocol,
                httpProtocol = metadata.httpProtocol,
                deliveredByteCount = copiedSize,
            )
            try {
                metadataConsumer.onMetadata(event)
            } catch (_: RuntimeException) {
                failLocked(TlsInspectionFailureReason.LOCAL_CONSUMER_FAILURE)
                return TlsInspectionSegmentResult.FAILED_CLOSED
            }
            if (events.size == configuration.maximumMetadataEvents) events.removeFirst()
            events.addLast(event)
            deliveredBytes += copiedSize.toLong()
            deliveredSegments += 1L
            TlsInspectionSegmentResult.DELIVERED
        } finally {
            ephemeral.zeroize()
            copied.fill(0)
        }
    }

    /** The host's Stop action must call this immediately; it is safe to call more than once. */
    fun stop() = synchronized(lock) {
        if (state == TlsInspectionLifecycleState.ACTIVE) {
            stopLocked(TlsInspectionLifecycleState.STOPPED, TlsInspectionStopReason.USER_STOPPED, safeNow() ?: startedAtMillis)
        }
    }

    fun snapshot(): TlsInspectionSnapshot = synchronized(lock) {
        TlsInspectionSnapshot(
            state = state,
            startedAtMillis = startedAtMillis,
            stoppedAtMillis = stoppedAtMillis,
            stopReason = stopReason,
            failureReason = failureReason,
            deliveredBytes = deliveredBytes,
            deliveredSegments = deliveredSegments,
            metadataEvents = events.toList(),
            limitations = limitations,
        )
    }

    private fun safeNow(): Long? = try {
        clock.nowMillis()
    } catch (_: RuntimeException) {
        null
    }

    private fun safeNowOrFailLocked(): Long? {
        val now = safeNow()
        if (now == null) failLocked(TlsInspectionFailureReason.CLOCK_UNAVAILABLE)
        else if (now < 0L) failLocked(TlsInspectionFailureReason.INVALID_CLOCK)
        return now
    }

    private fun failLocked(reason: TlsInspectionFailureReason) {
        if (state != TlsInspectionLifecycleState.ACTIVE) return
        failureReason = reason
        stopLocked(TlsInspectionLifecycleState.FAILED, TlsInspectionStopReason.FAILURE, safeNow() ?: startedAtMillis)
    }

    private fun stopLocked(newState: TlsInspectionLifecycleState, reason: TlsInspectionStopReason, atMillis: Long) {
        state = newState
        stopReason = reason
        stoppedAtMillis = atMillis.coerceAtLeast(startedAtMillis)
        notifyLifecycle(snapshot())
    }

    private fun notifyLifecycle(snapshot: TlsInspectionSnapshot) {
        try {
            lifecycleConsumer.onLifecycle(snapshot)
        } catch (_: RuntimeException) {
            // A UI observer cannot keep collection active or crash the session.
        }
    }
}
