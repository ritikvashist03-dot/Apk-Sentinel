package app.apksentinel.engine.remotestream

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.ArrayDeque

data class RemoteStreamStartRequest(
    val configuration: RemoteStreamConfiguration = RemoteStreamConfiguration(),
    val pairing: RemoteStreamPairing,
    val sessionConsent: RemoteStreamSessionConsent? = null,
    val sensitivePayloadAuthorization: RemoteStreamSensitivePayloadAuthorization? = null,
)

enum class RemoteStreamStartRejection {
    DISABLED_BY_DEFAULT,
    INVALID_CONFIGURATION,
    CLOCK_UNAVAILABLE,
    INVALID_CLOCK,
    PAIRING_CONSENT_NOT_FRESH,
    SESSION_CONSENT_NOT_FRESH,
    SENSITIVE_PAYLOAD_NOT_AUTHORIZED,
    RANDOM_UNAVAILABLE,
    TRANSPORT_OPEN_FAILED,
    TRANSPORT_SECURITY_PROOF_INVALID,
    SESSION_KEY_UNAVAILABLE,
}

sealed interface RemoteStreamStartResult {
    data class Started(val session: RemoteStreamSession) : RemoteStreamStartResult
    data class Rejected(val reason: RemoteStreamStartRejection) : RemoteStreamStartResult
}

enum class RemoteStreamLifecycleState { DISABLED, ACTIVE, STOPPED, EXPIRED, LIMIT_REACHED, FAILED, AUTO_STOPPED }

enum class RemoteStreamStopReason {
    USER_STOPPED,
    DURATION_EXPIRED,
    LIMIT_REACHED,
    NETWORK_CHANGED,
    APP_BACKGROUNDED,
    PROCESS_OWNER_STOPPED,
    CLOCK_FAILURE,
    CONSENT_EXPIRED,
    RECEIVER_AUTH_LOST,
    TRANSPORT_FAILURE,
    HOST_FAILURE,
}

enum class RemoteStreamFailureReason {
    CLOCK_UNAVAILABLE,
    INVALID_CLOCK,
    CLOCK_ROLLBACK,
    CONSENT_EXPIRED,
    RECEIVER_AUTH_LOST,
    TRANSPORT_FAILED,
    HOST_FAILED,
    FRAME_ENCRYPTION_FAILED,
}

enum class RemoteStreamOwnerSignal { NETWORK_CHANGED, APP_BACKGROUNDED, PROCESS_OWNER_STOPPED }

enum class RemoteStreamOfferResult {
    QUEUED_AND_SENT,
    QUEUED_BACKPRESSURE,
    DROPPED_NOT_ACTIVE,
    DROPPED_CATEGORY_NOT_ALLOWED,
    DROPPED_INVALID_RECORD,
    DROPPED_BACKPRESSURE,
    DROPPED_LIMIT,
    FAILED_CLOSED,
}

data class RemoteStreamSnapshot(
    val state: RemoteStreamLifecycleState,
    val destinationDisplayValue: String,
    val receiverFingerprint: String,
    val allowedDataCategories: Set<RemoteStreamDataCategory>,
    val startedAtMillis: Long? = null,
    val stoppedAtMillis: Long? = null,
    val stopReason: RemoteStreamStopReason? = null,
    val failureReason: RemoteStreamFailureReason? = null,
    val acceptedPackets: Long = 0L,
    val acceptedBytes: Long = 0L,
    val transmittedPackets: Long = 0L,
    val backpressureEvents: Long = 0L,
    val droppedPackets: Long = 0L,
    val queuedPackets: Int = 0,
    val queuedBytes: Int = 0,
) {
    /** Host UI must render these plainly and provide an immediate Stop action while true. */
    val mustShowProminentActiveIndicator: Boolean get() = state == RemoteStreamLifecycleState.ACTIVE
    val mustShowStopControl: Boolean get() = state == RemoteStreamLifecycleState.ACTIVE
}

fun interface RemoteStreamLifecycleConsumer { fun onLifecycle(snapshot: RemoteStreamSnapshot) }

/**
 * Opens exactly one user-paired outbound channel. The session itself contains
 * no listener or connection discovery code, and starts only after a host's
 * pinned mutual-TLS attestation matches the exact consented pairing.
 */
class RemoteStreamSessionFactory(
    private val secureHost: RemoteStreamSecureHost,
    private val clock: RemoteStreamClock = SystemRemoteStreamClock,
    private val random: SecureRandom = SecureRandom(),
) {
    fun start(
        request: RemoteStreamStartRequest,
        lifecycleConsumer: RemoteStreamLifecycleConsumer = RemoteStreamLifecycleConsumer { },
    ): RemoteStreamStartResult {
        val configuration = request.configuration
        if (!configuration.isRequested) return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.DISABLED_BY_DEFAULT)
        if (configuration.validate() != null) return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.INVALID_CONFIGURATION)
        val now = safeNow() ?: return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.CLOCK_UNAVAILABLE)
        if (now <= 0L) return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.INVALID_CLOCK)
        if (!request.pairing.consent.isFreshFor(request.pairing, now)) {
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.PAIRING_CONSENT_NOT_FRESH)
        }
        val sessionConsent = request.sessionConsent
        if (sessionConsent == null || !sessionConsent.isFreshFor(request.pairing, configuration, now)) {
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.SESSION_CONSENT_NOT_FRESH)
        }
        val sensitiveRequested = configuration.allowedDataCategories intersect RemoteStreamSensitivePayloadAuthorization.SENSITIVE_CATEGORIES
        if (sensitiveRequested.isNotEmpty() && (request.sensitivePayloadAuthorization?.isFreshFor(request.pairing, sensitiveRequested, now) != true)) {
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.SENSITIVE_PAYLOAD_NOT_AUTHORIZED)
        }

        val nonce = try {
            ByteArray(32).also(random::nextBytes)
        } catch (_: RuntimeException) {
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.RANDOM_UNAVAILABLE)
        }
        val keyDer = request.pairing.receiverIdentity.receiverPublicKeyDer()
        val opened = try {
            secureHost.openPinnedMutualTransport(
                RemoteStreamTransportOpenRequest(
                    destination = request.pairing.destination,
                    receiverKeyId = request.pairing.receiverIdentity.keyId,
                    receiverPublicKeyDer = keyDer,
                    expectedReceiverFingerprint = request.pairing.receiverIdentity.sha256Fingerprint,
                    sessionNonce = nonce.copyOf(),
                ),
            )
        } catch (_: RuntimeException) {
            nonce.fill(0)
            keyDer.fill(0)
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.TRANSPORT_OPEN_FAILED)
        } finally {
            keyDer.fill(0)
        }
        return when (opened) {
            is RemoteStreamTransportOpenResult.Rejected -> {
                nonce.fill(0)
                RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.TRANSPORT_OPEN_FAILED)
            }
            is RemoteStreamTransportOpenResult.Opened -> startOpened(request, sessionConsent, now, nonce, opened, lifecycleConsumer)
        }
    }

    private fun startOpened(
        request: RemoteStreamStartRequest,
        sessionConsent: RemoteStreamSessionConsent,
        now: Long,
        nonce: ByteArray,
        opened: RemoteStreamTransportOpenResult.Opened,
        lifecycleConsumer: RemoteStreamLifecycleConsumer,
    ): RemoteStreamStartResult {
        val proof = opened.proof
        val validProof = proof.tlsVersion in setOf(RemoteStreamTlsVersion.TLS_1_2, RemoteStreamTlsVersion.TLS_1_3) &&
            proof.destinationDisplayValue == request.pairing.destination.displayValue &&
            proof.observedReceiverFingerprint == request.pairing.receiverIdentity.sha256Fingerprint &&
            proof.mutualAuthenticationConfirmed &&
            MessageDigest.isEqual(proof.echoedSessionNonce, nonce)
        nonce.fill(0)
        proof.echoedSessionNonce.fill(0)
        if (!validProof) {
            closeOpened(opened)
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.TRANSPORT_SECURITY_PROOF_INVALID)
        }
        var key: ByteArray? = null
        try {
            key = opened.sessionKey.copyForImmediateUse()
            if (key == null || key.size != AES_256_KEY_BYTES) {
                closeTransport(opened.transport)
                return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.SESSION_KEY_UNAVAILABLE)
            }
            val encoder = RemoteStreamFrameEncoder(key)
            return RemoteStreamStartResult.Started(
                RemoteStreamSession(
                    configuration = request.configuration,
                    pairing = request.pairing,
                    sessionConsent = sessionConsent,
                    startedAtMillis = now,
                    clock = clock,
                    transport = opened.transport,
                    encoder = encoder,
                    lifecycleConsumer = lifecycleConsumer,
                ),
            )
        } catch (_: RuntimeException) {
            closeTransport(opened.transport)
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.SESSION_KEY_UNAVAILABLE)
        } finally {
            key?.fill(0)
            try {
                opened.sessionKey.destroy()
            } catch (_: RuntimeException) {
                // Best-effort cleanup cannot expose host implementation details.
            }
        }
    }

    private fun closeOpened(opened: RemoteStreamTransportOpenResult.Opened) {
        closeTransport(opened.transport)
        try {
            opened.sessionKey.destroy()
        } catch (_: RuntimeException) {
            // Best-effort cleanup of host-owned ephemeral material.
        }
    }

    private fun closeTransport(transport: RemoteStreamAuthenticatedTransport) {
        try {
            transport.close()
        } catch (_: RuntimeException) {
            // Host failures are intentionally not exposed as raw exception text.
        }
    }

    private fun safeNow(): Long? = try { clock.nowMillis() } catch (_: RuntimeException) { null }
}

/**
 * In-memory session with a bounded encrypted queue. Plain input is encrypted
 * before enqueue and is never persisted by this module. Ingress only performs
 * bounded validation/encryption and a non-blocking queue offer. Exactly one
 * writer thread owns transport I/O, always retries the ordered head, drops
 * newest input when full, and wipes every frame as soon as it is sent or the
 * session is stopped.
 */
class RemoteStreamSession internal constructor(
    private val configuration: RemoteStreamConfiguration,
    private val pairing: RemoteStreamPairing,
    private val sessionConsent: RemoteStreamSessionConsent,
    private val startedAtMillis: Long,
    private val clock: RemoteStreamClock,
    private val transport: RemoteStreamAuthenticatedTransport,
    private val encoder: RemoteStreamFrameEncoder,
    private val lifecycleConsumer: RemoteStreamLifecycleConsumer,
) {
    private val lock = Any()
    private val writerMonitor = Object()
    private val queue = ArrayDeque<QueuedRemoteStreamFrame>()
    private var state = RemoteStreamLifecycleState.ACTIVE
    private var stoppedAtMillis: Long? = null
    private var stopReason: RemoteStreamStopReason? = null
    private var failureReason: RemoteStreamFailureReason? = null
    private var lastObservedAtMillis: Long = startedAtMillis
    private var nextSequence = 1L
    private var acceptedPackets = 0L
    private var acceptedBytes = 0L
    private var transmittedPackets = 0L
    private var backpressureEvents = 0L
    private var droppedPackets = 0L
    private var queuedBytes = 0
    private var transportClosed = false
    private var writerExit = false

    private data class Transition(val snapshot: RemoteStreamSnapshot)

    init {
        Thread(::writerLoop, "apk-sentinel-remote-stream-writer").apply {
            isDaemon = true
            start()
        }
        notifyLifecycle(snapshot())
    }

    fun offer(record: RemoteStreamRecord): RemoteStreamOfferResult {
        var result = RemoteStreamOfferResult.DROPPED_NOT_ACTIVE
        var transition: Transition? = null
        synchronized(lock) {
            val usable = ensureUsableLocked()
            if (usable != null) {
                result = RemoteStreamOfferResult.FAILED_CLOSED
                transition = usable
            } else if (state != RemoteStreamLifecycleState.ACTIVE) {
                result = if (state == RemoteStreamLifecycleState.FAILED) {
                    RemoteStreamOfferResult.FAILED_CLOSED
                } else {
                    RemoteStreamOfferResult.DROPPED_NOT_ACTIVE
                }
            } else if (record.category !in configuration.allowedDataCategories) {
                droppedPackets += 1L
                result = RemoteStreamOfferResult.DROPPED_CATEGORY_NOT_ALLOWED
            } else if (record.observedAtMillis <= 0L || record.bytes.size !in 1..configuration.maximumRecordBytes ||
                record.observedAtMillis > lastObservedAtMillis + MAX_FUTURE_RECORD_SKEW_MILLIS
            ) {
                droppedPackets += 1L
                result = RemoteStreamOfferResult.DROPPED_INVALID_RECORD
            } else if (acceptedPackets >= configuration.maximumPackets ||
                acceptedBytes > configuration.maximumBytes - record.bytes.size.toLong()
            ) {
                transition = stopLocked(RemoteStreamLifecycleState.LIMIT_REACHED, RemoteStreamStopReason.LIMIT_REACHED, nowOrLastLocked())
                result = RemoteStreamOfferResult.DROPPED_LIMIT
            } else {
                val maximumFrameBytes = HEADER_BYTES + record.bytes.size + GCM_TAG_BYTES
                if (queue.size >= configuration.maximumQueueRecords ||
                    queuedBytes > configuration.maximumQueueBytes - maximumFrameBytes
                ) {
                    // Drop-newest is deliberate: the ordered queue head remains intact.
                    droppedPackets += 1L
                    result = RemoteStreamOfferResult.DROPPED_BACKPRESSURE
                } else {
                    val encoded = encoder.encode(record, nextSequence, configuration.maximumRecordBytes)
                    if (encoded == null) {
                        transition = failLocked(RemoteStreamFailureReason.FRAME_ENCRYPTION_FAILED)
                        result = RemoteStreamOfferResult.FAILED_CLOSED
                    } else {
                        val wasEmpty = queue.isEmpty()
                        nextSequence += 1L
                        acceptedPackets += 1L
                        acceptedBytes += encoded.payloadBytes.toLong()
                        queue.addLast(encoded)
                        queuedBytes += encoded.frame.size
                        result = if (wasEmpty) RemoteStreamOfferResult.QUEUED_AND_SENT else RemoteStreamOfferResult.QUEUED_BACKPRESSURE
                    }
                }
            }
        }
        synchronized(writerMonitor) { writerMonitor.notifyAll() }
        transition?.let(::completeTransition)
        return result
    }

    /** Retries only the queue head, preserving framing order and preventing replay gaps. */
    fun flush(): RemoteStreamOfferResult {
        var transition: Transition? = null
        val result = synchronized(lock) {
            val usable = ensureUsableLocked()
            if (usable != null) {
                transition = usable
                RemoteStreamOfferResult.FAILED_CLOSED
            } else if (state != RemoteStreamLifecycleState.ACTIVE) {
                if (state == RemoteStreamLifecycleState.FAILED) RemoteStreamOfferResult.FAILED_CLOSED else RemoteStreamOfferResult.DROPPED_NOT_ACTIVE
            } else if (queue.isEmpty()) {
                RemoteStreamOfferResult.QUEUED_AND_SENT
            } else {
                RemoteStreamOfferResult.QUEUED_BACKPRESSURE
            }
        }
        synchronized(writerMonitor) { writerMonitor.notifyAll() }
        transition?.let(::completeTransition)
        return result
    }

    /** The host must forward network/background/process ownership signals immediately. */
    fun onOwnerSignal(signal: RemoteStreamOwnerSignal) {
        val transition = synchronized(lock) {
            if (state != RemoteStreamLifecycleState.ACTIVE) null else {
                val reason = when (signal) {
                    RemoteStreamOwnerSignal.NETWORK_CHANGED -> RemoteStreamStopReason.NETWORK_CHANGED
                    RemoteStreamOwnerSignal.APP_BACKGROUNDED -> RemoteStreamStopReason.APP_BACKGROUNDED
                    RemoteStreamOwnerSignal.PROCESS_OWNER_STOPPED -> RemoteStreamStopReason.PROCESS_OWNER_STOPPED
                }
                stopLocked(RemoteStreamLifecycleState.AUTO_STOPPED, reason, nowOrLastLocked())
            }
        }
        synchronized(writerMonitor) { writerMonitor.notifyAll() }
        transition?.let(::completeTransition)
    }

    /** User-visible Stop action. Safe to invoke more than once. */
    fun stop() {
        val transition = synchronized(lock) {
            if (state == RemoteStreamLifecycleState.ACTIVE) {
                stopLocked(RemoteStreamLifecycleState.STOPPED, RemoteStreamStopReason.USER_STOPPED, nowOrLastLocked())
            } else null
        }
        synchronized(writerMonitor) { writerMonitor.notifyAll() }
        transition?.let(::completeTransition)
    }

    fun snapshot(): RemoteStreamSnapshot = synchronized(lock) {
        RemoteStreamSnapshot(
            state = state,
            destinationDisplayValue = pairing.destination.displayValue,
            receiverFingerprint = pairing.receiverIdentity.sha256Fingerprint,
            allowedDataCategories = configuration.allowedDataCategories.toSet(),
            startedAtMillis = startedAtMillis,
            stoppedAtMillis = stoppedAtMillis,
            stopReason = stopReason,
            failureReason = failureReason,
            acceptedPackets = acceptedPackets,
            acceptedBytes = acceptedBytes,
            transmittedPackets = transmittedPackets,
            backpressureEvents = backpressureEvents,
            droppedPackets = droppedPackets,
            queuedPackets = queue.size,
            queuedBytes = queuedBytes,
        )
    }

    /** Returns a terminal transition when the session must close immediately. */
    private fun ensureUsableLocked(): Transition? {
        if (state != RemoteStreamLifecycleState.ACTIVE) return null
        val now = safeNow() ?: return failLocked(RemoteStreamFailureReason.CLOCK_UNAVAILABLE)
        if (now <= 0L) return failLocked(RemoteStreamFailureReason.INVALID_CLOCK)
        if (now < lastObservedAtMillis || now < startedAtMillis) return failLocked(RemoteStreamFailureReason.CLOCK_ROLLBACK)
        lastObservedAtMillis = now
        if (now > sessionConsent.expiresAtMillis) return failLocked(RemoteStreamFailureReason.CONSENT_EXPIRED)
        if (now - startedAtMillis >= configuration.maximumDurationMillis) {
            return stopLocked(RemoteStreamLifecycleState.EXPIRED, RemoteStreamStopReason.DURATION_EXPIRED, now)
        }
        return null
    }

    /** The only method allowed to call transport.send, and only on the writer thread. */
    private fun writerLoop() {
        while (true) {
            var idleTransition: Transition? = null
            val head = synchronized(lock) {
                if (writerExit) return
                // Time-based limits must stop an idle session too; otherwise
                // expiry would depend on a later packet or explicit flush.
                idleTransition = ensureUsableLocked()
                if (idleTransition != null) null
                else if (state == RemoteStreamLifecycleState.ACTIVE && queue.isNotEmpty()) queue.first()
                else null
            }
            idleTransition?.let(::completeTransition)
            if (idleTransition != null) continue
            if (head == null) {
                synchronized(writerMonitor) { writerMonitor.wait(250L) }
                continue
            }
            val result = try {
                transport.send(head.frame)
            } catch (_: RuntimeException) {
                RemoteStreamTransportSendResult.TRANSPORT_FAILED
            }
            var transition: Transition? = null
            var sessionStopped = false
            synchronized(lock) {
                if (state != RemoteStreamLifecycleState.ACTIVE) {
                    sessionStopped = true
                } else {
                    when (result) {
                        RemoteStreamTransportSendResult.SENT -> {
                            if (queue.firstOrNull() === head) {
                                queue.removeFirst()
                                queuedBytes -= head.frame.size
                                head.frame.fill(0)
                                transmittedPackets += 1L
                            } else {
                                // A writer-owned head can never be replaced; fail closed if a host violates that invariant.
                                transition = failLocked(RemoteStreamFailureReason.HOST_FAILED)
                            }
                        }
                        RemoteStreamTransportSendResult.BACKPRESSURE -> {
                            backpressureEvents += 1L
                        }
                        RemoteStreamTransportSendResult.AUTHENTICATION_LOST -> {
                            transition = failLocked(RemoteStreamFailureReason.RECEIVER_AUTH_LOST)
                        }
                        RemoteStreamTransportSendResult.TRANSPORT_FAILED -> {
                            transition = failLocked(RemoteStreamFailureReason.TRANSPORT_FAILED)
                        }
                    }
                }
            }
            // stopLocked() wipes queued frames while this writer-owned frame
            // may still be in transport.send. Wipe the captured reference too.
            if (sessionStopped) head.frame.fill(0)
            transition?.let(::completeTransition)
            if (sessionStopped) continue
            if (result == RemoteStreamTransportSendResult.BACKPRESSURE) {
                synchronized(writerMonitor) { writerMonitor.wait(25L) }
            }
        }
    }

    private fun safeNow(): Long? = try { clock.nowMillis() } catch (_: RuntimeException) { null }

    private fun nowOrLastLocked(): Long = safeNow()?.takeIf { it >= lastObservedAtMillis } ?: lastObservedAtMillis

    private fun failLocked(reason: RemoteStreamFailureReason): Transition? {
        if (state != RemoteStreamLifecycleState.ACTIVE) return null
        failureReason = reason
        val stop = when (reason) {
            RemoteStreamFailureReason.CLOCK_UNAVAILABLE,
            RemoteStreamFailureReason.INVALID_CLOCK,
            RemoteStreamFailureReason.CLOCK_ROLLBACK -> RemoteStreamStopReason.CLOCK_FAILURE
            RemoteStreamFailureReason.CONSENT_EXPIRED -> RemoteStreamStopReason.CONSENT_EXPIRED
            RemoteStreamFailureReason.RECEIVER_AUTH_LOST -> RemoteStreamStopReason.RECEIVER_AUTH_LOST
            RemoteStreamFailureReason.TRANSPORT_FAILED -> RemoteStreamStopReason.TRANSPORT_FAILURE
            RemoteStreamFailureReason.HOST_FAILED,
            RemoteStreamFailureReason.FRAME_ENCRYPTION_FAILED -> RemoteStreamStopReason.HOST_FAILURE
        }
        return stopLocked(RemoteStreamLifecycleState.FAILED, stop, nowOrLastLocked())
    }

    private fun stopLocked(newState: RemoteStreamLifecycleState, reason: RemoteStreamStopReason, atMillis: Long): Transition? {
        if (state != RemoteStreamLifecycleState.ACTIVE) return null
        state = newState
        stopReason = reason
        stoppedAtMillis = atMillis.coerceAtLeast(startedAtMillis)
        while (queue.isNotEmpty()) queue.removeFirst().frame.fill(0)
        queuedBytes = 0
        encoder.destroy()
        writerExit = true
        transportClosed = true
        return Transition(snapshotLocked())
    }

    private fun completeTransition(transition: Transition) {
        runCatching { transport.close() }
        notifyLifecycle(transition.snapshot)
    }

    private fun snapshotLocked(): RemoteStreamSnapshot = RemoteStreamSnapshot(
        state = state,
        destinationDisplayValue = pairing.destination.displayValue,
        receiverFingerprint = pairing.receiverIdentity.sha256Fingerprint,
        allowedDataCategories = configuration.allowedDataCategories.toSet(),
        startedAtMillis = startedAtMillis,
        stoppedAtMillis = stoppedAtMillis,
        stopReason = stopReason,
        failureReason = failureReason,
        acceptedPackets = acceptedPackets,
        acceptedBytes = acceptedBytes,
        transmittedPackets = transmittedPackets,
        backpressureEvents = backpressureEvents,
        droppedPackets = droppedPackets,
        queuedPackets = queue.size,
        queuedBytes = queuedBytes,
    )

    private fun notifyLifecycle(snapshot: RemoteStreamSnapshot) {
        try {
            lifecycleConsumer.onLifecycle(snapshot)
        } catch (_: RuntimeException) {
            // UI observers cannot keep a sensitive stream alive or crash the session.
        }
    }
}

private const val MAX_FUTURE_RECORD_SKEW_MILLIS: Long = 60_000L
