package app.apksentinel.engine.remotestream

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import kotlin.system.measureTimeMillis

class RemoteStreamSessionTest {
    @Test
    fun literalDestinationRejectsDnsNamesLoopbackAndInvalidPorts() {
        assertEquals(
            RemoteStreamDestinationRejection.NOT_A_LITERAL_IP,
            (RemoteStreamDestination.parse("receiver.example", 443) as RemoteStreamDestinationResult.Rejected).reason,
        )
        assertEquals(
            RemoteStreamDestinationRejection.UNSPECIFIED_OR_LOOPBACK,
            (RemoteStreamDestination.parse("127.0.0.1", 443) as RemoteStreamDestinationResult.Rejected).reason,
        )
        assertEquals(
            RemoteStreamDestinationRejection.INVALID_PORT,
            (RemoteStreamDestination.parse("192.168.1.9", 0) as RemoteStreamDestinationResult.Rejected).reason,
        )
        assertTrue(RemoteStreamDestination.parse("192.168.1.9", 443) is RemoteStreamDestinationResult.Accepted)
        val ipv6 = RemoteStreamDestination.parse("2001:db8::10", 443) as RemoteStreamDestinationResult.Accepted
        assertEquals(16, ipv6.destination.addressBytes().size)
        assertTrue(RemoteStreamDestination.parse("::ffff:192.0.2.10", 443) is RemoteStreamDestinationResult.Accepted)
    }

    @Test
    fun receiverIdentityChecksP256EncodingAndFingerprint() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val encoded = Base64.getEncoder().encodeToString(pair.public.encoded)
        val fingerprint = sha256(pair.public.encoded)

        assertTrue(RemoteReceiverIdentity.fromP256X509("receiver-1", encoded, fingerprint) is RemoteReceiverIdentityResult.Accepted)
        assertEquals(
            RemoteReceiverIdentityRejection.FINGERPRINT_MISMATCH,
            (RemoteReceiverIdentity.fromP256X509("receiver-1", encoded, "0".repeat(64)) as RemoteReceiverIdentityResult.Rejected).reason,
        )
    }

    @Test
    fun defaultDisabledAndExpiredConsentCannotOpenTransport() {
        val host = FakeHost()
        val clock = MutableClock(10_000L)
        val disabled = factory(host, clock).start(request(RemoteStreamConfiguration()))
        assertEquals(RemoteStreamStartRejection.DISABLED_BY_DEFAULT, (disabled as RemoteStreamStartResult.Rejected).reason)
        assertEquals(0, host.openCalls)

        val config = enabledConfiguration()
        val expired = factory(host, clock).start(request(config, sessionExpiresAt = 9_999L))
        assertEquals(RemoteStreamStartRejection.SESSION_CONSENT_NOT_FRESH, (expired as RemoteStreamStartResult.Rejected).reason)
        assertEquals(0, host.openCalls)
    }

    @Test
    fun identityMismatchFailsClosedAndDestroysEphemeralKey() {
        val transport = FakeTransport(RemoteStreamTransportSendResult.SENT)
        val host = FakeHost(transport = transport, wrongFingerprint = true)
        val result = factory(host, MutableClock(10_000L)).start(request(enabledConfiguration()))

        assertEquals(RemoteStreamStartRejection.TRANSPORT_SECURITY_PROOF_INVALID, (result as RemoteStreamStartResult.Rejected).reason)
        assertTrue(transport.closed)
        assertTrue(host.lastKey!!.destroyed)
    }

    @Test
    fun sensitiveCategoryNeedsSeparateFreshAuthorization() {
        val config = enabledConfiguration(categories = setOf(RemoteStreamDataCategory.DECRYPTED_PAYLOAD))
        val host = FakeHost()
        val rejected = factory(host, MutableClock(10_000L)).start(request(config))
        assertEquals(RemoteStreamStartRejection.SENSITIVE_PAYLOAD_NOT_AUTHORIZED, (rejected as RemoteStreamStartResult.Rejected).reason)
        assertEquals(0, host.openCalls)
    }

    @Test
    fun receiverVerifierRejectsReplayAndOutOfOrderThenZeroizesCallbackBuffer() {
        val key = ByteArray(AES_256_KEY_BYTES) { (it + 1).toByte() }
        val encoder = RemoteStreamFrameEncoder(key)
        val first = encoder.encode(RemoteStreamRecord(RemoteStreamDataCategory.METADATA, 10_000L, byteArrayOf(3, 4)), 1L, 100)!!
        val second = encoder.encode(RemoteStreamRecord(RemoteStreamDataCategory.METADATA, 10_001L, byteArrayOf(5)), 2L, 100)!!
        val verifier = RemoteStreamReceiverFrameVerifier(key, 100)
        var retained: ByteBuffer? = null

        assertTrue(verifier.verifyAndConsume(first.frame) { received ->
            retained = received.useReadOnlyBytes { it }
        } is RemoteStreamFrameVerificationResult.Accepted)
        assertNotNull(retained)
        assertEquals(0, retained!!.get(0).toInt())
        assertEquals(
            RemoteStreamFrameRejection.REPLAYED,
            (verifier.verifyAndConsume(first.frame) { } as RemoteStreamFrameVerificationResult.Rejected).reason,
        )
        val freshVerifier = RemoteStreamReceiverFrameVerifier(key, 100)
        assertEquals(
            RemoteStreamFrameRejection.OUT_OF_ORDER,
            (freshVerifier.verifyAndConsume(second.frame) { } as RemoteStreamFrameVerificationResult.Rejected).reason,
        )
        first.frame.fill(0)
        second.frame.fill(0)
        verifier.close()
        freshVerifier.close()
        encoder.destroy()
        key.fill(0)
    }

    @Test
    fun boundedQueueBackpressureAndOwnerCancellationWipeEncryptedFrame() {
        val transport = FakeTransport(RemoteStreamTransportSendResult.BACKPRESSURE)
        val config = enabledConfiguration(maximumQueueRecords = 1, maximumQueueBytes = 4 * 1_024).copy(
            maximumRecordBytes = 4 * 1_024,
        )
        val started = factory(FakeHost(transport = transport), MutableClock(10_000L)).start(request(config)) as RemoteStreamStartResult.Started

        assertEquals(RemoteStreamOfferResult.QUEUED_AND_SENT, started.session.offer(record()))
        await { transport.lastFrame != null }
        val queuedReference = transport.lastFrame
        assertNotNull(queuedReference)
        assertEquals(RemoteStreamOfferResult.DROPPED_BACKPRESSURE, started.session.offer(record(bytes = byteArrayOf(8))))
        assertEquals(1L, started.session.snapshot().droppedPackets)
        started.session.onOwnerSignal(RemoteStreamOwnerSignal.APP_BACKGROUNDED)
        assertTrue(queuedReference!!.all { it == 0.toByte() })
        assertEquals(RemoteStreamLifecycleState.AUTO_STOPPED, started.session.snapshot().state)
        assertTrue(transport.closed)
    }

    @Test
    fun authLossClockRollbackAndLimitAutomaticallyStop() {
        val authLoss = factory(FakeHost(transport = FakeTransport(RemoteStreamTransportSendResult.AUTHENTICATION_LOST)), MutableClock(10_000L))
            .start(request(enabledConfiguration())) as RemoteStreamStartResult.Started
        assertEquals(RemoteStreamOfferResult.QUEUED_AND_SENT, authLoss.session.offer(record()))
        await { authLoss.session.snapshot().state == RemoteStreamLifecycleState.FAILED }
        assertEquals(RemoteStreamFailureReason.RECEIVER_AUTH_LOST, authLoss.session.snapshot().failureReason)

        val clock = MutableClock(10_000L)
        val rollback = factory(FakeHost(), clock).start(request(enabledConfiguration())) as RemoteStreamStartResult.Started
        clock.value = 9_999L
        assertEquals(RemoteStreamOfferResult.FAILED_CLOSED, rollback.session.offer(record(observedAt = 9_999L)))
        assertEquals(RemoteStreamFailureReason.CLOCK_ROLLBACK, rollback.session.snapshot().failureReason)

        val limited = factory(FakeHost(), MutableClock(10_000L)).start(
            request(enabledConfiguration(maximumPackets = 1, maximumBytes = 4_096L)),
        ) as RemoteStreamStartResult.Started
        assertEquals(RemoteStreamOfferResult.QUEUED_AND_SENT, limited.session.offer(record()))
        assertEquals(RemoteStreamOfferResult.DROPPED_LIMIT, limited.session.offer(record(bytes = byteArrayOf(9))))
        assertEquals(RemoteStreamLifecycleState.LIMIT_REACHED, limited.session.snapshot().state)
    }

    @Test
    fun boundedIngressDoesNotWaitForSlowWriter() {
        val transport = SlowTransport()
        val started = factory(FakeHost(transport = transport), MutableClock(10_000L)).start(request(enabledConfiguration()))
            as RemoteStreamStartResult.Started
        val elapsed = measureTimeMillis {
            assertEquals(RemoteStreamOfferResult.QUEUED_AND_SENT, started.session.offer(record()))
        }
        assertTrue("Ingress performed transport I/O", elapsed < 250L)
        assertTrue(transport.entered.await(1, java.util.concurrent.TimeUnit.SECONDS))
        started.session.stop()
        transport.release.countDown()
    }

    private fun factory(host: FakeHost, clock: MutableClock): RemoteStreamSessionFactory = RemoteStreamSessionFactory(host, clock)

    private fun request(
        configuration: RemoteStreamConfiguration,
        sessionExpiresAt: Long = 20_000L,
    ): RemoteStreamStartRequest {
        val destination = (RemoteStreamDestination.parse("192.168.1.7", 443) as RemoteStreamDestinationResult.Accepted).destination
        val identity = identity()
        val pairing = RemoteStreamPairing(
            destination = destination,
            receiverIdentity = identity,
            consent = RemoteStreamPairingConsent(
                disclosureVersion = "pairing-v1",
                acknowledgedAtMillis = 9_999L,
                expiresAtMillis = 20_000L,
                destinationDisplayValue = destination.displayValue,
                receiverFingerprint = identity.sha256Fingerprint,
            ),
        )
        return RemoteStreamStartRequest(
            configuration = configuration,
            pairing = pairing,
            sessionConsent = RemoteStreamSessionConsent(
                disclosureVersion = "stream-v1",
                acknowledgedAtMillis = minOf(9_999L, sessionExpiresAt - 1L),
                expiresAtMillis = sessionExpiresAt,
                destinationDisplayValue = destination.displayValue,
                receiverFingerprint = identity.sha256Fingerprint,
                dataCategories = configuration.allowedDataCategories,
                maximumPackets = configuration.maximumPackets,
                maximumBytes = configuration.maximumBytes,
                maximumDurationMillis = configuration.maximumDurationMillis,
                maximumQueueBytes = configuration.maximumQueueBytes,
                maximumQueueRecords = configuration.maximumQueueRecords,
            ),
        )
    }

    private fun enabledConfiguration(
        categories: Set<RemoteStreamDataCategory> = RemoteStreamConfiguration.DEFAULT_DATA_CATEGORIES,
        maximumPackets: Int = 2_000,
        maximumBytes: Long = 8L * 1_024L * 1_024L,
        maximumQueueRecords: Int = 32,
        maximumQueueBytes: Int = 256 * 1_024,
    ) = RemoteStreamConfiguration(
        enabled = true,
        allowedDataCategories = categories,
        maximumPackets = maximumPackets,
        maximumBytes = maximumBytes,
        maximumQueueRecords = maximumQueueRecords,
        maximumQueueBytes = maximumQueueBytes,
    )

    private fun record(observedAt: Long = 10_000L, bytes: ByteArray = byteArrayOf(1, 2, 3, 4)) =
        RemoteStreamRecord(RemoteStreamDataCategory.METADATA, observedAt, bytes)

    private fun identity(): RemoteReceiverIdentity {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return (RemoteReceiverIdentity.fromP256X509(
            keyId = "receiver-1",
            base64X509PublicKey = Base64.getEncoder().encodeToString(pair.public.encoded),
            expectedSha256Fingerprint = sha256(pair.public.encoded),
        ) as RemoteReceiverIdentityResult.Accepted).identity
    }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }

    private fun await(condition: () -> Boolean) {
        repeat(100) {
            if (condition()) return
            Thread.sleep(5L)
        }
        assertTrue("condition did not become true", condition())
    }
}

private class MutableClock(var value: Long) : RemoteStreamClock { override fun nowMillis(): Long = value }

private class FakeHost(
    private val transport: RemoteStreamAuthenticatedTransport = FakeTransport(RemoteStreamTransportSendResult.SENT),
    private val wrongFingerprint: Boolean = false,
) : RemoteStreamSecureHost {
    var openCalls = 0
    var lastKey: FakeSessionKey? = null

    override fun openPinnedMutualTransport(request: RemoteStreamTransportOpenRequest): RemoteStreamTransportOpenResult {
        openCalls += 1
        return RemoteStreamTransportOpenResult.Opened(
            transport = transport,
            proof = RemoteStreamTransportProof(
                tlsVersion = RemoteStreamTlsVersion.TLS_1_3,
                destinationDisplayValue = request.destination.displayValue,
                observedReceiverFingerprint = if (wrongFingerprint) "0".repeat(64) else request.expectedReceiverFingerprint,
                mutualAuthenticationConfirmed = true,
                echoedSessionNonce = request.sessionNonce.copyOf(),
            ),
            sessionKey = FakeSessionKey(),
        ).also { lastKey = it.sessionKey as FakeSessionKey }
    }
}

private class FakeSessionKey : RemoteStreamEphemeralSessionKey {
    private var bytes = ByteArray(AES_256_KEY_BYTES) { (it + 9).toByte() }
    var destroyed = false
        private set

    override fun copyForImmediateUse(): ByteArray? = if (destroyed) null else bytes.copyOf()

    override fun destroy() {
        bytes.fill(0)
        destroyed = true
    }
}

private class FakeTransport(var nextResult: RemoteStreamTransportSendResult) : RemoteStreamAuthenticatedTransport {
    var closed = false
    var lastFrame: ByteArray? = null

    override fun send(frame: ByteArray): RemoteStreamTransportSendResult {
        lastFrame = frame
        return nextResult
    }

    override fun close() { closed = true }
}

private class SlowTransport : RemoteStreamAuthenticatedTransport {
    val entered = CountDownLatch(1)
    val release = CountDownLatch(1)

    override fun send(frame: ByteArray): RemoteStreamTransportSendResult {
        entered.countDown()
        release.await()
        return RemoteStreamTransportSendResult.SENT
    }

    override fun close() = Unit
}
