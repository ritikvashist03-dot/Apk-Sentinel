package app.apksentinel.engine.tlsinspection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

class TlsInspectionSessionTest {
    @Test
    fun disabledDefaultCannotStartEvenWhenOtherInputsWouldBeValid() {
        val result = factory().start(
            request = request(configuration = TlsInspectionConfiguration()),
            decryptedSegmentConsumer = InMemoryTlsDecryptedSegmentConsumer { },
        )

        assertEquals(TlsInspectionStartRejection.DISABLED_BY_DEFAULT, (result as TlsInspectionStartResult.Rejected).reason)
    }

    @Test
    fun unknownCertificateInstallationFailsClosed() {
        val result = TlsInspectionSessionFactory(
            credentialProvider = FakeCredentialProvider(),
            installationVerifier = UnknownCertificateInstallationVerifier,
            clock = MutableClock(1_000L),
        ).start(
            request = request(enabledConfiguration()),
            decryptedSegmentConsumer = InMemoryTlsDecryptedSegmentConsumer { },
        )

        assertEquals(
            TlsInspectionStartRejection.CERTIFICATE_INSTALLATION_UNKNOWN,
            (result as TlsInspectionStartResult.Rejected).reason,
        )
    }

    @Test
    fun activeSessionUsesBoundedEphemeralBytesAndRecordsMetadataOnly() {
        var retainedView: ByteBuffer? = null
        val lifecycle = mutableListOf<TlsInspectionLifecycleState>()
        val started = factory(clock = MutableClock(1_000L)).start(
            request = request(enabledConfiguration(maximumSessionBytes = 4 * 1024, maximumBytesPerSegment = 4 * 1024)),
            decryptedSegmentConsumer = InMemoryTlsDecryptedSegmentConsumer { segment ->
                retainedView = segment.useReadOnlyBytes { bytes ->
                    assertTrue(bytes.isReadOnly)
                    assertEquals(4, bytes.remaining())
                    bytes
                }
            },
            lifecycleConsumer = TlsInspectionLifecycleConsumer { lifecycle += it.state },
        ) as TlsInspectionStartResult.Started
        val source = byteArrayOf(1, 2, 3, 4)

        assertEquals(
            TlsInspectionSegmentResult.DELIVERED,
            started.session.offerDecryptedHttpTls12Segment(
                packageName = "com.example.reader",
                metadata = metadata(4),
                plaintext = source,
            ),
        )
        assertEquals(1, source[0].toInt()) // The caller's data is never mutated.
        assertNotNull(retainedView)
        assertEquals(0, retainedView!!.get(0).toInt()) // The module copy was zeroized after the callback.

        val snapshot = started.session.snapshot()
        assertTrue(snapshot.mustShowProminentActiveIndicator)
        assertTrue(snapshot.mustShowStopControl)
        assertEquals(1L, snapshot.deliveredSegments)
        assertEquals(4L, snapshot.deliveredBytes)
        assertEquals(1, snapshot.metadataEvents.size)
        assertEquals("com.example.reader", snapshot.metadataEvents.single().packageName)
        assertEquals(listOf(TlsInspectionLifecycleState.ACTIVE), lifecycle)
    }

    @Test
    fun excludedPackageClockRollbackAndSessionLimitStopFurtherDelivery() {
        val clock = MutableClock(1_000L)
        val started = factory(clock = clock).start(
            request = request(enabledConfiguration(maximumSessionBytes = 4 * 1024, maximumBytesPerSegment = 4 * 1024)),
            decryptedSegmentConsumer = InMemoryTlsDecryptedSegmentConsumer { },
        ) as TlsInspectionStartResult.Started

        assertEquals(
            TlsInspectionSegmentResult.DROPPED_PACKAGE_NOT_ALLOWED,
            started.session.offerDecryptedHttpTls12Segment("com.example.other", metadata(4), byteArrayOf(1, 2, 3, 4)),
        )
        assertEquals(
            TlsInspectionSegmentResult.DELIVERED,
            started.session.offerDecryptedHttpTls12Segment("com.example.reader", metadata(4_096), ByteArray(4_096) { 7 }),
        )
        assertEquals(
            TlsInspectionSegmentResult.DROPPED_SESSION_LIMIT,
            started.session.offerDecryptedHttpTls12Segment("com.example.reader", metadata(1), byteArrayOf(1)),
        )
        assertEquals(TlsInspectionLifecycleState.LIMIT_REACHED, started.session.snapshot().state)

        val second = factory(clock = clock).start(
            request = request(enabledConfiguration()),
            decryptedSegmentConsumer = InMemoryTlsDecryptedSegmentConsumer { },
        ) as TlsInspectionStartResult.Started
        clock.value = 999L
        assertEquals(
            TlsInspectionSegmentResult.FAILED_CLOSED,
            second.session.offerDecryptedHttpTls12Segment("com.example.reader", metadata(1), byteArrayOf(1)),
        )
        assertEquals(TlsInspectionFailureReason.CLOCK_ROLLBACK, second.session.snapshot().failureReason)
    }

    private fun factory(clock: TlsInspectionClock = MutableClock(1_000L)): TlsInspectionSessionFactory =
        TlsInspectionSessionFactory(
            credentialProvider = FakeCredentialProvider(),
            installationVerifier = InstalledVerifier,
            clock = clock,
        )

    private fun request(configuration: TlsInspectionConfiguration) = TlsInspectionStartRequest(
        androidApiLevel = 36,
        configuration = configuration,
        selectedPackages = listOf(TlsInspectionPackageTarget("com.example.reader", TlsInspectionPackageCategory.GENERAL)),
        dataPlaneReadiness = TlsInspectionDataPlaneReadiness.REVIEWED_HTTP_TLS12_ONLY,
    )

    private fun enabledConfiguration(
        maximumSessionBytes: Int = 128 * 1_024,
        maximumBytesPerSegment: Int = 4 * 1_024,
    ) = TlsInspectionConfiguration(
        enabled = true,
        sessionConsent = TlsInspectionSessionConsent("session-v1", 1_000L),
        maximumSessionBytes = maximumSessionBytes,
        maximumBytesPerSegment = maximumBytesPerSegment,
    )

    private fun metadata(bytes: Int) = TlsInspectionMetadata(
        tlsProtocol = TlsInspectionProtocol.TLS_1_2,
        httpProtocol = TlsInspectionHttpProtocol.HTTP_2,
        plaintextByteCount = bytes,
    )
}

private object InstalledVerifier : CertificateInstallationVerifier {
    override fun verify(metadata: TlsCaCertificateMetadata): CertificateInstallationVerification =
        CertificateInstallationVerification(
            CertificateInstallationState.INSTALLED,
            CertificateInstallationVerificationReason.VERIFIED_BY_PUBLIC_OR_MANAGED_CAPABILITY,
        )
}

private class MutableClock(var value: Long) : TlsInspectionClock {
    override fun nowMillis(): Long = value
}
