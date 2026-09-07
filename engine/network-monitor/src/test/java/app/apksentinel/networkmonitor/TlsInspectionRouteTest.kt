package app.apksentinel.networkmonitor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsInspectionRouteTest {
    private val known = AppAttribution.Known("com.example.selected", uid = 10001)
    private val unknown = AppAttribution.Unknown(AttributionUnavailableReason.SHARED_UID_OR_AMBIGUOUS_OWNER)

    @Test
    fun sessionConfigurationRequiresExplicitConsentAndBoundedPackages() {
        val configuration = TlsInspectionSessionConfiguration(
            selectedPackages = setOf("com.example.selected"),
            sessionConsentVersion = "tls-session-v2",
            sessionConsentAcknowledgedAtMillis = 1L,
            sessionConsentNonce = "test-consent-nonce",
        )
        assertEquals(setOf("com.example.selected"), configuration.selectedPackages)
    }

    @Test
    fun enabledTunnelConfigurationRequiresAConsentNonce() {
        var rejected = false
        try {
            TlsInspectionTunnelConfiguration(
                enabled = true,
                selectedPackages = setOf("com.example.selected"),
                sessionConsentVersion = "tls-session-v2",
                sessionConsentAcknowledgedAtMillis = 1L,
            )
        } catch (_: IllegalArgumentException) {
            rejected = true
        }
        assertTrue(rejected)
    }

    @Test
    fun selectedKnownTcp443InterceptsButUnknownAndOtherPortBypass() {
        val session = fakeSession(setOf("com.example.selected"))
        assertTrue(session.openTcpFlow(known, 443) is TlsInspectionFlowDecision.Intercept)
        assertEquals(TlsInspectionFlowDecision.Bypass, session.openTcpFlow(unknown, 443))
        assertEquals(TlsInspectionFlowDecision.Bypass, session.openTcpFlow(known, 8443))
    }

    @Test
    fun selectedUdp443IsRejectedAsOpaqueQuic() {
        val session = fakeSession(setOf("com.example.selected"))
        assertTrue(session.rejectUdpFlow(known, 443))
        assertTrue(!session.rejectUdpFlow(unknown, 443))
    }

    private fun fakeSession(selected: Set<String>): TlsInspectionRouteSession = object : TlsInspectionRouteSession {
        override fun openTcpFlow(attribution: AppAttribution, remotePort: Int): TlsInspectionFlowDecision {
            val packageName = (attribution as? AppAttribution.Known)?.packageName ?: return TlsInspectionFlowDecision.Bypass
            if (remotePort != 443 || packageName !in selected) return TlsInspectionFlowDecision.Bypass
            return TlsInspectionFlowDecision.Intercept(object : TlsInspectionFlow {
                override fun onClientCiphertext(ciphertext: ByteArray) = TlsInspectionFlowResult()
                override fun onUpstreamCiphertext(ciphertext: ByteArray) = TlsInspectionFlowResult()
                override fun close() = Unit
            })
        }

        override fun rejectUdpFlow(attribution: AppAttribution, remotePort: Int): Boolean {
            val packageName = (attribution as? AppAttribution.Known)?.packageName ?: return false
            return remotePort == 443 && packageName in selected
        }

        override fun stop() = Unit
    }
}
