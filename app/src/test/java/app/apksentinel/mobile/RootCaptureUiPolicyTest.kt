package app.apksentinel.mobile

import app.apksentinel.engine.rootcapture.RootCaptureCapability
import app.apksentinel.engine.rootcapture.RootCaptureCapabilityResult
import app.apksentinel.engine.rootcapture.RootCaptureSessionSnapshot
import app.apksentinel.engine.rootcapture.RootCaptureScope
import app.apksentinel.engine.rootcapture.RootCaptureTerminalReason
import app.apksentinel.engine.rootcapture.RootCaptureOutputStatus
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RootCaptureUiPolicyTest {
    @Test fun capability_check_needs_its_fresh_acknowledgement() {
        assertFalse(RootCaptureUiPolicy.canCheck(capabilityAcknowledged = false, busy = false))
        assertFalse(RootCaptureUiPolicy.canCheck(capabilityAcknowledged = true, busy = true))
        assertTrue(RootCaptureUiPolicy.canCheck(capabilityAcknowledged = true, busy = false))
    }

    @Test fun start_needs_usable_result_distinct_acknowledgement_and_no_active_session() {
        val usable = RootCaptureCapabilityResult(RootCaptureCapability.USABLE)
        val active = RootCaptureSessionSnapshot("session", 1L, 60_000L, 2_000_000L, 2_000, active = true)
        assertFalse(RootCaptureUiPolicy.canStart(null, true, false, null))
        assertFalse(RootCaptureUiPolicy.canStart(usable, false, false, null))
        assertFalse(RootCaptureUiPolicy.canStart(usable, true, true, null))
        assertFalse(RootCaptureUiPolicy.canStart(usable, true, false, active))
        assertTrue(RootCaptureUiPolicy.canStart(usable, true, false, null))
    }

    @Test fun full_scope_requires_a_full_scope_capability_result() {
        val headersCapability = RootCaptureCapabilityResult(RootCaptureCapability.USABLE)
        assertFalse(
            RootCaptureUiPolicy.canStart(
                headersCapability,
                startAcknowledged = true,
                busy = false,
                snapshot = null,
                requiredScope = RootCaptureScope.FULL_PACKET_CAPTURE,
            ),
        )
    }

    @Test fun export_is_never_offered_for_an_active_session() {
        val active = RootCaptureSessionSnapshot("session", 1L, 60_000L, 2_000_000L, 2_000, active = true)
        val completed = active.copy(active = false, terminalReason = RootCaptureTerminalReason.USER_STOPPED, exportable = true)
        val finalizing = completed.copy(finalizing = true)
        assertFalse(RootCaptureUiPolicy.canExport(null, busy = false))
        assertFalse(RootCaptureUiPolicy.canExport(active, busy = false))
        assertFalse(RootCaptureUiPolicy.canExport(finalizing, busy = false))
        assertFalse(RootCaptureUiPolicy.canExport(completed, busy = true))
        assertTrue(RootCaptureUiPolicy.canExport(completed, busy = false))
        assertFalse(
            RootCaptureUiPolicy.canExport(
                completed.copy(outputStatus = RootCaptureOutputStatus.PARTIAL_OUTPUT_REJECTED, exportable = false),
                busy = false,
            ),
        )
    }
}
