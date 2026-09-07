package app.apksentinel.mobile

import app.apksentinel.engine.rootcapture.RootCaptureCapabilityResult
import app.apksentinel.engine.rootcapture.RootCaptureSessionSnapshot
import app.apksentinel.engine.rootcapture.RootCaptureScope

/** Small pure guard used by the advanced screen and locked down with unit tests. */
internal object RootCaptureUiPolicy {
    fun canCheck(capabilityAcknowledged: Boolean, busy: Boolean): Boolean = capabilityAcknowledged && !busy

    fun canStart(
        capability: RootCaptureCapabilityResult?,
        startAcknowledged: Boolean,
        busy: Boolean,
        snapshot: RootCaptureSessionSnapshot?,
        requiredScope: RootCaptureScope = capability?.scope ?: RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
    ): Boolean = capability?.isUsable == true && capability.scope == requiredScope && startAcknowledged && !busy && snapshot?.active != true && snapshot?.finalizing != true

    fun canExport(snapshot: RootCaptureSessionSnapshot?, busy: Boolean): Boolean =
        snapshot?.exportable == true && !snapshot.active && !snapshot.finalizing && !busy
}
