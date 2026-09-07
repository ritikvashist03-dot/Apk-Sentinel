package app.apksentinel.mobile

import app.apksentinel.networkmonitor.CapabilityAvailability
import app.apksentinel.networkmonitor.CapabilityReasonCode
import app.apksentinel.networkmonitor.EngineLimitationCode
import app.apksentinel.networkmonitor.FirewallEnforcementOutcome
import app.apksentinel.networkmonitor.NetworkUiTextCode
import app.apksentinel.networkmonitor.PacketParseFailureCode
import app.apksentinel.networkmonitor.PayloadInspectionDropReason
import app.apksentinel.networkmonitor.PayloadInspectionFailureReason
import app.apksentinel.networkmonitor.PayloadInspectionLimitation
import app.apksentinel.networkmonitor.PayloadInspectionState
import app.apksentinel.networkmonitor.PayloadInspectionTransport
import app.apksentinel.networkmonitor.PayloadRenderFormat
import app.apksentinel.networkmonitor.NetworkReviewIndicatorCode
import app.apksentinel.networkmonitor.ProtocolEvidenceConfidence
import app.apksentinel.networkmonitor.ProtocolEvidenceLimitation
import app.apksentinel.networkmonitor.ProtocolEvidenceSource
import app.apksentinel.networkmonitor.RawPcapngCaptureFailureReason
import app.apksentinel.networkmonitor.RawPcapngCaptureStartRejection
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** Compile-time exhaustiveness is supplied by `when`; this catches zero/missing resource IDs. */
class NetworkUiTextMapperTest {
    @Test fun every_typed_network_outcome_has_a_resource_mapping() {
        NetworkUiTextCode.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.text(it)) }
        CapabilityAvailability.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.capabilityAvailability(it)) }
        CapabilityReasonCode.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.capabilityReason(it)) }
        EngineLimitationCode.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.limitation(it)) }
        PacketParseFailureCode.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.parseFailure(it)) }
        RawPcapngCaptureStartRejection.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.captureStart(it)) }
        RawPcapngCaptureFailureReason.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.captureFailure(it)) }
        FirewallEnforcementOutcome.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.firewallOutcome(it)) }
        PayloadInspectionState.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.payloadState(it)) }
        PayloadInspectionFailureReason.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.payloadFailure(it)) }
        PayloadInspectionDropReason.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.payloadDrop(it)) }
        PayloadInspectionLimitation.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.payloadLimitation(it)) }
        PayloadInspectionTransport.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.payloadTransport(it)) }
        PayloadRenderFormat.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.payloadFormat(it)) }
        ProtocolEvidenceSource.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.protocolSource(it)) }
        ProtocolEvidenceConfidence.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.protocolConfidence(it)) }
        ProtocolEvidenceLimitation.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.protocolLimitation(it)) }
        NetworkReviewIndicatorCode.entries.forEach { assertNotEquals(0, NetworkUiTextMapper.reviewIndicator(it)) }
    }
}
