package app.apksentinel.mobile

import androidx.annotation.StringRes
import app.apksentinel.networkmonitor.CapabilityAvailability
import app.apksentinel.networkmonitor.CapabilityReasonCode
import app.apksentinel.networkmonitor.EngineLimitationCode
import app.apksentinel.networkmonitor.FirewallEnforcementOutcome
import app.apksentinel.networkmonitor.FirewallEnforcementState
import app.apksentinel.networkmonitor.FirewallAction
import app.apksentinel.networkmonitor.MonitoringCapabilityId
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
import app.apksentinel.networkmonitor.TransportProtocol

/** The only app-side route from typed network engine outcomes to localized prose. */
internal object NetworkUiTextMapper {
    @StringRes fun capabilityName(value: MonitoringCapabilityId): Int = when (value) {
        MonitoringCapabilityId.VPN_USER_CONSENT -> R.string.network_capability_vpn_consent
        MonitoringCapabilityId.IPV4_TUNNEL -> R.string.network_capability_ipv4
        MonitoringCapabilityId.IPV6_TUNNEL -> R.string.network_capability_ipv6
        MonitoringCapabilityId.TRAFFIC_FORWARDING -> R.string.network_capability_forwarding
        MonitoringCapabilityId.APP_ATTRIBUTION -> R.string.network_capability_app_attribution
        MonitoringCapabilityId.FIREWALL_ENFORCEMENT -> R.string.network_capability_firewall
        MonitoringCapabilityId.DNS_METADATA -> R.string.network_capability_dns
        MonitoringCapabilityId.PACKET_PAYLOAD_COLLECTION -> R.string.network_capability_payload
        MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT -> R.string.network_capability_pcapng
        MonitoringCapabilityId.METADATA_CAPTURE_EXPORT -> R.string.network_capability_metadata_export
        MonitoringCapabilityId.TLS_DECRYPTION -> R.string.network_capability_tls
        MonitoringCapabilityId.ROOT_ESCALATION -> R.string.network_capability_root
        MonitoringCapabilityId.REMOTE_TRAFFIC_RELAY -> R.string.network_capability_remote_relay
    }

    @StringRes fun text(code: NetworkUiTextCode): Int = when (code) {
        NetworkUiTextCode.MONITOR_STOPPED -> R.string.network_contract_monitor_stopped
        NetworkUiTextCode.MONITOR_STARTING -> R.string.network_contract_monitor_starting
        NetworkUiTextCode.MONITOR_ACTIVE -> R.string.network_contract_monitor_active
        NetworkUiTextCode.MONITOR_STOPPING -> R.string.network_contract_monitor_stopping
        NetworkUiTextCode.MONITOR_CONSENT_REQUIRED -> R.string.network_contract_consent_required
        NetworkUiTextCode.MONITOR_CAPABILITY_UNAVAILABLE -> R.string.network_contract_capability_unavailable
        NetworkUiTextCode.MONITOR_REVOKED_BY_SYSTEM -> R.string.network_contract_revoked
        NetworkUiTextCode.MONITOR_FAILED -> R.string.network_contract_failed
        NetworkUiTextCode.SESSION_ALREADY_ACTIVE -> R.string.network_contract_session_already_active
        NetworkUiTextCode.INVALID_START_REQUEST -> R.string.network_contract_invalid_start
        NetworkUiTextCode.FOREGROUND_SERVICE_NOT_ALLOWED -> R.string.network_contract_foreground_not_allowed
        NetworkUiTextCode.TUNNEL_ESTABLISHMENT_FAILED -> R.string.network_contract_tunnel_failed
        NetworkUiTextCode.FORWARDER_START_FAILED -> R.string.network_contract_forwarder_start_failed
        NetworkUiTextCode.FORWARDER_STOPPED -> R.string.network_contract_forwarder_stopped
        NetworkUiTextCode.PACKET_MALFORMED -> R.string.network_contract_packet_malformed
        NetworkUiTextCode.PACKET_IGNORED -> R.string.network_contract_packet_ignored
        NetworkUiTextCode.FIREWALL_ALLOWED -> R.string.network_contract_firewall_allowed
        NetworkUiTextCode.FIREWALL_BLOCKED -> R.string.network_contract_firewall_blocked
        NetworkUiTextCode.FIREWALL_ENFORCEMENT_FAILED -> R.string.network_contract_firewall_failed
        NetworkUiTextCode.RAW_CAPTURE_STARTED -> R.string.network_contract_capture_started
        NetworkUiTextCode.RAW_CAPTURE_REJECTED -> R.string.network_contract_capture_rejected
        NetworkUiTextCode.RAW_CAPTURE_FAILED -> R.string.network_contract_capture_failed
    }

    @StringRes fun capabilityAvailability(value: CapabilityAvailability): Int = when (value) {
        CapabilityAvailability.AVAILABLE -> R.string.network_contract_available
        CapabilityAvailability.LIMITED -> R.string.network_contract_limited
        CapabilityAvailability.UNAVAILABLE -> R.string.network_contract_unavailable
        CapabilityAvailability.REQUIRES_USER_CONSENT -> R.string.network_contract_consent_required_short
    }

    @StringRes fun capabilityReason(value: CapabilityReasonCode): Int = when (value) {
        CapabilityReasonCode.VPN_CONSENT_GRANTED -> R.string.network_contract_vpn_consent_granted
        CapabilityReasonCode.VPN_CONSENT_REQUIRED -> R.string.network_contract_vpn_consent_required
        CapabilityReasonCode.IP_FAMILY_NOT_SELECTED -> R.string.network_contract_ip_not_selected
        CapabilityReasonCode.IP_FAMILY_UNAVAILABLE -> R.string.network_contract_ip_unavailable
        CapabilityReasonCode.IP_FAMILY_LIMITED_COVERAGE -> R.string.network_contract_ip_limited
        CapabilityReasonCode.IP_FAMILY_SUPPORTED -> R.string.network_contract_ip_supported
        CapabilityReasonCode.FORWARDING_SUPPORTED -> R.string.network_contract_forwarding_supported
        CapabilityReasonCode.FORWARDING_LIMITED_COVERAGE -> R.string.network_contract_forwarding_limited
        CapabilityReasonCode.FORWARDING_UNAVAILABLE -> R.string.network_contract_forwarding_unavailable
        CapabilityReasonCode.APP_ATTRIBUTION_LIMITED -> R.string.network_contract_attribution_limited
        CapabilityReasonCode.APP_ATTRIBUTION_AVAILABLE -> R.string.network_contract_attribution_available
        CapabilityReasonCode.APP_ATTRIBUTION_UNAVAILABLE -> R.string.network_contract_attribution_unavailable
        CapabilityReasonCode.FIREWALL_CONFIRMATION_REQUIRED -> R.string.network_contract_firewall_confirmation
        CapabilityReasonCode.FIREWALL_LIMITED_COVERAGE -> R.string.network_contract_firewall_limited
        CapabilityReasonCode.FIREWALL_MODE_NOT_SELECTED -> R.string.network_contract_firewall_mode_not_selected
        CapabilityReasonCode.FIREWALL_UNAVAILABLE -> R.string.network_contract_firewall_unavailable
        CapabilityReasonCode.DNS_METADATA_LIMITED -> R.string.network_contract_dns_limited
        CapabilityReasonCode.RAW_CAPTURE_LIMITED -> R.string.network_contract_capture_limited
        CapabilityReasonCode.RAW_CAPTURE_UNAVAILABLE -> R.string.network_contract_capture_unavailable
        CapabilityReasonCode.METADATA_EXPORT_LIMITED -> R.string.network_contract_metadata_export_limited
        CapabilityReasonCode.TLS_DECRYPTION_UNAVAILABLE -> R.string.network_contract_tls_unavailable
        CapabilityReasonCode.ROOT_UNAVAILABLE -> R.string.network_contract_root_unavailable
        CapabilityReasonCode.REMOTE_RELAY_UNAVAILABLE -> R.string.network_contract_remote_relay_unavailable
    }

    @StringRes fun limitation(value: EngineLimitationCode): Int = when (value) {
        EngineLimitationCode.FORWARDING_DATA_PLANE_NOT_INSTALLED,
        EngineLimitationCode.FORWARDING_DATA_PLANE_UNAVAILABLE_FOR_CONFIGURATION,
        EngineLimitationCode.FORWARDING_DATA_PLANE_DOES_NOT_SUPPORT_REQUESTED_IP_FAMILY -> R.string.network_contract_forwarding_unavailable
        EngineLimitationCode.FORWARDING_DATA_PLANE_LIMITED_PROTOCOL_COVERAGE -> R.string.network_contract_forwarding_limited
        EngineLimitationCode.FIREWALL_ENFORCEMENT_NOT_SUPPORTED_BY_DATA_PLANE -> R.string.network_contract_firewall_unavailable
        EngineLimitationCode.APP_ATTRIBUTION_NOT_AVAILABLE -> R.string.network_contract_attribution_unavailable
        EngineLimitationCode.DNS_NAMES_HASHED_BY_DEFAULT,
        EngineLimitationCode.ENCRYPTED_DNS_NOT_INTERPRETED -> R.string.network_contract_dns_limited
        EngineLimitationCode.PACKET_PAYLOADS_ARE_NOT_COLLECTED,
        EngineLimitationCode.PACKET_PAYLOADS_NOT_PARSED_OR_REVEALED,
        EngineLimitationCode.PCAPNG_RAW_PACKET_EXPORT_LIMITED,
        EngineLimitationCode.PCAPNG_RAW_PACKET_EXPORT_NOT_AVAILABLE -> R.string.network_contract_capture_limited
        EngineLimitationCode.METADATA_CAPTURE_EXPORT_IS_NOT_PACKET_CAPTURE -> R.string.network_contract_metadata_export_limited
        EngineLimitationCode.TLS_DECRYPTION_AND_MITM_NOT_IMPLEMENTED -> R.string.network_contract_tls_unavailable
        EngineLimitationCode.ROOT_ESCALATION_NOT_IMPLEMENTED -> R.string.network_contract_root_unavailable
        EngineLimitationCode.REMOTE_RELAY_NOT_IMPLEMENTED -> R.string.network_contract_remote_relay_unavailable
        EngineLimitationCode.ANOTHER_VPN_OR_SYSTEM_REVOKED_ACCESS -> R.string.network_contract_revoked
    }

    @StringRes fun parseFailure(value: PacketParseFailureCode): Int = when (value) {
        PacketParseFailureCode.MALFORMED_PACKET -> R.string.network_contract_packet_malformed
        PacketParseFailureCode.IGNORED_PACKET -> R.string.network_contract_packet_ignored
    }

    @StringRes fun captureStart(value: RawPcapngCaptureStartRejection): Int = when (value) {
        RawPcapngCaptureStartRejection.ALREADY_ACTIVE,
        RawPcapngCaptureStartRejection.CLOCK_UNAVAILABLE,
        RawPcapngCaptureStartRejection.INVALID_START_TIME,
        RawPcapngCaptureStartRejection.WRITER_START_FAILED -> R.string.network_contract_capture_rejected
    }

    @StringRes fun captureFailure(value: RawPcapngCaptureFailureReason): Int = when (value) {
        RawPcapngCaptureFailureReason.CLOCK_UNAVAILABLE,
        RawPcapngCaptureFailureReason.INVALID_CLOCK_TIME,
        RawPcapngCaptureFailureReason.OUTPUT_WRITE_FAILED,
        RawPcapngCaptureFailureReason.WRITER_INTERRUPTED,
        RawPcapngCaptureFailureReason.WRITER_RUNTIME_FAILURE,
        RawPcapngCaptureFailureReason.WRITER_START_FAILED -> R.string.network_contract_capture_failed
    }

    @StringRes fun firewallOutcome(value: FirewallEnforcementOutcome): Int = when (value) {
        FirewallEnforcementOutcome.ALLOWED -> R.string.network_contract_firewall_allowed
        FirewallEnforcementOutcome.BLOCKED -> R.string.network_contract_firewall_blocked
        FirewallEnforcementOutcome.FAILED -> R.string.network_contract_firewall_failed
    }

    @StringRes fun firewallAction(value: FirewallAction): Int = when (value) {
        FirewallAction.ALLOW -> R.string.network_contract_action_allow
        FirewallAction.BLOCK -> R.string.network_contract_action_block
    }

    @StringRes fun firewallState(value: FirewallEnforcementState): Int = when (value) {
        FirewallEnforcementState.NOT_APPLICABLE -> R.string.network_contract_state_not_applicable
        FirewallEnforcementState.PENDING_FORWARDER_CONFIRMATION -> R.string.network_contract_state_pending
        FirewallEnforcementState.NOT_ENFORCED_FORWARDER_CAPABILITY_MISSING -> R.string.network_contract_state_not_enforced
        FirewallEnforcementState.CONFIRMED_ALLOWED -> R.string.network_contract_state_allowed
        FirewallEnforcementState.CONFIRMED_BLOCKED -> R.string.network_contract_state_blocked
        FirewallEnforcementState.FORWARDER_FAILED -> R.string.network_contract_state_failed
    }

    @StringRes fun transport(value: TransportProtocol): Int = when (value) {
        TransportProtocol.TCP -> R.string.network_contract_transport_tcp
        TransportProtocol.UDP -> R.string.network_contract_transport_udp
        TransportProtocol.ICMPV4 -> R.string.network_contract_transport_icmpv4
        TransportProtocol.ICMPV6 -> R.string.network_contract_transport_icmpv6
        TransportProtocol.OTHER -> R.string.network_contract_transport_other
    }

    @StringRes fun payloadState(value: PayloadInspectionState): Int = when (value) {
        PayloadInspectionState.DISABLED -> R.string.payload_state_disabled
        PayloadInspectionState.RUNNING -> R.string.payload_state_running
        PayloadInspectionState.STOPPED -> R.string.payload_state_stopped
        PayloadInspectionState.EXPIRED -> R.string.payload_state_expired
        PayloadInspectionState.FAILED -> R.string.payload_state_failed
    }

    @StringRes fun payloadFailure(value: PayloadInspectionFailureReason): Int = when (value) {
        PayloadInspectionFailureReason.CLOCK_UNAVAILABLE -> R.string.payload_failure_clock_unavailable
        PayloadInspectionFailureReason.INVALID_CLOCK_TIME -> R.string.payload_failure_invalid_clock
        PayloadInspectionFailureReason.WORKER_START_FAILED -> R.string.payload_failure_worker_start
        PayloadInspectionFailureReason.WORKER_INTERRUPTED -> R.string.payload_failure_worker_interrupted
        PayloadInspectionFailureReason.WORKER_RUNTIME_FAILURE -> R.string.payload_failure_worker_runtime
    }

    @StringRes fun payloadDrop(value: PayloadInspectionDropReason): Int = when (value) {
        PayloadInspectionDropReason.NOT_PLAINTEXT_OR_ENCRYPTED -> R.string.payload_drop_encrypted
        PayloadInspectionDropReason.INGRESS_QUEUE_FULL -> R.string.payload_drop_queue_full
        PayloadInspectionDropReason.RECORD_LIMIT_REACHED -> R.string.payload_drop_record_limit
        PayloadInspectionDropReason.SESSION_BYTE_LIMIT_REACHED -> R.string.payload_drop_session_limit
        PayloadInspectionDropReason.FLOW_BYTE_LIMIT_REACHED -> R.string.payload_drop_flow_limit
        PayloadInspectionDropReason.DURATION_EXPIRED -> R.string.payload_drop_duration
        PayloadInspectionDropReason.RECORD_TRUNCATED -> R.string.payload_drop_truncated
    }

    @StringRes fun payloadLimitation(value: PayloadInspectionLimitation): Int = when (value) {
        PayloadInspectionLimitation.DISABLED_BY_SESSION -> R.string.payload_limitation_disabled
        PayloadInspectionLimitation.CONTENT_HIDDEN_UNTIL_REVEAL -> R.string.payload_limitation_hidden
        PayloadInspectionLimitation.NO_TLS_DECRYPTION -> R.string.payload_limitation_no_tls
        PayloadInspectionLimitation.NO_REASSEMBLY -> R.string.payload_limitation_no_reassembly
        PayloadInspectionLimitation.LIKELY_PLAINTEXT_ONLY -> R.string.payload_limitation_plaintext
        PayloadInspectionLimitation.REDACTION_BEST_EFFORT -> R.string.payload_limitation_redaction
        PayloadInspectionLimitation.NO_DISK_OR_EXPORT -> R.string.payload_limitation_memory_only
        PayloadInspectionLimitation.MALFORMED_UTF8_REDACTED -> R.string.payload_limitation_malformed_redacted
    }

    @StringRes fun payloadTransport(value: PayloadInspectionTransport): Int = when (value) {
        PayloadInspectionTransport.TCP -> R.string.payload_transport_tcp
        PayloadInspectionTransport.UDP -> R.string.payload_transport_udp
    }

    @StringRes fun payloadFormat(value: PayloadRenderFormat): Int = when (value) {
        PayloadRenderFormat.TEXT -> R.string.payload_format_text
        PayloadRenderFormat.HEX -> R.string.payload_format_hex
    }

    @StringRes fun protocolSource(value: ProtocolEvidenceSource): Int = when (value) {
        ProtocolEvidenceSource.TLS_CLIENT_HELLO_SNI -> R.string.protocol_evidence_source_sni
        ProtocolEvidenceSource.CLEARTEXT_HTTP_REQUEST -> R.string.protocol_evidence_source_http_request
        ProtocolEvidenceSource.CLEARTEXT_HTTP_RESPONSE -> R.string.protocol_evidence_source_http_response
    }

    @StringRes fun protocolConfidence(value: ProtocolEvidenceConfidence): Int = when (value) {
        ProtocolEvidenceConfidence.HIGH -> R.string.protocol_evidence_confidence_high
        ProtocolEvidenceConfidence.LIMITED -> R.string.protocol_evidence_confidence_limited
    }

    @StringRes fun protocolLimitation(value: ProtocolEvidenceLimitation): Int = when (value) {
        ProtocolEvidenceLimitation.DISABLED_BY_SESSION -> R.string.protocol_limitation_disabled
        ProtocolEvidenceLimitation.FRAGMENTED_OR_INCOMPLETE -> R.string.protocol_limitation_fragmented
        ProtocolEvidenceLimitation.OVERSIZED -> R.string.protocol_limitation_oversized
        ProtocolEvidenceLimitation.MALFORMED -> R.string.protocol_limitation_malformed
        ProtocolEvidenceLimitation.UNSAFE_OR_UNSUPPORTED_NAME -> R.string.protocol_limitation_unsafe_name
        ProtocolEvidenceLimitation.BODY_NOT_CAPTURED -> R.string.protocol_limitation_body
        ProtocolEvidenceLimitation.SENSITIVE_HEADERS_OMITTED -> R.string.protocol_limitation_sensitive_headers
        ProtocolEvidenceLimitation.OPAQUE_OR_UNSUPPORTED -> R.string.protocol_limitation_opaque
    }

    @StringRes fun reviewIndicator(value: NetworkReviewIndicatorCode): Int = when (value) {
        NetworkReviewIndicatorCode.UNKNOWN_ATTRIBUTION -> R.string.flow_review_unknown_attribution
        NetworkReviewIndicatorCode.REPEATED_BLOCKS -> R.string.flow_review_repeated_blocks
        NetworkReviewIndicatorCode.REVIEWED_HIGH_VOLUME -> R.string.flow_review_high_volume
        NetworkReviewIndicatorCode.MANY_DESTINATIONS -> R.string.flow_review_many_destinations
        NetworkReviewIndicatorCode.PARSER_LIMITATION -> R.string.flow_review_parser_limitation
    }
}
