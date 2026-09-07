package app.apksentinel.networkmonitor

/**
 * Locale-neutral, bounded presentation contract for network-monitor state.
 *
 * Engine implementations may retain diagnostic text for logs, but UI and
 * exports must render only this code and its explicitly typed fields. In
 * particular, exception messages, document-provider messages, and arbitrary
 * forwarder prose have no place in this contract.
 */
enum class NetworkUiTextCode {
    MONITOR_STOPPED,
    MONITOR_STARTING,
    MONITOR_ACTIVE,
    MONITOR_STOPPING,
    MONITOR_CONSENT_REQUIRED,
    MONITOR_CAPABILITY_UNAVAILABLE,
    MONITOR_REVOKED_BY_SYSTEM,
    MONITOR_FAILED,
    SESSION_ALREADY_ACTIVE,
    INVALID_START_REQUEST,
    FOREGROUND_SERVICE_NOT_ALLOWED,
    TUNNEL_ESTABLISHMENT_FAILED,
    FORWARDER_START_FAILED,
    FORWARDER_STOPPED,
    PACKET_MALFORMED,
    PACKET_IGNORED,
    FIREWALL_ALLOWED,
    FIREWALL_BLOCKED,
    FIREWALL_ENFORCEMENT_FAILED,
    RAW_CAPTURE_STARTED,
    RAW_CAPTURE_REJECTED,
    RAW_CAPTURE_FAILED,
}

/** All fields are bounded primitives or stable enums; no provider text is allowed. */
data class NetworkUiText(
    val code: NetworkUiTextCode,
    val count: Int? = null,
    val mtu: Int? = null,
) {
    init {
        require(count == null || count >= 0)
        require(mtu == null || mtu in 0..9_000)
    }

    companion object {
        fun forLifecycle(state: MonitorLifecycleState): NetworkUiText = NetworkUiText(
            when (state) {
                MonitorLifecycleState.STOPPED -> NetworkUiTextCode.MONITOR_STOPPED
                MonitorLifecycleState.STARTING -> NetworkUiTextCode.MONITOR_STARTING
                MonitorLifecycleState.ACTIVE -> NetworkUiTextCode.MONITOR_ACTIVE
                MonitorLifecycleState.STOPPING -> NetworkUiTextCode.MONITOR_STOPPING
                MonitorLifecycleState.CONSENT_REQUIRED -> NetworkUiTextCode.MONITOR_CONSENT_REQUIRED
                MonitorLifecycleState.CAPABILITY_UNAVAILABLE -> NetworkUiTextCode.MONITOR_CAPABILITY_UNAVAILABLE
                MonitorLifecycleState.REVOKED_BY_SYSTEM -> NetworkUiTextCode.MONITOR_REVOKED_BY_SYSTEM
                MonitorLifecycleState.FAILED -> NetworkUiTextCode.MONITOR_FAILED
            },
        )
    }
}

/** Stable reason for a capability state; renderers map this instead of [CapabilityReport.detail]. */
enum class CapabilityReasonCode {
    VPN_CONSENT_GRANTED,
    VPN_CONSENT_REQUIRED,
    IP_FAMILY_NOT_SELECTED,
    IP_FAMILY_UNAVAILABLE,
    IP_FAMILY_LIMITED_COVERAGE,
    IP_FAMILY_SUPPORTED,
    FORWARDING_SUPPORTED,
    FORWARDING_LIMITED_COVERAGE,
    FORWARDING_UNAVAILABLE,
    APP_ATTRIBUTION_LIMITED,
    APP_ATTRIBUTION_AVAILABLE,
    APP_ATTRIBUTION_UNAVAILABLE,
    FIREWALL_CONFIRMATION_REQUIRED,
    FIREWALL_LIMITED_COVERAGE,
    FIREWALL_MODE_NOT_SELECTED,
    FIREWALL_UNAVAILABLE,
    DNS_METADATA_LIMITED,
    RAW_CAPTURE_LIMITED,
    RAW_CAPTURE_UNAVAILABLE,
    METADATA_EXPORT_LIMITED,
    TLS_DECRYPTION_UNAVAILABLE,
    ROOT_UNAVAILABLE,
    REMOTE_RELAY_UNAVAILABLE,
}

enum class PacketParseFailureCode {
    MALFORMED_PACKET,
    IGNORED_PACKET,
}

/** Conservative fallback for old data planes that have not populated [CapabilityReport.reason]. */
fun CapabilityReport.presentationReason(): CapabilityReasonCode = when (capability) {
    MonitoringCapabilityId.VPN_USER_CONSENT -> if (availability == CapabilityAvailability.AVAILABLE) {
        CapabilityReasonCode.VPN_CONSENT_GRANTED
    } else {
        CapabilityReasonCode.VPN_CONSENT_REQUIRED
    }
    MonitoringCapabilityId.IPV4_TUNNEL,
    MonitoringCapabilityId.IPV6_TUNNEL -> when (availability) {
        CapabilityAvailability.AVAILABLE -> CapabilityReasonCode.IP_FAMILY_SUPPORTED
        CapabilityAvailability.LIMITED -> CapabilityReasonCode.IP_FAMILY_LIMITED_COVERAGE
        else -> CapabilityReasonCode.IP_FAMILY_UNAVAILABLE
    }
    MonitoringCapabilityId.TRAFFIC_FORWARDING -> when (availability) {
        CapabilityAvailability.AVAILABLE -> CapabilityReasonCode.FORWARDING_SUPPORTED
        CapabilityAvailability.LIMITED -> CapabilityReasonCode.FORWARDING_LIMITED_COVERAGE
        else -> CapabilityReasonCode.FORWARDING_UNAVAILABLE
    }
    MonitoringCapabilityId.APP_ATTRIBUTION -> when (availability) {
        CapabilityAvailability.AVAILABLE -> CapabilityReasonCode.APP_ATTRIBUTION_AVAILABLE
        CapabilityAvailability.LIMITED -> CapabilityReasonCode.APP_ATTRIBUTION_LIMITED
        else -> CapabilityReasonCode.APP_ATTRIBUTION_UNAVAILABLE
    }
    MonitoringCapabilityId.FIREWALL_ENFORCEMENT -> when (availability) {
        CapabilityAvailability.AVAILABLE -> CapabilityReasonCode.FIREWALL_CONFIRMATION_REQUIRED
        CapabilityAvailability.LIMITED -> CapabilityReasonCode.FIREWALL_LIMITED_COVERAGE
        else -> CapabilityReasonCode.FIREWALL_UNAVAILABLE
    }
    MonitoringCapabilityId.DNS_METADATA -> CapabilityReasonCode.DNS_METADATA_LIMITED
    MonitoringCapabilityId.PACKET_PAYLOAD_COLLECTION,
    MonitoringCapabilityId.PCAPNG_RAW_PACKET_EXPORT -> if (availability == CapabilityAvailability.LIMITED) {
        CapabilityReasonCode.RAW_CAPTURE_LIMITED
    } else {
        CapabilityReasonCode.RAW_CAPTURE_UNAVAILABLE
    }
    MonitoringCapabilityId.METADATA_CAPTURE_EXPORT -> CapabilityReasonCode.METADATA_EXPORT_LIMITED
    MonitoringCapabilityId.TLS_DECRYPTION -> CapabilityReasonCode.TLS_DECRYPTION_UNAVAILABLE
    MonitoringCapabilityId.ROOT_ESCALATION -> CapabilityReasonCode.ROOT_UNAVAILABLE
    MonitoringCapabilityId.REMOTE_TRAFFIC_RELAY -> CapabilityReasonCode.REMOTE_RELAY_UNAVAILABLE
}
