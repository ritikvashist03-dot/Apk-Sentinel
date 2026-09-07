package app.apksentinel.networkmonitor

import java.util.UUID

/**
 * The requested behavior for a session. A session is never promoted to
 * [MonitorLifecycleState.ACTIVE] unless the installed data plane confirms that
 * it can forward traffic for the selected IP families.
 */
enum class MonitoringMode {
    METADATA_ONLY,
    FIREWALL_ENFORCEMENT,
}

enum class MonitorLifecycleState {
    STOPPED,
    STARTING,
    ACTIVE,
    STOPPING,
    CONSENT_REQUIRED,
    CAPABILITY_UNAVAILABLE,
    REVOKED_BY_SYSTEM,
    FAILED,
}

/** Start-time collection options cannot be edited once a session attempt owns them. */
fun isSessionConfigurationLocked(state: MonitorLifecycleState): Boolean = state in setOf(
    MonitorLifecycleState.STARTING,
    MonitorLifecycleState.ACTIVE,
    MonitorLifecycleState.STOPPING,
)

enum class MonitoringCapabilityId {
    VPN_USER_CONSENT,
    IPV4_TUNNEL,
    IPV6_TUNNEL,
    TRAFFIC_FORWARDING,
    APP_ATTRIBUTION,
    FIREWALL_ENFORCEMENT,
    DNS_METADATA,
    PACKET_PAYLOAD_COLLECTION,
    PCAPNG_RAW_PACKET_EXPORT,
    METADATA_CAPTURE_EXPORT,
    TLS_DECRYPTION,
    ROOT_ESCALATION,
    REMOTE_TRAFFIC_RELAY,
}

enum class CapabilityAvailability {
    AVAILABLE,
    LIMITED,
    UNAVAILABLE,
    REQUIRES_USER_CONSENT,
}

data class CapabilityReport(
    val capability: MonitoringCapabilityId,
    val availability: CapabilityAvailability,
    /** Diagnostic-only legacy text. Never render or export this field. */
    val detail: String,
    val reason: CapabilityReasonCode = CapabilityReasonCode.FORWARDING_UNAVAILABLE,
)

data class CapabilitySnapshot(
    val reports: List<CapabilityReport>,
) {
    fun reportFor(capability: MonitoringCapabilityId): CapabilityReport? =
        reports.firstOrNull { it.capability == capability }
}

/** Codes are safe to persist and export; details stay deliberately plain-language. */
enum class EngineLimitationCode {
    FORWARDING_DATA_PLANE_NOT_INSTALLED,
    FORWARDING_DATA_PLANE_UNAVAILABLE_FOR_CONFIGURATION,
    FORWARDING_DATA_PLANE_LIMITED_PROTOCOL_COVERAGE,
    FORWARDING_DATA_PLANE_DOES_NOT_SUPPORT_REQUESTED_IP_FAMILY,
    FIREWALL_ENFORCEMENT_NOT_SUPPORTED_BY_DATA_PLANE,
    APP_ATTRIBUTION_NOT_AVAILABLE,
    DNS_NAMES_HASHED_BY_DEFAULT,
    ENCRYPTED_DNS_NOT_INTERPRETED,
    PACKET_PAYLOADS_ARE_NOT_COLLECTED,
    /** Raw packet bytes are optional evidence only; they are never parsed or presented by this module. */
    PACKET_PAYLOADS_NOT_PARSED_OR_REVEALED,
    /** Explicit local raw-IP capture exists but is deliberately bounded and incomplete. */
    PCAPNG_RAW_PACKET_EXPORT_LIMITED,
    PCAPNG_RAW_PACKET_EXPORT_NOT_AVAILABLE,
    METADATA_CAPTURE_EXPORT_IS_NOT_PACKET_CAPTURE,
    TLS_DECRYPTION_AND_MITM_NOT_IMPLEMENTED,
    ROOT_ESCALATION_NOT_IMPLEMENTED,
    REMOTE_RELAY_NOT_IMPLEMENTED,
    ANOTHER_VPN_OR_SYSTEM_REVOKED_ACCESS,
}

data class EngineLimitation(
    val code: EngineLimitationCode,
    /** Diagnostic-only legacy text. Never render or export this field. */
    val detail: String,
)

private const val MAX_CONFIGURED_APP_PACKAGES = 250
private val ANDROID_PACKAGE_NAME = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")

sealed interface VpnAppSelection {
    /** All apps use the local VPN except the listed apps and this app itself. */
    data class AllAppsExcept(
        val packageNames: Set<String> = emptySet(),
    ) : VpnAppSelection {
        init {
            validatePackageNames(packageNames)
        }
    }

    /** Only these apps use the local VPN; the monitor's own package is removed later. */
    data class OnlyApps(
        val packageNames: Set<String>,
    ) : VpnAppSelection {
        init {
            require(packageNames.isNotEmpty()) { "At least one app must be selected." }
            validatePackageNames(packageNames)
        }
    }
}

data class TunnelConfiguration(
    val sessionName: String = "APK Sentinel local monitoring",
    val mode: MonitoringMode = MonitoringMode.METADATA_ONLY,
    val enableIpv4: Boolean = true,
    val enableIpv6: Boolean = true,
    val appSelection: VpnAppSelection = VpnAppSelection.AllAppsExcept(),
    val mtu: Int = 1_500,
    /** Disabled by default; this does not enable TLS decryption or payload retention. */
    val protocolEvidence: ProtocolEvidenceConfiguration = ProtocolEvidenceConfiguration(),
    /** Disabled by default and separately consented; it never decrypts TLS or persists content. */
    val payloadInspection: PayloadInspectionConfiguration = PayloadInspectionConfiguration(),
    val tlsInspection: TlsInspectionTunnelConfiguration = TlsInspectionTunnelConfiguration(),
) {
    init {
        require(sessionName.isNotBlank() && sessionName.length <= 64) {
            "Session name must be between 1 and 64 characters."
        }
        require(enableIpv4 || enableIpv6) { "At least one IP family must be enabled." }
        require(mtu in 576..9_000) { "MTU must be between 576 and 9000." }
    }
}

/** Intent-safe TLS request metadata; private keys and trust managers stay process-local. */
data class TlsInspectionTunnelConfiguration(
    val enabled: Boolean = false,
    val selectedPackages: Set<String> = emptySet(),
    val sessionConsentVersion: String? = null,
    val sessionConsentAcknowledgedAtMillis: Long? = null,
    val sessionConsentNonce: String? = null,
    val maximumSessionBytes: Int = 128 * 1_024,
    val maximumBytesPerFlow: Int = 64 * 1_024,
    val maximumDurationMillis: Long = 5 * 60 * 1_000L,
) {
    init {
        require(!enabled || selectedPackages.isNotEmpty())
        require(selectedPackages.size <= 25)
        require(!enabled || (
            sessionConsentVersion != null &&
                sessionConsentAcknowledgedAtMillis != null &&
                !sessionConsentNonce.isNullOrBlank()
            ))
    }

    fun sessionConfigurationOrNull(): TlsInspectionSessionConfiguration? = if (!enabled) null else {
        TlsInspectionSessionConfiguration(
            selectedPackages = selectedPackages,
            sessionConsentVersion = requireNotNull(sessionConsentVersion),
            sessionConsentAcknowledgedAtMillis = requireNotNull(sessionConsentAcknowledgedAtMillis),
            sessionConsentNonce = requireNotNull(sessionConsentNonce),
            maximumSessionBytes = maximumSessionBytes,
            maximumBytesPerFlow = maximumBytesPerFlow,
            maximumDurationMillis = maximumDurationMillis,
        )
    }
}

/**
 * A UI records this only after its separate, prominent disclosure is accepted.
 * Android's authoritative VPN consent is still checked immediately before start.
 */
data class VpnDisclosureAcknowledgement(
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
    /** A fresh opaque token makes one acknowledgement usable for one start attempt only. */
    val nonce: String = UUID.randomUUID().toString(),
) {
    init {
        require(disclosureVersion.isNotBlank()) { "A disclosure version is required." }
        require(acknowledgedAtMillis > 0L) { "Acknowledgement time must be positive." }
        require(nonce.isNotBlank()) { "Acknowledgement nonce is required." }
    }
}

/** Service-boundary validation for the prominent VPN disclosure acknowledgement. */
object VpnDisclosurePolicy {
    const val CURRENT_VERSION: String = "vpn-local-metadata-v1"
    const val MAX_AGE_MILLIS: Long = 5 * 60 * 1_000L
    private const val MAX_FUTURE_SKEW_MILLIS: Long = 30_000L

    fun isFreshAndExact(
        acknowledgement: VpnDisclosureAcknowledgement,
        nowMillis: Long,
    ): Boolean {
        val age = nowMillis - acknowledgement.acknowledgedAtMillis
        return acknowledgement.disclosureVersion == CURRENT_VERSION &&
            acknowledgement.nonce.isNotBlank() &&
            age in -MAX_FUTURE_SKEW_MILLIS..MAX_AGE_MILLIS
    }
}

/** Process-wide one-time gate; duplicate intents cannot reuse one disclosure token. */
object VpnDisclosureAcknowledgementGate {
    private const val MAX_RETAINED_TOKENS = 128
    private val lock = Any()
    private val consumed = LinkedHashSet<String>()

    fun consume(
        acknowledgement: VpnDisclosureAcknowledgement,
        nowMillis: Long,
    ): Boolean = synchronized(lock) {
        if (!VpnDisclosurePolicy.isFreshAndExact(acknowledgement, nowMillis)) return false
        val key = "${acknowledgement.disclosureVersion}:${acknowledgement.acknowledgedAtMillis}:${acknowledgement.nonce}"
        if (!consumed.add(key)) return false
        while (consumed.size > MAX_RETAINED_TOKENS) consumed.remove(consumed.first())
        true
    }

    internal fun resetForTests() = synchronized(lock) { consumed.clear() }
}

data class NetworkMonitorStartRequest(
    val tunnel: TunnelConfiguration,
    val disclosureAcknowledgement: VpnDisclosureAcknowledgement,
    /** Optional opaque app-owned remote-stream attachment; never a destination or credential. */
    val remoteStreamAttachmentToken: String? = null,
)

enum class PacketDirection {
    OUTBOUND,
    INBOUND,
    UNKNOWN,
}

enum class IpVersion {
    IPV4,
    IPV6,
}

enum class TransportProtocol {
    TCP,
    UDP,
    ICMPV4,
    ICMPV6,
    OTHER,
}

enum class AttributionConfidence {
    HIGH,
    MEDIUM,
    LOW,
    UNKNOWN,
}

enum class AttributionUnavailableReason {
    DATA_PLANE_DID_NOT_PROVIDE_UID,
    SHARED_UID_OR_AMBIGUOUS_OWNER,
    CONNECTION_OWNER_NOT_FOUND,
    PLATFORM_MAPPING_UNAVAILABLE,
    UNSUPPORTED_PROTOCOL,
    NOT_ATTEMPTED,
}

sealed interface AppAttribution {
    data class Known(
        val packageName: String,
        val uid: Int? = null,
        val confidence: AttributionConfidence = AttributionConfidence.MEDIUM,
    ) : AppAttribution {
        init {
            require(ANDROID_PACKAGE_NAME.matches(packageName)) { "Invalid Android package name." }
        }
    }

    data class Unknown(
        val reason: AttributionUnavailableReason,
    ) : AppAttribution
}

data class NetworkEndpoint(
    val address: String,
    val port: Int? = null,
) {
    init {
        require(address.isNotBlank()) { "IP address must not be blank." }
        require(port == null || port in 0..65_535) { "Port must be in 0..65535." }
    }
}

sealed interface SafeDnsName {
    /** DNS name capture is disabled for this session. */
    object NotCaptured : SafeDnsName

    /** A per-session salted SHA-256 prefix; it cannot be reversed by the export. */
    data class Hashed(
        val sha256Prefix: String,
        val labelCount: Int,
    ) : SafeDnsName

    /** Available only when the host app enables a separately consented policy. */
    data class PlaintextAfterExplicitConsent(
        val normalizedName: String,
    ) : SafeDnsName
}

enum class DnsMessageKind {
    QUERY,
    RESPONSE,
}

enum class DnsParseStatus {
    PARSED,
    HEADER_ONLY,
    MALFORMED,
}

/**
 * One A/AAAA answer from an observed DNS response.
 *
 * This is what makes a domain firewall rule possible at all: a rule names a host, but the
 * data plane only ever sees addresses, so without the observed answer there is nothing to
 * bind the two together. The address is recorded, never a resolved name — name handling
 * stays governed by [SafeDnsName].
 */
data class DnsAnswerRecord(
    val address: String,
    val ttlSeconds: Long,
    val isIpv6: Boolean,
) {
    init {
        require(address.isNotBlank() && address.length <= 45) { "A DNS answer address is out of range." }
        require(ttlSeconds in 0..0xFFFF_FFFFL) { "A DNS answer TTL is out of range." }
    }
}

data class DnsMetadata(
    val messageKind: DnsMessageKind,
    val transactionId: Int,
    val questionCount: Int,
    val responseCode: Int?,
    val questionName: SafeDnsName,
    val questionType: Int?,
    val status: DnsParseStatus,
    val answers: List<DnsAnswerRecord> = emptyList(),
) {
    init {
        require(transactionId in 0..65_535) { "DNS transaction ID is out of range." }
        require(questionCount in 0..65_535) { "DNS question count is out of range." }
        require(responseCode == null || responseCode in 0..15) { "DNS response code is out of range." }
        require(questionType == null || questionType in 0..65_535) { "DNS question type is out of range." }
        require(answers.size <= 64) { "Too many DNS answer records were retained." }
    }
}

enum class PacketParserNote {
    CAPTURE_TRUNCATED,
    NON_INITIAL_FRAGMENT,
    UNSUPPORTED_IPV6_EXTENSION_HEADER,
    EXCESSIVE_IPV6_EXTENSION_HEADERS,
    ENCRYPTED_OR_OPAQUE_IP_PAYLOAD,
    TRANSPORT_HEADER_TRUNCATED,
    DNS_NOT_PLAINTEXT,
    DNS_MESSAGE_TRUNCATED,
}

/** Metadata only. It intentionally has no raw packet, payload, SNI, or TLS fields. */
data class PacketMetadata(
    val ipVersion: IpVersion,
    val ipProtocolNumber: Int,
    val transportProtocol: TransportProtocol,
    val source: NetworkEndpoint,
    val destination: NetworkEndpoint,
    val icmpType: Int? = null,
    val icmpCode: Int? = null,
    val declaredIpPacketBytes: Int?,
    val capturedPacketBytes: Int,
    val dns: DnsMetadata? = null,
    val notes: Set<PacketParserNote> = emptySet(),
) {
    init {
        require(ipProtocolNumber in 0..255) { "IP protocol number is out of range." }
        require(capturedPacketBytes >= 0) { "Captured packet length must not be negative." }
        require(declaredIpPacketBytes == null || declaredIpPacketBytes >= 0) {
            "Declared packet length must not be negative."
        }
    }
}

sealed interface PacketParseResult {
    data class Parsed(val metadata: PacketMetadata) : PacketParseResult

    data class Malformed(val reason: String) : PacketParseResult

    data class Ignored(val reason: String) : PacketParseResult
}

data class NetworkFlowKey(
    val ipVersion: IpVersion,
    val protocol: TransportProtocol,
    val source: NetworkEndpoint,
    val destination: NetworkEndpoint,
    val direction: PacketDirection,
)

data class NetworkFlow(
    val id: String,
    val key: NetworkFlowKey,
    val attribution: AppAttribution,
    val direction: PacketDirection,
    val startedAtMillis: Long,
    val lastSeenAtMillis: Long,
    val packetCount: Long,
    val observedBytes: Long,
    val latestDnsName: SafeDnsName? = null,
) {
    init {
        require(packetCount >= 0L) { "Packet count must not be negative." }
        require(observedBytes >= 0L) { "Observed byte count must not be negative." }
    }

    companion object {
        fun fromPacket(
            metadata: PacketMetadata,
            attribution: AppAttribution,
            direction: PacketDirection,
            atMillis: Long,
        ): NetworkFlow = NetworkFlow(
            id = UUID.randomUUID().toString(),
            key = metadata.toFlowKey(direction),
            attribution = attribution,
            direction = direction,
            startedAtMillis = atMillis,
            lastSeenAtMillis = atMillis,
            packetCount = 1L,
            observedBytes = metadata.capturedPacketBytes.toLong(),
            latestDnsName = metadata.dns?.questionName,
        )
    }

    fun observe(metadata: PacketMetadata, attribution: AppAttribution, atMillis: Long): NetworkFlow = copy(
        attribution = preferKnownAttribution(this.attribution, attribution),
        lastSeenAtMillis = maxOf(lastSeenAtMillis, atMillis),
        packetCount = packetCount + 1L,
        observedBytes = observedBytes + metadata.capturedPacketBytes.toLong(),
        latestDnsName = metadata.dns?.questionName ?: latestDnsName,
    )
}

fun PacketMetadata.toFlowKey(direction: PacketDirection): NetworkFlowKey = NetworkFlowKey(
    ipVersion = ipVersion,
    protocol = transportProtocol,
    source = source,
    destination = destination,
    direction = direction,
)

private fun preferKnownAttribution(
    old: AppAttribution,
    fresh: AppAttribution,
): AppAttribution = when {
    old is AppAttribution.Known -> old
    fresh is AppAttribution.Known -> fresh
    else -> old
}

sealed interface NetworkEvent {
    val sessionId: String
    val atMillis: Long
}

data class MonitorStateEvent(
    override val sessionId: String,
    override val atMillis: Long,
    val state: MonitorLifecycleState,
    /** Diagnostic-only legacy text. Never render or export this field. */
    val detail: String,
    val uiText: NetworkUiText = NetworkUiText.forLifecycle(state),
) : NetworkEvent

data class PacketObservedEvent(
    override val sessionId: String,
    override val atMillis: Long,
    val flowId: String,
    val direction: PacketDirection,
    val attribution: AppAttribution,
    val metadata: PacketMetadata,
) : NetworkEvent

data class FirewallDecisionEvent(
    override val sessionId: String,
    override val atMillis: Long,
    val flowId: String?,
    val decision: FirewallDecision,
) : NetworkEvent

data class PacketParseFailureEvent(
    override val sessionId: String,
    override val atMillis: Long,
    /** Diagnostic-only parser text. Never render or export this field. */
    val reason: String,
    val code: PacketParseFailureCode = PacketParseFailureCode.MALFORMED_PACKET,
) : NetworkEvent

data class EngineLimitationEvent(
    override val sessionId: String,
    override val atMillis: Long,
    val limitation: EngineLimitation,
) : NetworkEvent

data class ForwarderEnforcementEvent(
    override val sessionId: String,
    override val atMillis: Long,
    val result: FirewallEnforcementResult,
) : NetworkEvent

data class NetworkSessionMetadata(
    val sessionId: String,
    val requestedMode: MonitoringMode,
    val state: MonitorLifecycleState,
    val startedAtMillis: Long,
    val endedAtMillis: Long?,
    val retainedEventCount: Int,
    val droppedEventCount: Long,
    val capabilities: CapabilitySnapshot,
    val limitations: List<EngineLimitation>,
)

private fun validatePackageNames(packageNames: Set<String>) {
    require(packageNames.size <= MAX_CONFIGURED_APP_PACKAGES) {
        "At most $MAX_CONFIGURED_APP_PACKAGES app packages can be selected."
    }
    require(packageNames.all(ANDROID_PACKAGE_NAME::matches)) { "One or more package names are invalid." }
}
