package app.apksentinel.engine.rootcapture

/**
 * A containment-first rooted capture foundation. Nothing in this module probes
 * root or starts a process by itself. A host must obtain a fresh, explicit
 * acknowledgement for the exact action before calling either public gateway.
 */
object RootCaptureDefaults {
    const val FEATURE_ENABLED_BY_DEFAULT: Boolean = false
    const val MIN_API: Int = 26
    const val MAX_CONSENT_AGE_MILLIS: Long = 60_000L
}

enum class RootCaptureConsentAction {
    CAPABILITY_CHECK,
    START_HEADERS_ONLY_CAPTURE,
    START_FULL_PACKET_CAPTURE,
}

/**
 * Explicit capture scopes. The full scope captures packet bytes up to the
 * selected snap length; it never decrypts TLS, installs a CA, or uploads data.
 */
enum class RootCaptureScope {
    IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
    FULL_PACKET_CAPTURE,
}

fun RootCaptureScope.requiredConsentAction(): RootCaptureConsentAction = when (this) {
    RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> RootCaptureConsentAction.START_HEADERS_ONLY_CAPTURE
    RootCaptureScope.FULL_PACKET_CAPTURE -> RootCaptureConsentAction.START_FULL_PACKET_CAPTURE
}

data class RootCaptureConsent(
    val action: RootCaptureConsentAction,
    val scope: RootCaptureScope,
    val disclosureVersion: String,
    val acknowledgedAtMillis: Long,
    val sessionNonce: String,
) {
    init {
        require(disclosureVersion.matches(Regex("^[A-Za-z0-9._-]{1,120}$"))) { "Disclosure version is invalid." }
        require(acknowledgedAtMillis > 0L) { "Acknowledgement time is invalid." }
        require(sessionNonce.matches(Regex("^[A-Za-z0-9_-]{16,96}$"))) { "Consent nonce is invalid." }
    }
}

enum class RootCaptureConsentRejection {
    WRONG_ACTION,
    WRONG_SCOPE,
    CLOCK_UNAVAILABLE,
    CLOCK_ROLLBACK,
    ACKNOWLEDGEMENT_IN_FUTURE,
    ACKNOWLEDGEMENT_STALE,
    CONSENT_ALREADY_USED,
}

sealed interface RootCaptureConsentCheck {
    data object Accepted : RootCaptureConsentCheck
    data class Rejected(val reason: RootCaptureConsentRejection) : RootCaptureConsentCheck
}

interface RootCaptureClock {
    fun nowMillis(): Long
}

object SystemRootCaptureClock : RootCaptureClock {
    override fun nowMillis(): Long = System.currentTimeMillis()
}

object RootCaptureConsentValidator {
    fun validate(
        consent: RootCaptureConsent,
        action: RootCaptureConsentAction,
        scope: RootCaptureScope,
        clock: RootCaptureClock,
    ): RootCaptureConsentCheck {
        if (consent.action != action) return RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.WRONG_ACTION)
        if (consent.scope != scope) return RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.WRONG_SCOPE)
        val now = runCatching(clock::nowMillis).getOrElse {
            return RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.CLOCK_UNAVAILABLE)
        }
        if (now < consent.acknowledgedAtMillis) return RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.ACKNOWLEDGEMENT_IN_FUTURE)
        val age = now - consent.acknowledgedAtMillis
        if (age < 0L) return RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.CLOCK_ROLLBACK)
        if (age > RootCaptureDefaults.MAX_CONSENT_AGE_MILLIS) {
            return RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.ACKNOWLEDGEMENT_STALE)
        }
        return RootCaptureConsentCheck.Accepted
    }
}

/** Process-local single-use guard for hosts that validate consent outside the controller. */
class RootCaptureConsentUseLedger {
    private val consumedNonces = HashSet<String>()

    /** Reserve a nonce after the caller has already performed action/scope validation. */
    fun consumeNonce(sessionNonce: String): Boolean = synchronized(consumedNonces) {
        consumedNonces.add(sessionNonce)
    }

    fun validateAndConsume(
        consent: RootCaptureConsent,
        action: RootCaptureConsentAction,
        scope: RootCaptureScope,
        clock: RootCaptureClock,
    ): RootCaptureConsentCheck {
        val validation = RootCaptureConsentValidator.validate(consent, action, scope, clock)
        if (validation !is RootCaptureConsentCheck.Accepted) return validation
        return synchronized(consumedNonces) {
            if (consumedNonces.add(consent.sessionNonce)) {
                RootCaptureConsentCheck.Accepted
            } else {
                RootCaptureConsentCheck.Rejected(RootCaptureConsentRejection.CONSENT_ALREADY_USED)
            }
        }
    }
}

/** Only fixed interface categories are accepted; a host may not inject an arbitrary shell interface name. */
enum class RootCaptureInterface { ALL_DEVICE, WIFI, MOBILE }

/**
 * The safe filter only includes IPv4 TCP SYN, FIN, or RST packets whose IP
 * total length exactly equals the IPv4 and TCP header lengths. That excludes
 * application payload bytes, including TCP Fast Open data on a SYN.
 */
enum class RootCaptureFilter {
    IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD,
    /** All link-layer packets visible on the selected allowlisted interface. */
    ALL_TRAFFIC,
    /** Fixed IPv4/IPv6 TCP-or-UDP filter; no address or text BPF is accepted. */
    IPV4_IPV6_TCP_UDP,
}

data class RootCaptureLimits(
    val maximumDurationMillis: Long = 60_000L,
    val maximumBytes: Long = 2L * 1024L * 1024L,
    val maximumPackets: Int = 2_000,
    val snapLengthBytes: Int = 96,
) {
    init {
        require(maximumDurationMillis in 5_000L..10L * 60L * 1_000L) { "Capture duration is outside the allowed range." }
        require(maximumBytes in 32L * 1_024L..8L * 1_024L * 1_024L) { "Capture byte cap is outside the allowed range." }
        require(maximumPackets in 1..10_000) { "Capture packet cap is outside the allowed range." }
        require(snapLengthBytes in 96..MAX_SNAP_LENGTH_BYTES) { "Capture snap length is outside the allowed range." }
    }

    companion object {
        const val MAX_SNAP_LENGTH_BYTES: Int = 65_535
        const val FULL_CAPTURE_MIN_SNAP_LENGTH_BYTES: Int = 256

        /** Conservative full-capture preset; callers may choose a smaller bounded value. */
        fun fullPacketCaptureDefaults(): RootCaptureLimits = RootCaptureLimits(
            maximumDurationMillis = 60_000L,
            maximumBytes = 4L * 1024L * 1024L,
            maximumPackets = 2_000,
            snapLengthBytes = 4 * 1024,
        )
    }
}

data class RootCaptureStartRequest(
    val androidApiLevel: Int,
    val featureEnabled: Boolean = RootCaptureDefaults.FEATURE_ENABLED_BY_DEFAULT,
    val scope: RootCaptureScope = RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
    val captureInterface: RootCaptureInterface,
    val filter: RootCaptureFilter = RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD,
    val limits: RootCaptureLimits = RootCaptureLimits(),
)

enum class RootCaptureLimitation {
    ROOT_NEVER_REQUESTED_SILENTLY,
    DEVICE_ROOT_MANAGER_DECIDES_ACCESS,
    NO_BUNDLED_CAPTURE_BINARY,
    TCPDUMP_AVAILABILITY_VARIES,
    IPV4_TCP_CONNECTION_CONTROL_ONLY,
    APPLICATION_PAYLOADS_EXCLUDED,
    TLS_DECRYPTION_NOT_SUPPORTED,
    CA_INSTALLATION_NOT_SUPPORTED,
    CREDENTIALS_NOT_CAPTURED_OR_EXPORTED,
    APP_PRIVATE_TEMPORARY_OUTPUT_ONLY,
    USER_MEDIATED_SAF_EXPORT_ONLY,
    NO_UPLOAD_OR_REMOTE_STREAMING,
    CAPTURE_COUNTS_AND_OUTPUT_ARE_BOUNDED,
    FULL_PACKET_BYTES_CAPTURED_UP_TO_SNAP_LENGTH,
    IPV4_AND_IPV6_PACKET_SCOPE_AVAILABLE,
    SNAP_LENGTH_MAY_TRUNCATE_LARGE_PACKETS,
    FULL_CAPTURE_REQUIRES_EXPLICIT_SCOPE_CONSENT,
}

object RootCaptureLimitationSets {
    fun forScope(scope: RootCaptureScope): Set<RootCaptureLimitation> = buildSet {
        add(RootCaptureLimitation.ROOT_NEVER_REQUESTED_SILENTLY)
        add(RootCaptureLimitation.DEVICE_ROOT_MANAGER_DECIDES_ACCESS)
        add(RootCaptureLimitation.NO_BUNDLED_CAPTURE_BINARY)
        add(RootCaptureLimitation.TCPDUMP_AVAILABILITY_VARIES)
        add(RootCaptureLimitation.TLS_DECRYPTION_NOT_SUPPORTED)
        add(RootCaptureLimitation.CA_INSTALLATION_NOT_SUPPORTED)
        add(RootCaptureLimitation.CREDENTIALS_NOT_CAPTURED_OR_EXPORTED)
        add(RootCaptureLimitation.APP_PRIVATE_TEMPORARY_OUTPUT_ONLY)
        add(RootCaptureLimitation.USER_MEDIATED_SAF_EXPORT_ONLY)
        add(RootCaptureLimitation.NO_UPLOAD_OR_REMOTE_STREAMING)
        add(RootCaptureLimitation.CAPTURE_COUNTS_AND_OUTPUT_ARE_BOUNDED)
        when (scope) {
            RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY -> {
                add(RootCaptureLimitation.IPV4_TCP_CONNECTION_CONTROL_ONLY)
                add(RootCaptureLimitation.APPLICATION_PAYLOADS_EXCLUDED)
            }
            RootCaptureScope.FULL_PACKET_CAPTURE -> {
                add(RootCaptureLimitation.FULL_PACKET_BYTES_CAPTURED_UP_TO_SNAP_LENGTH)
                add(RootCaptureLimitation.IPV4_AND_IPV6_PACKET_SCOPE_AVAILABLE)
                add(RootCaptureLimitation.SNAP_LENGTH_MAY_TRUNCATE_LARGE_PACKETS)
                add(RootCaptureLimitation.FULL_CAPTURE_REQUIRES_EXPLICIT_SCOPE_CONSENT)
            }
        }
    }
}

enum class RootCaptureCapability {
    USABLE,
    UNSUPPORTED_ANDROID_API,
    ROOT_BINARY_UNAVAILABLE,
    ROOT_ACCESS_DENIED,
    ROOT_PROBE_FAILED,
    TCPDUMP_UNAVAILABLE,
    TCPDUMP_PROBE_FAILED,
}

data class RootCaptureCapabilityResult(
    val capability: RootCaptureCapability,
    val limitations: Set<RootCaptureLimitation> = RootCaptureLimitationSets.forScope(RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY),
    val scope: RootCaptureScope = RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
) {
    val isUsable: Boolean get() = capability == RootCaptureCapability.USABLE
}

sealed interface RootCaptureStartResult {
    data class Started(val session: RootCaptureSessionSnapshot) : RootCaptureStartResult
    data class Rejected(val reason: RootCaptureStartRejection) : RootCaptureStartResult
}

enum class RootCaptureStartRejection {
    DISABLED_BY_DEFAULT,
    UNSUPPORTED_ANDROID_API,
    CONSENT_REJECTED,
    ROOT_UNAVAILABLE,
    TCPDUMP_UNAVAILABLE,
    TEMPORARY_OUTPUT_UNAVAILABLE,
    PROCESS_START_FAILED,
    ANOTHER_CAPTURE_ACTIVE,
}

enum class RootCaptureTerminalReason {
    USER_STOPPED,
    DURATION_CAP_REACHED,
    BYTE_CAP_REACHED,
    PACKET_CAP_REACHED,
    PROCESS_EXITED,
    PROCESS_DIED,
    OUTPUT_UNAVAILABLE,
    ERASURE_REQUESTED,
}

data class RootCaptureSessionSnapshot(
    val sessionId: String,
    val startedAtMillis: Long,
    val maximumDurationMillis: Long,
    val maximumBytes: Long,
    val maximumPackets: Int,
    val active: Boolean,
    val terminalReason: RootCaptureTerminalReason? = null,
    val observedBytes: Long = 0L,
    val observedPackets: Int = 0,
    /** True while Stop/limit has requested termination but the pump has not finalized output. */
    val finalizing: Boolean = false,
    val mustShowProminentActiveIndicator: Boolean = active,
    val mustShowStopControl: Boolean = active,
    val scope: RootCaptureScope = RootCaptureScope.IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY,
    val filter: RootCaptureFilter = RootCaptureFilter.IPV4_TCP_CONNECTION_CONTROL_NO_PAYLOAD,
    val outputStatus: RootCaptureOutputStatus = RootCaptureOutputStatus.COMPLETE,
    val exportable: Boolean = !active && outputStatus != RootCaptureOutputStatus.PARTIAL_OUTPUT_REJECTED,
)

enum class RootCaptureOutputStatus {
    COMPLETE,
    TRUNCATED_AT_BYTE_CAP,
    TRUNCATED_AT_PACKET_CAP,
    PARTIAL_OUTPUT_REJECTED,
}

data class RootCaptureExportRequest(val sessionId: String)

sealed interface RootCaptureExportResult {
    data object UserMediatedDestinationRequired : RootCaptureExportResult
    data object ExportedAndErased : RootCaptureExportResult
    data class Rejected(val reason: RootCaptureExportRejection) : RootCaptureExportResult
}

enum class RootCaptureExportRejection { SESSION_UNKNOWN, SESSION_ACTIVE, OUTPUT_UNAVAILABLE, DESTINATION_WRITE_FAILED }

sealed interface RootCaptureEraseResult {
    data object Erased : RootCaptureEraseResult
    data object NothingToErase : RootCaptureEraseResult
    data object CleanupIncomplete : RootCaptureEraseResult
}
