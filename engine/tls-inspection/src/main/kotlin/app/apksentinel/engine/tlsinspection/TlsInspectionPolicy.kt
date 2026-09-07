package app.apksentinel.engine.tlsinspection

/** Categories that are never eligible for TLS content handling. UNKNOWN is also excluded to fail closed. */
enum class TlsInspectionPackageCategory {
    GENERAL,
    /** A package sharing a UID or process boundary is never eligible. */
    SHARED,
    /** Explicit name for callers that distinguish shared UID from other sharing. */
    SHARED_UID,
    BANKING,
    PAYMENT,
    AUTHENTICATION,
    PASSWORD_MANAGER,
    HEALTH,
    UNKNOWN,
}

data class TlsInspectionPackageTarget(
    val packageName: String,
    val category: TlsInspectionPackageCategory,
    /** PackageManager reported a shared UID/process boundary. */
    val sharedUid: Boolean = false,
) {
    init {
        require(PACKAGE_PATTERN.matches(packageName)) { "Package name is invalid." }
    }

    private companion object {
        val PACKAGE_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+$")
    }
}

enum class TlsInspectionPackageScopeRejection {
    EMPTY_SELECTION,
    TOO_MANY_PACKAGES,
    DUPLICATE_PACKAGE,
    SENSITIVE_CATEGORY_EXCLUDED,
}

sealed interface TlsInspectionPackageScopeResult {
    data class Allowed(val scope: TlsInspectionPackageScope) : TlsInspectionPackageScopeResult
    data class Rejected(val reason: TlsInspectionPackageScopeRejection) : TlsInspectionPackageScopeResult
}

/**
 * A bounded, explicit allowlist. The mandatory exclusions cannot be removed by
 * configuration, so banking, payment, authentication, password-manager, and
 * health packages never receive a decrypted segment.
 */
class TlsInspectionPackageScope private constructor(
    private val allowedPackages: Set<String>,
) {
    fun contains(packageName: String): Boolean = packageName in allowedPackages

    fun packages(): Set<String> = allowedPackages.toSet()

    companion object {
        const val MAX_SELECTED_PACKAGES = 25

        val mandatoryExcludedCategories: Set<TlsInspectionPackageCategory> = setOf(
            TlsInspectionPackageCategory.BANKING,
            TlsInspectionPackageCategory.PAYMENT,
            TlsInspectionPackageCategory.AUTHENTICATION,
            TlsInspectionPackageCategory.PASSWORD_MANAGER,
            TlsInspectionPackageCategory.HEALTH,
            TlsInspectionPackageCategory.SHARED,
            TlsInspectionPackageCategory.SHARED_UID,
            TlsInspectionPackageCategory.UNKNOWN,
        )

        fun create(targets: List<TlsInspectionPackageTarget>): TlsInspectionPackageScopeResult {
            if (targets.isEmpty()) return TlsInspectionPackageScopeResult.Rejected(TlsInspectionPackageScopeRejection.EMPTY_SELECTION)
            if (targets.size > MAX_SELECTED_PACKAGES) {
                return TlsInspectionPackageScopeResult.Rejected(TlsInspectionPackageScopeRejection.TOO_MANY_PACKAGES)
            }
            if (targets.map { it.packageName }.toSet().size != targets.size) {
                return TlsInspectionPackageScopeResult.Rejected(TlsInspectionPackageScopeRejection.DUPLICATE_PACKAGE)
            }
            if (targets.any { it.category in mandatoryExcludedCategories || it.sharedUid }) {
                return TlsInspectionPackageScopeResult.Rejected(TlsInspectionPackageScopeRejection.SENSITIVE_CATEGORY_EXCLUDED)
            }
            return TlsInspectionPackageScopeResult.Allowed(TlsInspectionPackageScope(targets.map { it.packageName }.toSet()))
        }
    }
}

/**
 * This value must originate from a separately reviewed HTTP-over-TLS-1.2
 * bridge. It is false by default and this module does not provide that bridge.
 */
enum class TlsInspectionDataPlaneReadiness { UNAVAILABLE, REVIEWED_HTTP_TLS12_ONLY }

data class TlsInspectionConfiguration(
    val enabled: Boolean = false,
    val sessionConsent: TlsInspectionSessionConsent? = null,
    val maximumSessionBytes: Int = 128 * 1_024,
    val maximumBytesPerSegment: Int = 4 * 1_024,
    val maximumMetadataEvents: Int = 64,
    val maximumDurationMillis: Long = 5 * 60 * 1_000L,
) {
    init {
        require(!enabled || sessionConsent != null) { "Enabled TLS inspection requires separate session consent." }
        require(maximumSessionBytes in 4 * 1_024..512 * 1_024) { "Session byte bound is outside the supported range." }
        require(maximumBytesPerSegment in 256..16 * 1_024) { "Segment byte bound is outside the supported range." }
        require(maximumBytesPerSegment <= maximumSessionBytes) { "Segment bound cannot exceed session bound." }
        require(maximumMetadataEvents in 1..128) { "Metadata event bound is outside the supported range." }
        require(maximumDurationMillis in 5_000L..30 * 60 * 1_000L) { "Duration is outside the supported range." }
    }

    val isRequested: Boolean get() = enabled && sessionConsent != null
}

data class TlsInspectionStartRequest(
    val androidApiLevel: Int,
    val configuration: TlsInspectionConfiguration = TlsInspectionConfiguration(),
    val selectedPackages: List<TlsInspectionPackageTarget>,
    val dataPlaneReadiness: TlsInspectionDataPlaneReadiness = TlsInspectionDataPlaneReadiness.UNAVAILABLE,
)

enum class TlsInspectionStartRejection {
    DISABLED_BY_DEFAULT,
    UNSUPPORTED_ANDROID_API,
    DATA_PLANE_UNAVAILABLE,
    PACKAGE_SCOPE_REJECTED,
    CLOCK_UNAVAILABLE,
    INVALID_CLOCK,
    CA_CREDENTIAL_UNAVAILABLE,
    CERTIFICATE_NOT_INSTALLED,
    CERTIFICATE_INSTALLATION_UNKNOWN,
    CERTIFICATE_VERIFICATION_FAILED,
}

interface TlsInspectionClock {
    fun nowMillis(): Long
}

object SystemTlsInspectionClock : TlsInspectionClock {
    override fun nowMillis(): Long = System.currentTimeMillis()
}
