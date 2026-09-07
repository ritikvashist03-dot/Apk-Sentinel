package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.engine.threatintel.EncryptedThreatFeedSnapshotStore
import app.apksentinel.engine.threatintel.ThreatFeedInstallResult
import app.apksentinel.engine.threatintel.ThreatFeedKey
import app.apksentinel.engine.threatintel.ThreatFeedLoadResult
import app.apksentinel.engine.threatintel.ThreatFeedRepository
import app.apksentinel.engine.threatintel.ThreatFeedRetentionResult
import app.apksentinel.engine.threatintel.ThreatFeedStoreFailure
import app.apksentinel.engine.threatintel.ThreatFeedVerifier
import app.apksentinel.engine.threatintel.ThreatIndicator
import app.apksentinel.engine.threatintel.VerifiedThreatFeed

internal sealed interface AppThreatFeedState {
    data class Active(val feed: VerifiedThreatFeed, val activatedAtMillis: Long) : AppThreatFeedState
    data object Missing : AppThreatFeedState
    data class Unavailable(val failure: ThreatFeedFailure) : AppThreatFeedState
}

/**
 * Stable, non-localized threat-feed failure categories for the app boundary.
 *
 * Engine codes are kept in [ThreatFeedFailure.engineCode] for diagnostics, but
 * engine prose is deliberately never returned to Compose. This keeps the UI
 * localizable and avoids surfacing implementation details from a verifier.
 */
internal enum class ThreatFeedIssue {
    PUBLISHER_KEY_UNAVAILABLE,
    SECURE_STORAGE_UNAVAILABLE,
    STORED_SNAPSHOT_INCONSISTENT,
    PAYLOAD_SIZE,
    DEVICE_CLOCK,
    FEED_FORMAT,
    INDICATOR_LIMIT,
    TIME_OR_VERSION,
    FEED_LIFETIME,
    FUTURE_DATED,
    EXPIRED,
    ROLLBACK,
    SIGNING_KEY_UNTRUSTED,
    SIGNING_KEY_CONFIGURATION,
    SIGNING_KEY_INACTIVE,
    SIGNING_KEY_VALIDITY,
    SIGNATURE_FORMAT,
    SIGNATURE_INVALID,
    NO_INDICATORS,
    INVALID_INDICATOR,
    DUPLICATE_INDICATOR,
    SNAPSHOT_TOO_LARGE,
    MALFORMED_SNAPSHOT,
    UNKNOWN;

    companion object {
        fun fromEngineCode(code: String): ThreatFeedIssue = when (code) {
            "STORAGE" -> SECURE_STORAGE_UNAVAILABLE
            "SNAPSHOT" -> STORED_SNAPSHOT_INCONSISTENT
            "PAYLOAD_SIZE" -> PAYLOAD_SIZE
            "CLOCK" -> DEVICE_CLOCK
            "FORMAT" -> FEED_FORMAT
            "ENTRY_LIMIT" -> INDICATOR_LIMIT
            "TIME_VERSION" -> TIME_OR_VERSION
            "LIFETIME" -> FEED_LIFETIME
            "FUTURE" -> FUTURE_DATED
            "EXPIRED" -> EXPIRED
            "ROLLBACK" -> ROLLBACK
            "KEY", "KEY_REVOKED" -> SIGNING_KEY_UNTRUSTED
            "KEY_CONFIG" -> SIGNING_KEY_CONFIGURATION
            "KEY_RETIRED" -> SIGNING_KEY_INACTIVE
            "KEY_VALIDITY" -> SIGNING_KEY_VALIDITY
            "SIGNATURE_ENCODING" -> SIGNATURE_FORMAT
            "SIGNATURE" -> SIGNATURE_INVALID
            "ENTRY_EMPTY" -> NO_INDICATORS
            "ENTRY" -> INVALID_INDICATOR
            "DUPLICATE_ENTRY" -> DUPLICATE_INDICATOR
            else -> UNKNOWN
        }

        fun fromStoreFailure(reason: ThreatFeedStoreFailure): ThreatFeedIssue = when (reason) {
            ThreatFeedStoreFailure.STORAGE_UNAVAILABLE -> SECURE_STORAGE_UNAVAILABLE
            ThreatFeedStoreFailure.MALFORMED_SNAPSHOT -> MALFORMED_SNAPSHOT
            ThreatFeedStoreFailure.SNAPSHOT_TOO_LARGE -> SNAPSHOT_TOO_LARGE
        }
    }
}

/** A typed failure with the stable engine identifier retained for diagnostics. */
internal data class ThreatFeedFailure(
    val issue: ThreatFeedIssue,
    val engineCode: String,
)

/** Typed outcome for a manual feed verification attempt. */
internal sealed interface ThreatFeedInstallOutcome {
    data class Installed(
        val version: Long,
        val indicatorCount: Int,
    ) : ThreatFeedInstallOutcome

    data class Rejected(val failure: ThreatFeedFailure) : ThreatFeedInstallOutcome
}

/** App-owned composition for the signed, encrypted, offline threat feed. */
internal class ThreatIntelManager(context: Context) {
    private var encryptedStorage: AndroidKeystoreEncryptedStorage? = null
    private val buildKeyConfigured = BuildConfig.THREAT_FEED_KEY_ID.matches(Regex("[A-Za-z0-9._-]{1,64}")) &&
        BuildConfig.THREAT_FEED_PUBLIC_KEY_BASE64.isNotBlank()
    private val repository: ThreatFeedRepository? = runCatching {
        val keyId = BuildConfig.THREAT_FEED_KEY_ID
        val publicKey = BuildConfig.THREAT_FEED_PUBLIC_KEY_BASE64
        require(keyId.matches(Regex("[A-Za-z0-9._-]{1,64}")) && publicKey.isNotBlank())
        val appContext = context.applicationContext
        val storage = AndroidKeystoreEncryptedStorage(
            preferences = appContext.getSharedPreferences("threat_feed_encrypted", Context.MODE_PRIVATE),
            keyAlias = "apk_sentinel_threat_feed_v1",
            namespace = "apk_sentinel_threat_feed",
        )
        encryptedStorage = storage
        ThreatFeedRepository(
            verifier = ThreatFeedVerifier(listOf(ThreatFeedKey(keyId, publicKey))),
            store = EncryptedThreatFeedSnapshotStore(storage),
        )
    }.getOrNull()
    private val initializationFailure: ThreatFeedFailure? = if (repository == null) {
        ThreatFeedFailure(
            issue = if (buildKeyConfigured) ThreatFeedIssue.SIGNING_KEY_CONFIGURATION else ThreatFeedIssue.PUBLISHER_KEY_UNAVAILABLE,
            engineCode = if (buildKeyConfigured) "BUILD_KEY_INVALID" else "BUILD_KEY_MISSING",
        )
    } else {
        null
    }

    fun load(nowMillis: Long = System.currentTimeMillis()): AppThreatFeedState {
        val repo = repository ?: return AppThreatFeedState.Unavailable(requireNotNull(initializationFailure))
        return when (val result = repo.loadActive(nowMillis)) {
            is ThreatFeedLoadResult.Active -> AppThreatFeedState.Active(result.feed, result.activatedAtMillis)
            ThreatFeedLoadResult.Missing -> AppThreatFeedState.Missing
            is ThreatFeedLoadResult.Unavailable -> AppThreatFeedState.Unavailable(result.toFailure())
        }
    }

    fun install(
        payload: ByteArray,
        signatureBase64: String,
        nowMillis: Long = System.currentTimeMillis(),
    ): ThreatFeedInstallOutcome {
        val repo = repository ?: return ThreatFeedInstallOutcome.Rejected(requireNotNull(initializationFailure))
        return when (val result = repo.install(payload, signatureBase64.trim(), nowMillis)) {
            is ThreatFeedInstallResult.Installed -> ThreatFeedInstallOutcome.Installed(
                version = result.feed.version,
                indicatorCount = result.feed.indicators.size,
            )
            is ThreatFeedInstallResult.Rejected -> ThreatFeedInstallOutcome.Rejected(result.toFailure())
            is ThreatFeedInstallResult.StorageFailure -> ThreatFeedInstallOutcome.Rejected(
                ThreatFeedFailure(ThreatFeedIssue.fromStoreFailure(result.reason), result.reason.name),
            )
        }
    }

    fun erase(): Boolean {
        val result = repository?.erase()
        val recordRemoved = result == null || result in setOf(
            ThreatFeedRetentionResult.DELETED,
            ThreatFeedRetentionResult.NOTHING_TO_DELETE,
        )
        // Always attempt alias deletion, even if record deletion reports a
        // storage failure. Full erase must not strand the app-owned key.
        val keyRemoved = encryptedStorage?.deleteEncryptionKey() != false
        return recordRemoved && keyRemoved
    }

    fun hostIndicators(host: String): List<ThreatIndicator> =
        (load() as? AppThreatFeedState.Active)?.feed?.matchHost(host).orEmpty()

    fun apkIndicators(sha256: String): List<ThreatIndicator> =
        (load() as? AppThreatFeedState.Active)?.feed?.matchApkSha256(sha256).orEmpty()

    fun activeFeed(): VerifiedThreatFeed? = (load() as? AppThreatFeedState.Active)?.feed
}

private fun ThreatFeedLoadResult.Unavailable.toFailure(): ThreatFeedFailure =
    ThreatFeedFailure(ThreatFeedIssue.fromEngineCode(code), code)

private fun ThreatFeedInstallResult.Rejected.toFailure(): ThreatFeedFailure =
    ThreatFeedFailure(ThreatFeedIssue.fromEngineCode(code), code)
