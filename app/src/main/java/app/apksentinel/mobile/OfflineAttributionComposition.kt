package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import app.apksentinel.networkmonitor.OfflineAttributionFailure
import app.apksentinel.networkmonitor.OfflineAttributionLoadResult
import app.apksentinel.networkmonitor.OfflineAttributionMetadata
import app.apksentinel.networkmonitor.OfflineAttributionRollbackGuard
import app.apksentinel.networkmonitor.OfflineAttributionSigningKey
import app.apksentinel.networkmonitor.OfflineIpAttributionLookup
import app.apksentinel.networkmonitor.OfflineIpAttributionResult
import app.apksentinel.networkmonitor.OfflineIpAttributionVerifier
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64
import java.util.concurrent.Executors

internal sealed interface OfflineAttributionAppState {
    data object Missing : OfflineAttributionAppState
    data class Active(val metadata: OfflineAttributionMetadata) : OfflineAttributionAppState
    data class Unavailable(val reason: OfflineAttributionFailure) : OfflineAttributionAppState
}

internal sealed interface OfflineAttributionInstallOutcome {
    data class Accepted(val state: OfflineAttributionAppState.Active) : OfflineAttributionInstallOutcome
    data class Rejected(
        val reason: OfflineAttributionFailure,
        val retainedState: OfflineAttributionAppState,
    ) : OfflineAttributionInstallOutcome
}

/** Thread-safe epoch used to linearize privacy erase against queued work. */
internal class OfflineAttributionGenerationGate {
    private var generation = 0L

    @Synchronized
    fun capture(): Long = generation

    @Synchronized
    fun advance(): Long {
        generation += 1L
        return generation
    }

    @Synchronized
    fun isCurrent(captured: Long): Boolean = captured == generation
}

internal object OfflineAttributionComposition {
    private const val MAX_PAYLOAD_BYTES = 900_000
    private const val MAX_SIGNATURE_BYTES = 4_096
    private const val FORMAT_VERSION = 2
    private val key = SecureStorageKey("offline.attribution.bundle.v1")
    // Remove this legacy marker during erase; V2 stores bundle and guard in one atomic record.
    private val legacyRollbackKey = SecureStorageKey("offline.attribution.rollback.v1")
    private val lock = OfflineAttributionGenerationGate()
    private val executor = Executors.newSingleThreadExecutor { task ->
        Thread(task, "apk-sentinel-attribution-composition").apply { isDaemon = true }
    }
    private var storage: AndroidKeystoreEncryptedStorage? = null
    private var lookup: OfflineIpAttributionLookup = OfflineIpAttributionLookup.unavailable()
    private var state: OfflineAttributionAppState = OfflineAttributionAppState.Missing

    fun initialize(context: Context, onReady: (OfflineAttributionAppState) -> Unit = {}) {
        val app = context.applicationContext
        val requestGeneration = lock.capture()
        executor.execute {
            val next = loadStored(app, requestGeneration)
            val retained = synchronized(lock) {
                // A storage read/guard failure must not tear down a valid
                // in-memory runtime that was already serving lookups.
                if (next != null && lock.isCurrent(requestGeneration) &&
                    (next is OfflineAttributionAppState.Active || state !is OfflineAttributionAppState.Active)
                ) {
                    state = next
                }
                state
            }
            onReady(retained)
        }
    }

    fun current(): OfflineAttributionAppState = synchronized(lock) { state }

    fun lookup(literalAddress: String): OfflineIpAttributionResult = synchronized(lock) {
        lookup.lookup(literalAddress)
    }

    fun install(
        context: Context,
        payload: ByteArray,
        signatureBase64: String,
        onComplete: (OfflineAttributionAppState) -> Unit,
    ) {
        installWithOutcome(context, payload, signatureBase64) { outcome ->
            onComplete(
                when (outcome) {
                    is OfflineAttributionInstallOutcome.Accepted -> outcome.state
                    is OfflineAttributionInstallOutcome.Rejected -> outcome.retainedState
                },
            )
        }
    }

    fun installWithOutcome(
        context: Context,
        payload: ByteArray,
        signatureBase64: String,
        onComplete: (OfflineAttributionInstallOutcome) -> Unit,
    ) {
        val candidate = payload.copyOf()
        val requestGeneration = lock.capture()
        executor.execute {
            val result = try {
                if (candidate.isEmpty() || candidate.size > MAX_PAYLOAD_BYTES || signatureBase64.length !in 1..MAX_SIGNATURE_BYTES) {
                    OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.PAYLOAD_SIZE)
                } else {
                    verifyAndPersist(context.applicationContext, candidate, signatureBase64, requestGeneration)
                }
            } finally {
                candidate.fill(0)
            }
            val next = synchronized(lock) {
                // A rejected candidate must not turn a working runtime into an
                // unavailable one. The immutable lookup is changed only after
                // the complete V2 record has been encrypted and committed.
                if (result is OfflineAttributionAppState.Active) {
                    state = result
                }
                state
            }
            onComplete(
                if (result is OfflineAttributionAppState.Active) {
                    OfflineAttributionInstallOutcome.Accepted(result)
                } else {
                    OfflineAttributionInstallOutcome.Rejected(
                        reason = (result as OfflineAttributionAppState.Unavailable).reason,
                        retainedState = next,
                    )
                },
            )
        }
    }

    fun erase(context: Context): Boolean = synchronized(lock) {
        lock.advance()
        // Disarm first, even if Keystore/preferences cleanup later fails.
        lookup = OfflineIpAttributionLookup.unavailable()
        state = OfflineAttributionAppState.Missing
        runCatching { NetworkMonitorRuntime.installOfflineIpAttributionForFutureSessions(lookup) }
        runCatching {
            val secure = secureStorage(context.applicationContext)
            val removedBundle = secure.remove(key) is SecureStorageResult.Success
            val removedLegacyMarker = secure.remove(legacyRollbackKey) is SecureStorageResult.Success
            val keyRemoved = secure.deleteEncryptionKey()
            removedBundle && removedLegacyMarker && keyRemoved
        }.getOrDefault(false)
    }

    private fun verifyAndPersist(
        context: Context,
        payload: ByteArray,
        signature: String,
        requestGeneration: Long,
    ): OfflineAttributionAppState {
        val verifier = verifier() ?: return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.KEY_CONFIGURATION)
        val stored = when (val read = readStored(context)) {
            StoredRead.Failure -> return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.LOADER_FAILED)
            StoredRead.Missing -> null
            is StoredRead.Present -> read.value
        }
        val now = System.currentTimeMillis()
        val guard = stored?.guard ?: object : OfflineAttributionRollbackGuard {
            override fun highestAcceptedVersion(keyId: String): Long? = null
            override fun latestTrustedNowMillis(): Long? = null
        }
        return when (val result = verifier.verify(payload, signature, now, guard)) {
            is OfflineAttributionLoadResult.Rejected -> OfflineAttributionAppState.Unavailable(result.reason)
            is OfflineAttributionLoadResult.Accepted -> {
                val nextVersions = (stored?.highestVersions ?: emptyMap()).toMutableMap()
                nextVersions[result.metadata.keyId] = maxOf(
                    nextVersions[result.metadata.keyId] ?: 0L,
                    result.metadata.version,
                )
                val encoded = encode(
                    payload = payload,
                    signature = signature,
                    highestVersions = nextVersions,
                    trustedNowMillis = maxOf(stored?.trustedNowMillis ?: 0L, now),
                ) ?: return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.PAYLOAD_SIZE)
                val saved = try {
                    var committed = false
                    synchronized(lock) {
                        if (lock.isCurrent(requestGeneration)) {
                            committed = secureStorage(context).write(key, encoded) is SecureStorageResult.Success
                        }
                    }
                    committed
                } finally { encoded.fill(0) }
                if (!saved) return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.LOADER_FAILED)
                synchronized(lock) {
                    if (!lock.isCurrent(requestGeneration)) {
                        return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.LOADER_FAILED)
                    }
                    lookup = result.lookup
                    NetworkMonitorRuntime.installOfflineIpAttributionForFutureSessions(result.lookup)
                }
                OfflineAttributionAppState.Active(result.metadata)
            }
        }
    }

    private fun loadStored(context: Context, requestGeneration: Long): OfflineAttributionAppState? {
        val stored = when (val read = readStored(context)) {
            StoredRead.Failure -> return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.LOADER_FAILED)
            StoredRead.Missing -> return OfflineAttributionAppState.Missing
            is StoredRead.Present -> read.value
        }
        return try {
            val verifier = verifier() ?: return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.KEY_CONFIGURATION)
            when (val result = verifier.verify(stored.payload, stored.signature, System.currentTimeMillis(), stored.guard)) {
                is OfflineAttributionLoadResult.Rejected -> OfflineAttributionAppState.Unavailable(result.reason)
                is OfflineAttributionLoadResult.Accepted -> {
                    if (result.metadata.version != stored.highestVersions[result.metadata.keyId] ||
                        result.metadata.keyId !in stored.highestVersions
                    ) {
                        return OfflineAttributionAppState.Unavailable(OfflineAttributionFailure.FORMAT)
                    }
                    synchronized(lock) {
                        if (!lock.isCurrent(requestGeneration)) return null
                        lookup = result.lookup
                        NetworkMonitorRuntime.installOfflineIpAttributionForFutureSessions(result.lookup)
                    }
                    OfflineAttributionAppState.Active(result.metadata)
                }
            }
        } finally {
            stored.payload.fill(0)
        }
    }

    private fun verifier(): OfflineIpAttributionVerifier? {
        val id = BuildConfig.THREAT_FEED_KEY_ID
        val publicKey = BuildConfig.THREAT_FEED_PUBLIC_KEY_BASE64
        if (!id.matches(Regex("[A-Za-z0-9._-]{1,64}")) || publicKey.isBlank()) return null
        return runCatching {
            OfflineIpAttributionVerifier(
                trustedKeys = listOf(OfflineAttributionSigningKey(id, publicKey)),
                maximumPayloadBytes = MAX_PAYLOAD_BYTES,
            )
        }.getOrNull()
    }

    private fun secureStorage(context: Context): AndroidKeystoreEncryptedStorage = synchronized(lock) {
        storage ?: AndroidKeystoreEncryptedStorage(
            preferences = context.getSharedPreferences("offline_attribution_encrypted", Context.MODE_PRIVATE),
            keyAlias = "apk_sentinel.offline_attribution.v1",
            namespace = "apk_sentinel_offline_attribution",
        ).also { storage = it }
    }

    private fun readStored(context: Context): StoredRead {
        val bytes = when (val read = secureStorage(context).read(key)) {
            is SecureStorageResult.Failure -> return StoredRead.Failure
            is SecureStorageResult.Success -> read.value ?: return StoredRead.Missing
        }
        return try {
            decode(bytes)?.let { StoredRead.Present(it) } ?: StoredRead.Failure
        } finally {
            bytes.fill(0)
        }
    }

    private fun encode(
        payload: ByteArray,
        signature: String,
        highestVersions: Map<String, Long>,
        trustedNowMillis: Long,
    ): ByteArray? {
        val signatureBytes = signature.toByteArray(Charsets.US_ASCII)
        if (payload.isEmpty() || payload.size > MAX_PAYLOAD_BYTES || signatureBytes.size > MAX_SIGNATURE_BYTES ||
            trustedNowMillis < 0L || highestVersions.isEmpty() || highestVersions.size > MAX_GUARD_KEYS
        ) return null
        val guardEntries = highestVersions.entries.sortedBy { it.key }
        if (guardEntries.any { !KEY_ID.matches(it.key) || it.value <= 0L }) return null
        return try {
            ByteArrayOutputStream(HEADER_BYTES + payload.size + signatureBytes.size).use { bytes ->
                DataOutputStream(bytes).use { output ->
                    output.writeInt(MAGIC)
                    output.writeInt(FORMAT_VERSION)
                    output.writeInt(payload.size)
                    output.writeInt(signatureBytes.size)
                    output.writeInt(guardEntries.size)
                    output.writeLong(trustedNowMillis)
                    guardEntries.forEach { (keyId, version) ->
                        val keyBytes = keyId.toByteArray(Charsets.US_ASCII)
                        output.writeInt(keyBytes.size)
                        output.writeLong(version)
                        output.write(keyBytes)
                    }
                    output.write(payload)
                    output.write(signatureBytes)
                }
                bytes.toByteArray()
            }
        } catch (_: RuntimeException) {
            null
        } finally {
            signatureBytes.fill(0)
        }
    }

    private fun decode(bytes: ByteArray): StoredAttribution? {
        if (bytes.size < HEADER_BYTES || bytes.size > MAX_RECORD_BYTES) return null
        return try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                if (input.readInt() != MAGIC || input.readInt() != FORMAT_VERSION) return null
                val payloadSize = input.readInt()
                val signatureSize = input.readInt()
                val guardCount = input.readInt()
                val trustedNowMillis = input.readLong()
                if (payloadSize !in 1..MAX_PAYLOAD_BYTES || signatureSize !in 1..MAX_SIGNATURE_BYTES ||
                    guardCount !in 1..MAX_GUARD_KEYS || trustedNowMillis < 0L
                ) return null
                val versions = linkedMapOf<String, Long>()
                repeat(guardCount) {
                    val keySize = input.readInt()
                    val version = input.readLong()
                    if (keySize !in 1..MAX_KEY_ID_BYTES || version <= 0L) return null
                    val keyBytes = ByteArray(keySize)
                    input.readFully(keyBytes)
                    val keyId = keyBytes.toString(Charsets.US_ASCII)
                    keyBytes.fill(0)
                    if (!KEY_ID.matches(keyId) || versions.put(keyId, version) != null) return null
                }
                if (input.available() != payloadSize + signatureSize) return null
                val payload = ByteArray(payloadSize)
                val signatureBytes = ByteArray(signatureSize)
                input.readFully(payload)
                input.readFully(signatureBytes)
                val signature = signatureBytes.toString(Charsets.US_ASCII)
                val decodedSignature = runCatching { Base64.getDecoder().decode(signature) }.getOrNull()
                if (signatureBytes.any { it.toInt() !in 0x21..0x7e } ||
                    decodedSignature == null || Base64.getEncoder().encodeToString(decodedSignature) != signature
                ) {
                    payload.fill(0)
                    decodedSignature?.fill(0)
                    return null
                }
                decodedSignature.fill(0)
                signatureBytes.fill(0)
                StoredAttribution(payload, signature, versions, trustedNowMillis)
            }
        } catch (_: Exception) {
            null
        }
    }

    private data class StoredAttribution(
        val payload: ByteArray,
        val signature: String,
        val highestVersions: Map<String, Long>,
        val trustedNowMillis: Long,
    ) {
        val guard: OfflineAttributionRollbackGuard = object : OfflineAttributionRollbackGuard {
            override fun highestAcceptedVersion(keyId: String): Long? = highestVersions[keyId]
            override fun latestTrustedNowMillis(): Long = trustedNowMillis
        }
    }

    private sealed interface StoredRead {
        data object Missing : StoredRead
        data object Failure : StoredRead
        data class Present(val value: StoredAttribution) : StoredRead
    }

    private const val MAGIC = 0x4F414232 // OAB2
    private const val HEADER_BYTES = 4 + 4 + 4 + 4 + 4 + 8
    private const val MAX_KEY_ID_BYTES = 64
    private const val MAX_GUARD_KEYS = 32
    private const val MAX_RECORD_BYTES = HEADER_BYTES + MAX_PAYLOAD_BYTES + MAX_SIGNATURE_BYTES +
        MAX_GUARD_KEYS * (4 + 8 + MAX_KEY_ID_BYTES)
    private val KEY_ID = Regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
}
