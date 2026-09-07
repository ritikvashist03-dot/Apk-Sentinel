package app.apksentinel.networkmonitor

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.SecureStorageKey

/**
 * Android composition point for durable history. Calling [create] only builds
 * an inactive controller; it does not install it in [NetworkMonitorRuntime],
 * load ciphertext, or begin persistence. A host must explicitly put the
 * returned controller in [NetworkMonitorDependencies.durableHistory].
 */
object AndroidEncryptedNetworkHistoryFactory {
    fun create(
        context: Context,
        policy: DurableHistoryRetentionPolicy = DurableHistoryRetentionPolicy.SEVEN_DAYS,
        limits: DurableHistoryLimits = DurableHistoryLimits(),
    ): EncryptedNetworkHistoryController {
        val application = context.applicationContext
        val storage = AndroidKeystoreEncryptedStorage(
            preferences = application.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE),
            keyAlias = KEY_ALIAS,
            namespace = STORAGE_NAMESPACE,
        )
        return EncryptedNetworkHistoryController(
            storage = storage,
            key = SecureStorageKey(STORAGE_KEY),
            keyEraser = DurableHistoryKeyEraser(storage::deleteEncryptionKey),
            policy = policy,
            limits = limits,
        )
    }

    private const val PREFERENCES_NAME = "apk_sentinel_network_history"
    private const val KEY_ALIAS = "apk_sentinel_network_history_v1"
    private const val STORAGE_NAMESPACE = "apk_sentinel_network_history"
    private const val STORAGE_KEY = "network-history-v1"
}
