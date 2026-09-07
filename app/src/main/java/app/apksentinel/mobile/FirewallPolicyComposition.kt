package app.apksentinel.mobile

import android.content.Context
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import app.apksentinel.networkmonitor.FirewallEnforcementObserver
import app.apksentinel.networkmonitor.FirewallPolicyController
import app.apksentinel.networkmonitor.FirewallPolicySecureStore
import app.apksentinel.networkmonitor.FirewallPolicySecureStoreErase
import app.apksentinel.networkmonitor.FirewallPolicySecureStoreRead
import app.apksentinel.networkmonitor.FirewallPolicySecureStoreWrite
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import app.apksentinel.networkmonitor.ObservedDomainDestinationCapability

/**
 * App-owned composition for durable firewall preferences. Installation changes
 * only dependencies used by sessions started after this call; the active VPN
 * service retains its own immutable provider snapshot.
 */
internal object FirewallPolicyComposition {
    private val lock = Any()
    private var policy: FirewallPolicyController? = null

    fun initialize(context: Context): FirewallPolicyController = synchronized(lock) {
        policy ?: FirewallPolicyController(
            secureStore = AndroidFirewallPolicySecureStore(context.applicationContext),
            // Without this, domainDestinationAvailable() always answered false and every
            // domain rule stayed UNSUPPORTED_SCOPE for the life of the app.
            domainDestinationCapability = ObservedDomainDestinationCapability,
        ).also { controller ->
            // Composite installation preserves the established process-local rule provider.
            NetworkMonitorRuntime.addFirewallRuleProviderForFutureSessions(controller)
            NetworkMonitorRuntime.installFirewallEnforcementObserverForFutureSessions(
                FirewallEnforcementObserver { decision, result, atMillis ->
                    controller.recordConfirmedOutcome(decision, result, atMillis)
                },
            )
            policy = controller
        }
    }

    fun controller(): FirewallPolicyController? = synchronized(lock) { policy }

    /** Called only after monitor stop is confirmed by the Privacy flow. */
    fun eraseForPrivacy(): Boolean = synchronized(lock) { policy?.eraseForPrivacy() ?: false }
}

/** One dedicated AES-GCM ciphertext slot and one dedicated Android Keystore alias. */
private class AndroidFirewallPolicySecureStore(context: Context) : FirewallPolicySecureStore {
    private val storage = AndroidKeystoreEncryptedStorage(
        preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE),
        keyAlias = KEY_ALIAS,
        namespace = NAMESPACE,
    )

    override fun read(): FirewallPolicySecureStoreRead = when (val result = storage.read(KEY)) {
        is SecureStorageResult.Success -> result.value?.let { FirewallPolicySecureStoreRead.Available(it) }
            ?: FirewallPolicySecureStoreRead.Missing
        is SecureStorageResult.Failure -> FirewallPolicySecureStoreRead.Unavailable
    }

    override fun write(plaintext: ByteArray): FirewallPolicySecureStoreWrite = when (storage.write(KEY, plaintext)) {
        is SecureStorageResult.Success -> FirewallPolicySecureStoreWrite.WRITTEN
        is SecureStorageResult.Failure -> FirewallPolicySecureStoreWrite.UNAVAILABLE
    }

    override fun erase(): FirewallPolicySecureStoreErase {
        val ciphertextRemoved = storage.remove(KEY) is SecureStorageResult.Success
        if (!ciphertextRemoved) return FirewallPolicySecureStoreErase.UNAVAILABLE
        return if (storage.deleteEncryptionKey()) FirewallPolicySecureStoreErase.ERASED
        else FirewallPolicySecureStoreErase.REJECTED
    }

    private companion object {
        val KEY = SecureStorageKey("firewall.policy.v1")
        const val PREFERENCES = "firewall_policy_encrypted"
        const val KEY_ALIAS = "apk_sentinel.firewall_policy.v1"
        const val NAMESPACE = "apk_sentinel_firewall_policy"
    }
}
