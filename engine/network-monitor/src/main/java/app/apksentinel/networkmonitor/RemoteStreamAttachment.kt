package app.apksentinel.networkmonitor

import java.security.SecureRandom
import java.util.Base64

/** Terminal reasons delivered by the VPN owner to an attached remote stream. */
enum class RemoteStreamAttachmentStopReason {
    VPN_REVOKED,
    SERVICE_DESTROYED,
    NETWORK_CHANGED,
    USER_STOPPED,
}

/** Opaque, process-local capability. The token has no destination or identity data. */
@JvmInline
value class RemoteStreamAttachmentToken private constructor(val value: String) {
    companion object {
        fun create(): RemoteStreamAttachmentToken {
            val bytes = ByteArray(18).also(SecureRandom()::nextBytes)
            return try {
                RemoteStreamAttachmentToken(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes))
            } finally {
                bytes.fill(0)
            }
        }
    }
}

/** The app supplies the session callback; the service remains the lifecycle owner. */
interface RemoteStreamAttachmentCallbacks {
    fun onOwnerStopped(reason: RemoteStreamAttachmentStopReason)

    /** Must synchronously encrypt/copy or reject bytes; the caller does not retain them. */
    fun offer(category: String, observedAtMillis: Long, bytes: ByteArray): Boolean
}

/**
 * Process-local attachment registry. It intentionally has no persistence,
 * discovery, destination, socket, or transport behavior. Service teardown
 * invalidates every attachment so a remote session cannot outlive its VPN
 * owner or silently resume after process death.
 */
object RemoteStreamAttachmentRegistry {
    private val lock = Any()
    private val callbacks = LinkedHashMap<String, RemoteStreamAttachmentCallbacks>()

    fun register(token: RemoteStreamAttachmentToken, callback: RemoteStreamAttachmentCallbacks): Boolean = synchronized(lock) {
        if (token.value.isBlank() || callbacks.containsKey(token.value)) return false
        callbacks[token.value] = callback
        true
    }

    fun unregister(token: RemoteStreamAttachmentToken) = synchronized(lock) {
        callbacks.remove(token.value)
    }

    fun contains(token: String?): Boolean = token != null && synchronized(lock) {
        callbacks.containsKey(token)
    }

    fun offer(token: String?, category: String, observedAtMillis: Long, bytes: ByteArray): Boolean {
        if (token.isNullOrBlank() || category !in ALLOWED_CATEGORIES || bytes.isEmpty()) return false
        val callback = synchronized(lock) { callbacks[token] } ?: return false
        return runCatching { callback.offer(category, observedAtMillis, bytes) }.getOrDefault(false)
    }

    fun stop(token: String?, reason: RemoteStreamAttachmentStopReason): Boolean {
        if (token.isNullOrBlank()) return false
        val callback = synchronized(lock) { callbacks.remove(token) } ?: return false
        runCatching { callback.onOwnerStopped(reason) }
        return true
    }

    fun stopAll(reason: RemoteStreamAttachmentStopReason) {
        val active = synchronized(lock) { callbacks.values.toList().also { callbacks.clear() } }
        active.forEach { callback -> runCatching { callback.onOwnerStopped(reason) } }
    }

    private val ALLOWED_CATEGORIES = setOf("METADATA", "RAW_ENCRYPTED_PACKET")
}
