package app.apksentinel.networkmonitor

import java.util.UUID

/**
 * Process-local, one-shot TLS session consent. The nonce is never accepted as
 * proof by itself: the service consumes the issued record and checks its
 * version, timestamp, and freshness before opening a route.
 */
data class TlsInspectionSessionConsent(
    val version: String,
    val acknowledgedAtMillis: Long,
    val nonce: String,
)

object TlsInspectionSessionConsentRegistry {
    const val MAX_AGE_MILLIS: Long = 2 * 60 * 1_000L

    private data class Pending(
        val version: String,
        val acknowledgedAtMillis: Long,
    )

    private val lock = Any()
    private val pending = LinkedHashMap<String, Pending>()

    fun issue(version: String, nowMillis: Long = System.currentTimeMillis()): TlsInspectionSessionConsent {
        require(version.isNotBlank())
        require(nowMillis > 0L)
        val nonce = UUID.randomUUID().toString()
        synchronized(lock) {
            purgeExpiredLocked(nowMillis)
            pending[nonce] = Pending(version, nowMillis)
        }
        return TlsInspectionSessionConsent(version, nowMillis, nonce)
    }

    /** Removes the record regardless of validity, making every attempt one-shot. */
    fun consume(consent: TlsInspectionSessionConsent, nowMillis: Long = System.currentTimeMillis()): Boolean {
        synchronized(lock) {
            purgeExpiredLocked(nowMillis)
            val issued = pending.remove(consent.nonce) ?: return false
            return issued.version == consent.version &&
                issued.acknowledgedAtMillis == consent.acknowledgedAtMillis &&
                nowMillis >= issued.acknowledgedAtMillis &&
                nowMillis - issued.acknowledgedAtMillis <= MAX_AGE_MILLIS
        }
    }

    fun revoke(nonce: String?) {
        if (nonce.isNullOrBlank()) return
        synchronized(lock) { pending.remove(nonce) }
    }

    internal fun resetForTests() = synchronized(lock) { pending.clear() }

    private fun purgeExpiredLocked(nowMillis: Long) {
        pending.entries.removeIf { (_, value) ->
            nowMillis < value.acknowledgedAtMillis ||
                nowMillis - value.acknowledgedAtMillis > MAX_AGE_MILLIS
        }
    }
}
