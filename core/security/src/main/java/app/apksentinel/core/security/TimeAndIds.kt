package app.apksentinel.core.security

import java.security.SecureRandom
import java.util.Base64

/**
 * A time source is injected into security decisions so expiry behaviour is
 * deterministic in tests and auditable in calling code.
 */
fun interface EpochClock {
    fun nowEpochMillis(): Long
}

object SystemEpochClock : EpochClock {
    override fun nowEpochMillis(): Long = System.currentTimeMillis()
}

/**
 * Produces opaque identifiers. Implementations must not log generated values.
 */
fun interface OpaqueIdGenerator {
    fun nextId(): String
}

class SecureOpaqueIdGenerator(
    private val secureRandom: SecureRandom = SecureRandom(),
) : OpaqueIdGenerator {
    override fun nextId(): String {
        val bytes = ByteArray(ID_BYTE_LENGTH)
        secureRandom.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private companion object {
        const val ID_BYTE_LENGTH = 24
    }
}
