package app.apksentinel.core.security

import java.util.Base64

/**
 * Storage keys are internal identifiers. Their string rendering is redacted so
 * an accidental diagnostic log does not disclose logical storage layout.
 */
@JvmInline
value class SecureStorageKey(val value: String) {
    init {
        require(KEY_PATTERN.matches(value)) { "Storage keys must be concise machine-readable identifiers." }
    }

    override fun toString(): String = "[secure-storage-key]"

    private companion object {
        val KEY_PATTERN = Regex("^[a-z][a-z0-9_.-]{1,127}$")
    }
}

interface StringKeyValueStore {
    fun read(key: String): String?

    fun write(key: String, value: String): Boolean

    fun remove(key: String): Boolean
}

/**
 * Useful for tests and in-memory composition only. It deliberately stores
 * encoded ciphertext rather than plaintext when used with EncryptedStorage.
 */
class InMemoryStringKeyValueStore : StringKeyValueStore {
    private val lock = Any()
    private val values = LinkedHashMap<String, String>()

    override fun read(key: String): String? = synchronized(lock) { values[key] }

    override fun write(key: String, value: String): Boolean = synchronized(lock) {
        values[key] = value
        true
    }

    override fun remove(key: String): Boolean = synchronized(lock) {
        values.remove(key)
        true
    }
}

enum class CryptoFailure {
    KEY_UNAVAILABLE,
    OPERATION_FAILED,
}

sealed interface CryptoResult<out T> {
    data class Success<T>(val value: T) : CryptoResult<T>

    data class Failure(val reason: CryptoFailure) : CryptoResult<Nothing>
}

/**
 * Authenticated ciphertext with an explicit nonce. Both arrays are copied at
 * the boundary to prevent callers mutating a payload after it has been stored.
 */
class Ciphertext(nonce: ByteArray, bytes: ByteArray) {
    val nonce: ByteArray = nonce.copyOf()
    val bytes: ByteArray = bytes.copyOf()

    init {
        require(nonce.isNotEmpty()) { "Ciphertext nonce cannot be empty." }
        require(bytes.isNotEmpty()) { "Ciphertext bytes cannot be empty." }
    }

    override fun equals(other: Any?): Boolean =
        other is Ciphertext && nonce.contentEquals(other.nonce) && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = 31 * nonce.contentHashCode() + bytes.contentHashCode()

    override fun toString(): String =
        "Ciphertext(nonceLength=" + nonce.size + ", byteLength=" + bytes.size + ")"
}

interface AuthenticatedCipher {
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray): CryptoResult<Ciphertext>

    fun decrypt(ciphertext: Ciphertext, associatedData: ByteArray): CryptoResult<ByteArray>
}

enum class SecureStorageFailure {
    INPUT_TOO_LARGE,
    BACKING_STORE_FAILURE,
    MALFORMED_PAYLOAD,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
}

sealed interface SecureStorageResult<out T> {
    data class Success<T>(val value: T) : SecureStorageResult<T>

    data class Failure(val reason: SecureStorageFailure) : SecureStorageResult<Nothing>
}

interface EncryptedStorage {
    fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit>

    fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?>

    fun remove(key: SecureStorageKey): SecureStorageResult<Unit>
}

/**
 * Versioned authenticated encrypted storage over a string key-value backend.
 * The logical key is included as associated data, preventing a stored payload
 * from being replayed under another key in the same namespace.
 */
class AuthenticatedEncryptedStorage(
    private val backingStore: StringKeyValueStore,
    private val cipher: AuthenticatedCipher,
    private val namespace: String = DEFAULT_NAMESPACE,
) : EncryptedStorage {
    private val lock = Any()

    init {
        require(NAMESPACE_PATTERN.matches(namespace)) {
            "namespace must be a concise machine-readable identifier."
        }
    }

    override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> =
        synchronized(lock) {
            if (plaintext.size > MAX_PLAINTEXT_BYTES) {
                return@synchronized SecureStorageResult.Failure(SecureStorageFailure.INPUT_TOO_LARGE)
            }
            val ciphertext = when (
                val encryption = cipher.encrypt(plaintext.copyOf(), associatedDataFor(key))
            ) {
                is CryptoResult.Success -> encryption.value
                is CryptoResult.Failure -> {
                    return@synchronized SecureStorageResult.Failure(
                        SecureStorageFailure.ENCRYPTION_FAILED,
                    )
                }
            }
            val encoded = encode(ciphertext)
            val wrote = try {
                backingStore.write(storageKeyFor(key), encoded)
            } catch (_: RuntimeException) {
                false
            }
            if (!wrote) {
                SecureStorageResult.Failure(SecureStorageFailure.BACKING_STORE_FAILURE)
            } else {
                SecureStorageResult.Success(Unit)
            }
        }

    override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> = synchronized(lock) {
        val encoded = try {
            backingStore.read(storageKeyFor(key))
        } catch (_: RuntimeException) {
            return@synchronized SecureStorageResult.Failure(SecureStorageFailure.BACKING_STORE_FAILURE)
        } ?: return@synchronized SecureStorageResult.Success(null)

        val ciphertext = decode(encoded)
            ?: return@synchronized SecureStorageResult.Failure(SecureStorageFailure.MALFORMED_PAYLOAD)
        when (val decryption = cipher.decrypt(ciphertext, associatedDataFor(key))) {
            is CryptoResult.Success -> SecureStorageResult.Success(decryption.value.copyOf())
            is CryptoResult.Failure -> SecureStorageResult.Failure(SecureStorageFailure.DECRYPTION_FAILED)
        }
    }

    override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> = synchronized(lock) {
        val removed = try {
            backingStore.remove(storageKeyFor(key))
        } catch (_: RuntimeException) {
            false
        }
        if (removed) {
            SecureStorageResult.Success(Unit)
        } else {
            SecureStorageResult.Failure(SecureStorageFailure.BACKING_STORE_FAILURE)
        }
    }

    private fun storageKeyFor(key: SecureStorageKey): String = namespace + "." + key.value

    private fun associatedDataFor(key: SecureStorageKey): ByteArray =
        storageKeyFor(key).encodeToByteArray()

    private fun encode(ciphertext: Ciphertext): String =
        PAYLOAD_VERSION + SEPARATOR +
            BASE64_ENCODER.encodeToString(ciphertext.nonce) + SEPARATOR +
            BASE64_ENCODER.encodeToString(ciphertext.bytes)

    private fun decode(encoded: String): Ciphertext? {
        val pieces = encoded.split(SEPARATOR)
        if (pieces.size != 3 || pieces[0] != PAYLOAD_VERSION) {
            return null
        }
        return try {
            val nonce = BASE64_DECODER.decode(pieces[1])
            val bytes = BASE64_DECODER.decode(pieces[2])
            Ciphertext(nonce, bytes)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private companion object {
        const val DEFAULT_NAMESPACE = "apk_sentinel_secure_storage"
        const val MAX_PLAINTEXT_BYTES = 1_048_576
        const val PAYLOAD_VERSION = "v1"
        const val SEPARATOR = "|"
        val NAMESPACE_PATTERN = Regex("^[a-z][a-z0-9_.-]{1,127}$")
        val BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding()
        val BASE64_DECODER = Base64.getUrlDecoder()
    }
}
