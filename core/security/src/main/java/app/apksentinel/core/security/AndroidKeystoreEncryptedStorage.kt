package app.apksentinel.core.security

import android.content.SharedPreferences

/**
 * Synchronous SharedPreferences backend for ciphertext. Commit is intentional:
 * callers receive a deterministic success or failure result before proceeding.
 */
class SharedPreferencesStringKeyValueStore(
    private val preferences: SharedPreferences,
) : StringKeyValueStore {
    override fun read(key: String): String? = preferences.getString(key, null)

    override fun write(key: String, value: String): Boolean =
        preferences.edit().putString(key, value).commit()

    override fun remove(key: String): Boolean =
        preferences.edit().remove(key).commit()
}

/**
 * Ready-to-compose Android storage adapter. The ciphertext is stored in the
 * supplied SharedPreferences while encryption keys remain managed by Android
 * Keystore through AndroidKeystoreAesGcmCipher.
 */
class AndroidKeystoreEncryptedStorage(
    preferences: SharedPreferences,
    keyAlias: String,
    namespace: String = "apk_sentinel_secure_storage",
) : EncryptedStorage {
    private val keystoreCipher = AndroidKeystoreAesGcmCipher(keyAlias)
    private val delegate = AuthenticatedEncryptedStorage(
        backingStore = SharedPreferencesStringKeyValueStore(preferences),
        cipher = keystoreCipher,
        namespace = namespace,
    )

    override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> =
        delegate.write(key, plaintext)

    override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> =
        delegate.read(key)

    override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> =
        delegate.remove(key)

    /** Use only after every value protected by this dedicated alias is removed. */
    fun deleteEncryptionKey(): Boolean = keystoreCipher.deleteKey()
}
