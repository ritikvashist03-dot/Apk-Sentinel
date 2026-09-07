package app.apksentinel.core.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.ProviderException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-GCM implementation whose key is created and addressed through Android
 * Keystore. Device-specific Keystore implementations may differ; this class
 * does not detect, request, or claim hardware-backed key storage.
 */
class AndroidKeystoreAesGcmCipher(
    private val keyAlias: String,
) : AuthenticatedCipher {
    init {
        require(ALIAS_PATTERN.matches(keyAlias)) {
            "Keystore aliases must be concise machine-readable identifiers."
        }
    }

    override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): CryptoResult<Ciphertext> {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            cipher.updateAAD(associatedData)
            val encrypted = cipher.doFinal(plaintext)
            val nonce = cipher.iv ?: return CryptoResult.Failure(CryptoFailure.OPERATION_FAILED)
            CryptoResult.Success(Ciphertext(nonce, encrypted))
        } catch (_: GeneralSecurityException) {
            CryptoResult.Failure(CryptoFailure.KEY_UNAVAILABLE)
        } catch (_: ProviderException) {
            CryptoResult.Failure(CryptoFailure.OPERATION_FAILED)
        }
    }

    override fun decrypt(ciphertext: Ciphertext, associatedData: ByteArray): CryptoResult<ByteArray> {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateKey(),
                GCMParameterSpec(GCM_TAG_LENGTH_BITS, ciphertext.nonce),
            )
            cipher.updateAAD(associatedData)
            CryptoResult.Success(cipher.doFinal(ciphertext.bytes))
        } catch (_: GeneralSecurityException) {
            CryptoResult.Failure(CryptoFailure.OPERATION_FAILED)
        } catch (_: ProviderException) {
            CryptoResult.Failure(CryptoFailure.OPERATION_FAILED)
        }
    }

    /** Deletes this app-owned alias for an explicit erase/reset flow. */
    fun deleteKey(): Boolean = try {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (keyStore.containsAlias(keyAlias)) keyStore.deleteEntry(keyAlias)
        !keyStore.containsAlias(keyAlias)
    } catch (_: Exception) {
        // AndroidKeyStore.load(null) may surface provider-specific checked or
        // runtime failures. An erase flow must report failure, not crash.
        false
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = keyStore.getKey(keyAlias, null)
        if (existing != null) {
            return existing as? SecretKey
                ?: throw KeyStoreException("Existing key has an incompatible type.")
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER,
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(KEY_SIZE_BITS)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .build()
        keyGenerator.init(parameterSpec)
        return keyGenerator.generateKey()
    }

    private companion object {
        val ALIAS_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_.-]{1,127}$")
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_SIZE_BITS = 256
        const val GCM_TAG_LENGTH_BITS = 128
    }
}
