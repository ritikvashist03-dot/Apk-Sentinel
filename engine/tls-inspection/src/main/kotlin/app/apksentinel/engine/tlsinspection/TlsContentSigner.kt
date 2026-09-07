package app.apksentinel.engine.tlsinspection

import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import java.io.OutputStream
import java.security.PrivateKey
import java.security.Signature

/**
 * Signs through the platform JCA provider so Android Keystore private keys
 * remain non-exportable. Bouncy Castle supplies the X.509 builder/encoding;
 * no private-key bytes are requested.
 */
object TlsContentSignerFactory {
    fun create(signatureAlgorithm: String, privateKey: PrivateKey): ContentSigner {
        val signature = Signature.getInstance(signatureAlgorithm).apply { initSign(privateKey) }
        return object : ContentSigner {
            private val output = object : OutputStream() {
                override fun write(oneByte: Int) = signature.update(oneByte.toByte())
                override fun write(bytes: ByteArray, offset: Int, length: Int) = signature.update(bytes, offset, length)
            }

            override fun getAlgorithmIdentifier() =
                DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm)

            override fun getOutputStream(): OutputStream = output
            override fun getSignature(): ByteArray = signature.sign()
        }
    }
}
