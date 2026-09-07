package app.apksentinel.engine.tlsinspection

import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SecurityParameters
import org.bouncycastle.tls.TlsContext

/**
 * Samples a live BouncyCastle TLS connection for the secrets a key log needs.
 *
 * This exists because JSSE has no portable way to read a session's secrets. On Android the
 * default provider is Conscrypt, which keeps them inside BoringSSL where no Java reflection
 * can reach them, so a key log is only possible on a leg we drive with BouncyCastle.
 *
 * TLS 1.2 has one secret worth logging, the master secret, and it never changes.
 *
 * TLS 1.3 needs two per direction: the handshake traffic secret and then
 * `..._TRAFFIC_SECRET_0`, the application one Wireshark actually needs to read the traffic.
 * BouncyCastle spreads those across two fields and two [SecurityParameters] objects, and
 * moves them as the connection progresses - the handshake value stays in `trafficSecret*`
 * while the application value ends up in `baseKey*`, the base for later KeyUpdates. Rather
 * than encode that layout, this treats every field as a candidate and keeps the first two
 * DISTINCT values seen per direction, in order: first is the handshake secret, second is
 * `TRAFFIC_SECRET_0`. Later KeyUpdate values are ignored because Wireshark derives those
 * forward on its own.
 *
 * Sampling has to happen while the connection is being driven. BouncyCastle destroys a
 * secret once it has derived record keys from it, so a value read after the fact is often
 * already gone; [BcTlsServerLeg] samples between handshake messages for this reason.
 *
 * At most two secrets per direction are retained, and [clear] zeroizes them.
 */
class BcTlsKeyLogSampler {

    private var clientRandom: ByteArray? = null
    private var masterSecretEmitted = false
    private val clientSeen = mutableListOf<ByteArray>()
    private val serverSeen = mutableListOf<ByteArray>()

    /**
     * Reads whatever is newly available on [context]. Returns one entry per newly observed
     * key-log phase, or an empty list when nothing changed - the normal case for most calls.
     */
    fun sample(context: TlsContext?): List<TlsKeyLogSecrets> {
        if (context == null) return emptyList()
        // Both parameter objects matter: during the handshake only the handshake object
        // exists, and afterwards the connection object carries values the other one lost.
        return buildList {
            addAll(sampleFrom(runCatching { context.securityParametersHandshake }.getOrNull()))
            addAll(sampleFrom(runCatching { context.securityParametersConnection }.getOrNull()))
        }
    }

    private fun sampleFrom(parameters: SecurityParameters?): List<TlsKeyLogSecrets> {
        if (parameters == null) return emptyList()
        val random = clientRandom
            ?: parameters.clientRandom
                ?.takeIf { it.size == TlsKeyLogSecrets.CLIENT_RANDOM_BYTES }
                ?.copyOf()
                ?.also { clientRandom = it }
            ?: return emptyList()

        val found = mutableListOf<TlsKeyLogSecrets>()

        if (!masterSecretEmitted && !isTls13(parameters)) {
            // A TLS 1.3 session also populates masterSecret, but a CLIENT_RANDOM line there
            // is meaningless and makes Wireshark report a failed decryption rather than none.
            val master = BcTlsSecretAccess.copyOf(parameters.masterSecret)
            if (master != null && master.isNotEmpty()) {
                masterSecretEmitted = true
                found += TlsKeyLogSecrets(clientRandom = random.copyOf(), masterSecret = master)
            }
        }

        record(clientSeen, parameters.trafficSecretClient, parameters.baseKeyClient) { phase, secret ->
            found += when (phase) {
                0 -> TlsKeyLogSecrets(random.copyOf(), clientHandshakeTrafficSecret = secret)
                else -> TlsKeyLogSecrets(random.copyOf(), clientApplicationTrafficSecret = secret)
            }
        }
        record(serverSeen, parameters.trafficSecretServer, parameters.baseKeyServer) { phase, secret ->
            found += when (phase) {
                0 -> TlsKeyLogSecrets(random.copyOf(), serverHandshakeTrafficSecret = secret)
                else -> TlsKeyLogSecrets(random.copyOf(), serverApplicationTrafficSecret = secret)
            }
        }
        return found
    }

    /** Adds any candidate not already seen, up to the two phases a key log needs. */
    private inline fun record(
        seen: MutableList<ByteArray>,
        vararg candidates: org.bouncycastle.tls.crypto.TlsSecret?,
        emit: (phase: Int, secret: ByteArray) -> Unit,
    ) {
        candidates.forEach { candidate ->
            if (seen.size >= PHASES) return
            val bytes = BcTlsSecretAccess.copyOf(candidate) ?: return@forEach
            if (bytes.isEmpty() || seen.any { it.contentEquals(bytes) }) {
                bytes.fill(0)
                return@forEach
            }
            seen += bytes.copyOf()
            emit(seen.size - 1, bytes)
        }
    }

    /** Zeroizes every retained value. */
    fun clear() {
        clientRandom?.fill(0)
        clientSeen.forEach { it.fill(0) }
        serverSeen.forEach { it.fill(0) }
        clientRandom = null
        clientSeen.clear()
        serverSeen.clear()
        masterSecretEmitted = false
    }

    private fun isTls13(parameters: SecurityParameters): Boolean = runCatching {
        val version = parameters.negotiatedVersion ?: return false
        ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version)
    }.getOrDefault(false)

    private companion object {
        /** The handshake traffic secret and TRAFFIC_SECRET_0. KeyUpdates are derived by the reader. */
        const val PHASES = 2
    }
}
