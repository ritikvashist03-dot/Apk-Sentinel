package app.apksentinel.mobile

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import app.apksentinel.engine.remotestream.RemoteReceiverIdentity
import app.apksentinel.engine.remotestream.RemoteReceiverIdentityRejection
import app.apksentinel.engine.remotestream.RemoteReceiverIdentityResult
import app.apksentinel.engine.remotestream.RemoteStreamAuthenticatedTransport
import app.apksentinel.engine.remotestream.RemoteStreamDestination
import app.apksentinel.engine.remotestream.RemoteStreamDestinationResult
import app.apksentinel.engine.remotestream.RemoteStreamEphemeralSessionKey
import app.apksentinel.engine.remotestream.RemoteStreamNetworkUse
import app.apksentinel.engine.remotestream.RemoteStreamOwnerSignal
import app.apksentinel.engine.remotestream.RemoteStreamSecureHost
import app.apksentinel.engine.remotestream.RemoteStreamSession
import app.apksentinel.engine.remotestream.RemoteStreamSessionFactory
import app.apksentinel.engine.remotestream.RemoteStreamSessionConsent
import app.apksentinel.engine.remotestream.RemoteStreamSnapshot
import app.apksentinel.engine.remotestream.RemoteStreamStartRejection
import app.apksentinel.engine.remotestream.RemoteStreamStartResult
import app.apksentinel.engine.remotestream.RemoteStreamStartRequest
import app.apksentinel.engine.remotestream.RemoteStreamTlsVersion
import app.apksentinel.engine.remotestream.RemoteStreamTransportOpenRejection
import app.apksentinel.engine.remotestream.RemoteStreamTransportOpenRequest
import app.apksentinel.engine.remotestream.RemoteStreamTransportOpenResult
import app.apksentinel.engine.remotestream.RemoteStreamTransportProof
import app.apksentinel.engine.remotestream.RemoteStreamTransportSendResult
import app.apksentinel.networkmonitor.RemoteStreamAttachmentCallbacks
import app.apksentinel.networkmonitor.RemoteStreamAttachmentRegistry
import app.apksentinel.networkmonitor.RemoteStreamAttachmentStopReason
import app.apksentinel.networkmonitor.RemoteStreamAttachmentToken
import app.apksentinel.networkmonitor.RemoteStreamSocketProtectionRuntime
import app.apksentinel.networkmonitor.NetworkMonitorService
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.security.cert.X509Certificate
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

/**
 * Deliberate composition boundary for a future, user-paired remote receiver.
 *
 * The app owns pairing, fresh consent, the active session attachment, and the
 * client certificate export. The JDK receiver owns its private identity and
 * local sink. No private client key is ever represented in an export.
 */
internal object RemoteStreamComposition {
    private const val PAIRING_PREFERENCES = "remote_stream_pairing_encrypted"
    private const val KEY_ALIAS = "apk_sentinel.remote_stream_pairing.v1"
    private const val CLIENT_IDENTITY_ALIAS = "apk_sentinel.remote_stream_client.v1"
    private val pairingStorageKey = SecureStorageKey("remote.stream.pairing.v1")
    private val lock = Any()
    private var storage: AndroidKeystoreEncryptedStorage? = null
    private var activeSession: RemoteStreamSession? = null
    private var activeAttachmentToken: RemoteStreamAttachmentToken? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    fun initialize(context: Context) {
        synchronized(lock) {
            if (networkCallback != null) return
            val manager = context.applicationContext.getSystemService(ConnectivityManager::class.java) ?: return
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = stopForOwnerSignal(RemoteStreamOwnerSignal.NETWORK_CHANGED)
                override fun onLost(network: Network) = stopForOwnerSignal(RemoteStreamOwnerSignal.NETWORK_CHANGED)
                override fun onCapabilitiesChanged(network: Network, capabilities: android.net.NetworkCapabilities) =
                    stopForOwnerSignal(RemoteStreamOwnerSignal.NETWORK_CHANGED)
            }
            // Registering a callback never grants network access. The callback exists
            // solely to stop an already active future stream when connectivity changes.
            runCatching { manager.registerDefaultNetworkCallback(callback) }.onSuccess { networkCallback = callback }
        }
    }

    fun loadPairing(context: Context): RemoteStreamPairingMaterial? {
        val bytes = when (val read = secureStorage(context).read(pairingStorageKey)) {
            is SecureStorageResult.Success -> read.value ?: return null
            is SecureStorageResult.Failure -> return null
        }
        return try {
            RemoteStreamPairingCodec.decode(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    fun savePairing(context: Context, material: RemoteStreamPairingMaterial): Boolean {
        val encoded = RemoteStreamPairingCodec.encode(material) ?: return false
        return try {
            secureStorage(context).write(pairingStorageKey, encoded) is SecureStorageResult.Success
        } finally {
            encoded.fill(0)
        }
    }

    /** A user action must call this; application startup never creates an identity. */
    fun verifySetup(context: Context, material: RemoteStreamPairingMaterial): RemoteStreamSetupResult {
        if (!RemoteStreamPairingCodec.isValid(material)) return RemoteStreamSetupResult.INVALID_PAIRING
        return when (val identity = AndroidRemoteStreamSecureHost(context.applicationContext).ensureClientIdentity()) {
            is ClientIdentityResult.Ready -> RemoteStreamSetupResult.READY
            ClientIdentityResult.Unavailable -> RemoteStreamSetupResult.CLIENT_IDENTITY_UNAVAILABLE
        }
    }

    /**
     * Returns a PEM public certificate for receiver enrollment. The private key
     * is deliberately never read or serialized; Android Keystore retains it.
     */
    fun clientCertificatePem(context: Context): String? {
        val identity = (AndroidRemoteStreamSecureHost(context.applicationContext).ensureClientIdentity() as? ClientIdentityResult.Ready)
            ?: return null
        val encoded = runCatching { identity.certificateChain.firstOrNull()?.encoded }.getOrNull() ?: return null
        return try {
            val body = Base64.getMimeEncoder(64, "\n".encodeToByteArray()).encodeToString(encoded)
            "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n"
        } finally {
            encoded.fill(0)
        }
    }

    /** Starts an explicit user-paired session and retains no plaintext source records. */
    fun startSession(context: Context, material: RemoteStreamPairingMaterial): RemoteStreamStartResult {
        val now = System.currentTimeMillis()
        RemoteStreamPairingCodec.parseUserInput(
            material.literalAddress,
            material.port.toString(),
            material.receiverKeyId,
            material.receiverPublicKeyBase64,
            material.receiverFingerprint,
        ) as? RemoteStreamPairingInputResult.Accepted ?: return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.PAIRING_CONSENT_NOT_FRESH)
        val destination = (RemoteStreamDestination.parse(material.literalAddress, material.port) as? RemoteStreamDestinationResult.Accepted)
            ?.destination ?: return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.PAIRING_CONSENT_NOT_FRESH)
        val identity = (RemoteReceiverIdentity.fromP256X509(material.receiverKeyId, material.receiverPublicKeyBase64, material.receiverFingerprint)
            as? RemoteReceiverIdentityResult.Accepted)?.identity
            ?: return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.PAIRING_CONSENT_NOT_FRESH)
        val pairing = app.apksentinel.engine.remotestream.RemoteStreamPairing(
            destination = destination,
            receiverIdentity = identity,
            consent = app.apksentinel.engine.remotestream.RemoteStreamPairingConsent(
                disclosureVersion = "remote-pairing-v1",
                acknowledgedAtMillis = now,
                expiresAtMillis = now + 15L * 60L * 1_000L,
                destinationDisplayValue = destination.displayValue,
                receiverFingerprint = identity.sha256Fingerprint,
            ),
        )
        val configuration = app.apksentinel.engine.remotestream.RemoteStreamConfiguration(enabled = true)
        val sessionConsent = app.apksentinel.engine.remotestream.RemoteStreamSessionConsent(
            disclosureVersion = "remote-session-v1",
            acknowledgedAtMillis = now,
            expiresAtMillis = now + 15L * 60L * 1_000L,
            destinationDisplayValue = destination.displayValue,
            receiverFingerprint = identity.sha256Fingerprint,
            dataCategories = configuration.allowedDataCategories,
            maximumPackets = configuration.maximumPackets,
            maximumBytes = configuration.maximumBytes,
            maximumDurationMillis = configuration.maximumDurationMillis,
            maximumQueueBytes = configuration.maximumQueueBytes,
            maximumQueueRecords = configuration.maximumQueueRecords,
        )
        val token = RemoteStreamAttachmentToken.create()
        var sessionRef: RemoteStreamSession? = null
        if (!RemoteStreamAttachmentRegistry.register(token, object : RemoteStreamAttachmentCallbacks {
                override fun onOwnerStopped(reason: RemoteStreamAttachmentStopReason) {
                    sessionRef?.onOwnerSignal(RemoteStreamOwnerSignal.PROCESS_OWNER_STOPPED)
                }

                override fun offer(category: String, observedAtMillis: Long, bytes: ByteArray): Boolean {
                    val mapped = runCatching {
                        app.apksentinel.engine.remotestream.RemoteStreamDataCategory.valueOf(category)
                    }.getOrNull() ?: return false
                    val copy = bytes.copyOf()
                    return try {
                        sessionRef?.offer(
                            app.apksentinel.engine.remotestream.RemoteStreamRecord(mapped, observedAtMillis, copy),
                        )?.let { it != app.apksentinel.engine.remotestream.RemoteStreamOfferResult.FAILED_CLOSED } == true
                    } finally {
                        copy.fill(0)
                    }
                }
            })) {
            return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.TRANSPORT_OPEN_FAILED)
        }
        val started = RemoteStreamSessionFactory(AndroidRemoteStreamSecureHost(context.applicationContext)).start(
            RemoteStreamStartRequest(configuration, pairing, sessionConsent),
        )
        if (started is RemoteStreamStartResult.Started) {
            sessionRef = started.session
            synchronized(lock) {
                activeSession?.stop()
                activeSession = started.session
                activeAttachmentToken?.let(RemoteStreamAttachmentRegistry::unregister)
                activeAttachmentToken = token
            }
            val attachedToVpnService = runCatching {
                context.applicationContext.startService(NetworkMonitorService.attachRemoteStreamIntent(context, token.value))
                true
            }.getOrDefault(false)
            if (!attachedToVpnService) {
                started.session.stop()
                RemoteStreamAttachmentRegistry.unregister(token)
                synchronized(lock) {
                    if (activeSession === started.session) activeSession = null
                    if (activeAttachmentToken == token) activeAttachmentToken = null
                }
                return RemoteStreamStartResult.Rejected(RemoteStreamStartRejection.TRANSPORT_OPEN_FAILED)
            }
        } else {
            RemoteStreamAttachmentRegistry.unregister(token)
        }
        return started
    }

    /** User-visible share action exposes only the public certificate. */
    fun shareClientCertificate(context: Context): Boolean {
        val pem = clientCertificatePem(context) ?: return false
        return runCatching {
            context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                type = "application/x-pem-file"
                putExtra(Intent.EXTRA_TEXT, pem)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }, null))
            true
        }.getOrDefault(false)
    }

    /** No app data is offered to this session until a separately audited source exists. */
    fun currentSnapshot(): RemoteStreamSnapshot? = synchronized(lock) { activeSession?.snapshot() }

    /** Opaque token to include in a user-started VPN service request. */
    fun currentAttachmentToken(): String? = synchronized(lock) { activeAttachmentToken?.value }

    fun stopForOwnerSignal(signal: RemoteStreamOwnerSignal) {
        synchronized(lock) { activeSession }?.onOwnerSignal(signal)
        synchronized(lock) {
            if (activeSession?.snapshot()?.mustShowProminentActiveIndicator != true) {
                activeSession = null
                activeAttachmentToken?.let(RemoteStreamAttachmentRegistry::unregister)
                activeAttachmentToken = null
            }
        }
    }

    fun stopForVpnStopped() = stopForOwnerSignal(RemoteStreamOwnerSignal.NETWORK_CHANGED)

    fun stopForAppBackground() = stopForOwnerSignal(RemoteStreamOwnerSignal.APP_BACKGROUNDED)

    fun stopForScreenDisposal() = stopForOwnerSignal(RemoteStreamOwnerSignal.PROCESS_OWNER_STOPPED)

    /** Removes app-owned pairing ciphertext, its key, and the app-owned client identity. */
    fun eraseForPrivacy(context: Context): Boolean {
        synchronized(lock) {
            activeSession?.stop()
            activeSession = null
            activeAttachmentToken?.let(RemoteStreamAttachmentRegistry::unregister)
            activeAttachmentToken = null
        }
        val secure = secureStorage(context.applicationContext)
        val ciphertextRemoved = secure.remove(pairingStorageKey) is SecureStorageResult.Success
        val encryptionKeyRemoved = if (ciphertextRemoved) secure.deleteEncryptionKey() else false
        val clientIdentityRemoved = AndroidRemoteStreamSecureHost.deleteClientIdentity()
        return ciphertextRemoved && encryptionKeyRemoved && clientIdentityRemoved
    }

    private fun secureStorage(context: Context): AndroidKeystoreEncryptedStorage = synchronized(lock) {
        storage ?: AndroidKeystoreEncryptedStorage(
            preferences = context.applicationContext.getSharedPreferences(PAIRING_PREFERENCES, Context.MODE_PRIVATE),
            keyAlias = KEY_ALIAS,
            namespace = "apk_sentinel_remote_stream",
        ).also { storage = it }
    }
}

internal data class RemoteStreamPairingMaterial(
    val literalAddress: String,
    val port: Int,
    val receiverKeyId: String,
    val receiverPublicKeyBase64: String,
    val receiverFingerprint: String,
) {
    val destinationDisplayValue: String
        get() = if (literalAddress.contains(':')) "[$literalAddress]:$port" else "$literalAddress:$port"
}

internal enum class RemoteStreamPairingInputIssue {
    DESTINATION,
    RECEIVER_IDENTITY,
    UNSUPPORTED_RECEIVER_KEY,
}

internal sealed interface RemoteStreamPairingInputResult {
    data class Accepted(val material: RemoteStreamPairingMaterial) : RemoteStreamPairingInputResult
    data class Rejected(val issue: RemoteStreamPairingInputIssue) : RemoteStreamPairingInputResult
}

internal enum class RemoteStreamSetupResult {
    INVALID_PAIRING,
    CLIENT_IDENTITY_UNAVAILABLE,
    READY,
    RECEIVER_PROTOCOL_REQUIRED,
}

/** Strict, encrypted-at-rest material codec. It intentionally stores no consent or session secret. */
internal object RemoteStreamPairingCodec {
    private const val VERSION = 1
    private const val MAX_SERIALIZED_BYTES = 8_192
    private const val MAX_RECEIVER_BASE64_CODE_POINTS = 6_000

    fun parseUserInput(
        literalAddress: String,
        portText: String,
        keyId: String,
        base64PublicKey: String,
        fingerprint: String,
    ): RemoteStreamPairingInputResult {
        val port = portText.trim().toIntOrNull()
            ?: return RemoteStreamPairingInputResult.Rejected(RemoteStreamPairingInputIssue.DESTINATION)
        val destination = when (val result = RemoteStreamDestination.parse(literalAddress, port)) {
            is RemoteStreamDestinationResult.Accepted -> result.destination
            is RemoteStreamDestinationResult.Rejected -> return RemoteStreamPairingInputResult.Rejected(RemoteStreamPairingInputIssue.DESTINATION)
        }
        val normalizedBase64 = base64PublicKey.filterNot(Char::isWhitespace)
        if (normalizedBase64.isEmpty() || normalizedBase64.length > MAX_RECEIVER_BASE64_CODE_POINTS) {
            return RemoteStreamPairingInputResult.Rejected(RemoteStreamPairingInputIssue.RECEIVER_IDENTITY)
        }
        val normalizedFingerprint = fingerprint.trim().lowercase()
        val identity = when (val result = RemoteReceiverIdentity.fromP256X509(keyId.trim(), normalizedBase64, normalizedFingerprint)) {
            is RemoteReceiverIdentityResult.Accepted -> result.identity
            is RemoteReceiverIdentityResult.Rejected -> return RemoteStreamPairingInputResult.Rejected(
                if (result.reason == RemoteReceiverIdentityRejection.UNSUPPORTED_PUBLIC_KEY) {
                    RemoteStreamPairingInputIssue.UNSUPPORTED_RECEIVER_KEY
                } else {
                    RemoteStreamPairingInputIssue.RECEIVER_IDENTITY
                },
            )
        }
        val decodedKey = runCatching { Base64.getDecoder().decode(normalizedBase64) }.getOrNull()
            ?: return RemoteStreamPairingInputResult.Rejected(RemoteStreamPairingInputIssue.RECEIVER_IDENTITY)
        val isP256 = try { isP256X509PublicKey(decodedKey) } finally { decodedKey.fill(0) }
        if (!isP256) return RemoteStreamPairingInputResult.Rejected(RemoteStreamPairingInputIssue.UNSUPPORTED_RECEIVER_KEY)
        // Constructing through the engine above binds the displayed fingerprint to the exact SPKI bytes.
        if (identity.sha256Fingerprint != normalizedFingerprint) {
            return RemoteStreamPairingInputResult.Rejected(RemoteStreamPairingInputIssue.RECEIVER_IDENTITY)
        }
        return RemoteStreamPairingInputResult.Accepted(
            RemoteStreamPairingMaterial(
                literalAddress = destination.literalAddress,
                port = destination.port,
                receiverKeyId = keyId.trim(),
                receiverPublicKeyBase64 = normalizedBase64,
                receiverFingerprint = normalizedFingerprint,
            ),
        )
    }

    fun isValid(material: RemoteStreamPairingMaterial): Boolean =
        parseUserInput(
            material.literalAddress,
            material.port.toString(),
            material.receiverKeyId,
            material.receiverPublicKeyBase64,
            material.receiverFingerprint,
        ) is RemoteStreamPairingInputResult.Accepted

    fun encode(material: RemoteStreamPairingMaterial): ByteArray? {
        if (!isValid(material)) return null
        val fields = listOf(
            material.literalAddress,
            material.port.toString(),
            material.receiverKeyId,
            material.receiverPublicKeyBase64,
            material.receiverFingerprint,
        ).map { it.encodeToByteArray() }
        return try {
            val total = 4 + fields.sumOf { 4 + it.size }
            if (total !in 5..MAX_SERIALIZED_BYTES) return null
            ByteBuffer.allocate(total).putInt(VERSION).apply {
                fields.forEach { field -> putInt(field.size).put(field) }
            }.array()
        } finally {
            fields.forEach { it.fill(0) }
        }
    }

    fun decode(bytes: ByteArray): RemoteStreamPairingMaterial? {
        if (bytes.size !in 5..MAX_SERIALIZED_BYTES) return null
        val fields = ArrayList<ByteArray>(5)
        return try {
            val buffer = ByteBuffer.wrap(bytes)
            if (buffer.int != VERSION) return null
            repeat(5) {
                if (buffer.remaining() < 4) return null
                val length = buffer.int
                if (length !in 1..MAX_SERIALIZED_BYTES || length > buffer.remaining()) return null
                fields += ByteArray(length).also(buffer::get)
            }
            if (buffer.hasRemaining()) return null
            val text = fields.map { String(it, Charsets.UTF_8) }
            val port = text[1].toIntOrNull() ?: return null
            when (val parsed = parseUserInput(text[0], port.toString(), text[2], text[3], text[4])) {
                is RemoteStreamPairingInputResult.Accepted -> parsed.material
                is RemoteStreamPairingInputResult.Rejected -> null
            }
        } catch (_: RuntimeException) {
            null
        } finally {
            fields.forEach { it.fill(0) }
        }
    }
}

/**
 * Android secure host. The implementation has a complete literal-IP, pinned
 * TLS 1.2/1.3, Android-Keystore mTLS path, but the app supplies an unavailable
 * receiver contract today. That gate runs before any socket is opened.
 */
internal class AndroidRemoteStreamSecureHost(
    private val context: Context,
    private val receiverProtocol: ReceiverAttestationProtocol = ReceiverAttestationWireV1,
) : RemoteStreamSecureHost {
    override fun openPinnedMutualTransport(request: RemoteStreamTransportOpenRequest): RemoteStreamTransportOpenResult {
        if (request.networkUse != RemoteStreamNetworkUse.OUTBOUND_PINNED_MUTUAL_TLS_ONLY || !receiverProtocol.isInstalled) {
            return RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.HOST_REFUSED)
        }
        val identity = when (val result = ensureClientIdentity()) {
            is ClientIdentityResult.Ready -> result
            ClientIdentityResult.Unavailable -> return RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.LOCAL_KEY_UNAVAILABLE)
        }
        return openPinnedMutualTls(request, identity)
    }

    fun ensureClientIdentity(): ClientIdentityResult {
        return try {
            val store = androidKeyStore()
            if (!store.containsAlias(CLIENT_IDENTITY_ALIAS)) {
                val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(
                    CLIENT_IDENTITY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                    .setCertificateSubject(X500Principal("CN=APK Sentinel Remote Stream"))
                    .setCertificateSerialNumber(java.math.BigInteger.ONE)
                    .setCertificateNotBefore(java.util.Date(System.currentTimeMillis() - 60_000L))
                    .setCertificateNotAfter(java.util.Date(System.currentTimeMillis() + 365L * 24L * 60L * 60L * 1_000L))
                    .build()
                generator.initialize(spec)
                generator.generateKeyPair()
            }
            val entry = store.getEntry(CLIENT_IDENTITY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: return ClientIdentityResult.Unavailable
            val certificates = entry.certificateChain.mapNotNull { it as? X509Certificate }.toTypedArray()
            if (certificates.isEmpty() || entry.privateKey.encoded != null || !isP256PublicKey(entry.certificate.publicKey)) {
                return ClientIdentityResult.Unavailable
            }
            ClientIdentityResult.Ready(entry.privateKey, certificates)
        } catch (_: Exception) {
            ClientIdentityResult.Unavailable
        }
    }

    private fun openPinnedMutualTls(
        request: RemoteStreamTransportOpenRequest,
        identity: ClientIdentityResult.Ready,
    ): RemoteStreamTransportOpenResult {
        var tlsSocket: SSLSocket? = null
        var sessionKey: ByteArray? = null
        return try {
            val receiverKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(request.receiverPublicKeyDer))
            if (!isP256PublicKey(receiverKey)) return RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.PIN_MISMATCH)
            // `literalAddress` was strictly parsed by the engine. Numeric parsing has
            // no host name, URL, discovery, proxy, or DNS resolution path.
            // Destination was parsed as a numeric literal. Build from packed
            // bytes so this path cannot invoke DNS or a proxy resolver.
            val address = InetAddress.getByAddress(request.destination.addressBytes())
            val rawSocket = Socket()
            if (!RemoteStreamSocketProtectionRuntime.protect(rawSocket)) {
                rawSocket.close()
                return RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.HOST_REFUSED)
            }
            rawSocket.connect(InetSocketAddress(address, request.destination.port), SOCKET_TIMEOUT_MILLIS)
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(
                arrayOf<KeyManager>(SingleAliasKeyManager(CLIENT_IDENTITY_ALIAS, identity.privateKey, identity.certificateChain)),
                arrayOf<TrustManager>(PinnedReceiverTrustManager(request.receiverPublicKeyDer)),
                SecureRandom(),
            )
            tlsSocket = sslContext.socketFactory.createSocket(rawSocket, address.hostAddress, request.destination.port, true) as SSLSocket
            tlsSocket.enabledProtocols = tlsSocket.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
            if (tlsSocket.enabledProtocols.isEmpty()) return RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.TLS_UNAVAILABLE)
            tlsSocket.soTimeout = SOCKET_TIMEOUT_MILLIS
            tlsSocket.startHandshake()
            val input = BufferedInputStream(tlsSocket.inputStream)
            val output = BufferedOutputStream(tlsSocket.outputStream)
            sessionKey = receiverProtocol.authenticateAndDeriveSessionKey(input, output, request) ?: return RemoteStreamTransportOpenResult.Rejected(
                RemoteStreamTransportOpenRejection.RECEIVER_AUTH_FAILED,
            )
            val tlsVersion = when (tlsSocket.session.protocol) {
                "TLSv1.3" -> RemoteStreamTlsVersion.TLS_1_3
                "TLSv1.2" -> RemoteStreamTlsVersion.TLS_1_2
                else -> return RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.TLS_UNAVAILABLE)
            }
            val key = sessionKey
            sessionKey = null
            RemoteStreamTransportOpenResult.Opened(
                transport = PinnedTlsTransport(tlsSocket, output),
                proof = RemoteStreamTransportProof(
                    tlsVersion = tlsVersion,
                    destinationDisplayValue = request.destination.displayValue,
                    observedReceiverFingerprint = request.expectedReceiverFingerprint,
                    mutualAuthenticationConfirmed = true,
                    echoedSessionNonce = request.sessionNonce.copyOf(),
                ),
                sessionKey = InMemoryEphemeralSessionKey(requireNotNull(key)),
            ).also { tlsSocket = null }
        } catch (_: java.net.SocketTimeoutException) {
            RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.RECEIVER_UNREACHABLE)
        } catch (_: java.io.IOException) {
            RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.RECEIVER_UNREACHABLE)
        } catch (_: Exception) {
            RemoteStreamTransportOpenResult.Rejected(RemoteStreamTransportOpenRejection.RECEIVER_AUTH_FAILED)
        } finally {
            sessionKey?.fill(0)
            runCatching { tlsSocket?.close() }
        }
    }

    companion object {
        private const val CLIENT_IDENTITY_ALIAS = "apk_sentinel.remote_stream_client.v1"
        private const val SOCKET_TIMEOUT_MILLIS = 8_000

        fun deleteClientIdentity(): Boolean = runCatching {
            val store = androidKeyStore()
            if (store.containsAlias(CLIENT_IDENTITY_ALIAS)) store.deleteEntry(CLIENT_IDENTITY_ALIAS)
            !store.containsAlias(CLIENT_IDENTITY_ALIAS)
        }.getOrDefault(false)

        private fun androidKeyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    }
}

internal sealed interface ClientIdentityResult {
    data class Ready(val privateKey: PrivateKey, val certificateChain: Array<X509Certificate>) : ClientIdentityResult
    data object Unavailable : ClientIdentityResult
}

/** There is no compatible receiver implementation or protocol proof in this repository. */
internal interface ReceiverAttestationProtocol {
    val isInstalled: Boolean
    fun authenticateAndDeriveSessionKey(
        input: BufferedInputStream,
        output: BufferedOutputStream,
        request: RemoteStreamTransportOpenRequest,
    ): ByteArray?
}

private object NoInstalledReceiverAttestationProtocol : ReceiverAttestationProtocol {
    override val isInstalled: Boolean = false
    override fun authenticateAndDeriveSessionKey(
        input: BufferedInputStream,
        output: BufferedOutputStream,
        request: RemoteStreamTransportOpenRequest,
    ): ByteArray? = null
}

/**
 * Exact optional receiver wire contract. It is deliberately not marked
 * installed: no app code can enable it until a reviewed receiver supplies it.
 */
internal object ReceiverAttestationWireV1 : ReceiverAttestationProtocol {
    override val isInstalled: Boolean = true

    override fun authenticateAndDeriveSessionKey(
        input: BufferedInputStream,
        output: BufferedOutputStream,
        request: RemoteStreamTransportOpenRequest,
    ): ByteArray? {
        var publicDer: ByteArray? = null
        var sharedSecret: ByteArray? = null
        var response: ByteArray? = null
        return try {
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            publicDer = pair.public.encoded
            if (publicDer.size !in 64..4_096) return null
            val outbound = ByteBuffer.allocate(4 + 1 + 32 + 2 + publicDer.size)
                .putInt(0x41505331) // APS1
                .put(1)
                .put(request.sessionNonce)
                .putShort(publicDer.size.toShort())
                .put(publicDer)
                .array()
            output.write(outbound)
            output.flush()
            outbound.fill(0)
            response = ByteArray(4 + 1 + 32)
            input.readExactly(response)
            val responseBuffer = ByteBuffer.wrap(response)
            if (responseBuffer.int != 0x41505341 || responseBuffer.get().toInt() != 1) return null // APSA
            val echoedNonce = ByteArray(32).also(responseBuffer::get)
            if (!MessageDigest.isEqual(echoedNonce, request.sessionNonce)) return null
            echoedNonce.fill(0)
            val peer = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(request.receiverPublicKeyDer))
            val agreement = KeyAgreement.getInstance("ECDH")
            agreement.init(pair.private)
            agreement.doPhase(peer, true)
            sharedSecret = agreement.generateSecret()
            val label = "APK Sentinel Remote Stream v1".encodeToByteArray()
            val derivationInput = ByteArray(label.size + request.sessionNonce.size + sharedSecret.size).also {
                label.copyInto(it, 0)
                request.sessionNonce.copyInto(it, label.size)
                sharedSecret.copyInto(it, label.size + request.sessionNonce.size)
            }
            try {
                MessageDigest.getInstance("SHA-256").digest(derivationInput)
            } finally {
                label.fill(0)
                derivationInput.fill(0)
            }
        } catch (_: Exception) {
            null
        } finally {
            publicDer?.fill(0)
            sharedSecret?.fill(0)
            response?.fill(0)
        }
    }
}

private class SingleAliasKeyManager(
    private val alias: String,
    private val privateKey: PrivateKey,
    private val certificateChain: Array<X509Certificate>,
) : X509ExtendedKeyManager() {
    override fun getClientAliases(keyType: String?, issuers: Array<out java.security.Principal>?): Array<String>? =
        if (keyType == null || keyType.equals("EC", ignoreCase = true)) arrayOf(alias) else null

    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out java.security.Principal>?, socket: Socket?): String? =
        if (keyType.isNullOrEmpty() || keyType.any { it.equals("EC", ignoreCase = true) }) alias else null

    override fun getServerAliases(keyType: String?, issuers: Array<out java.security.Principal>?): Array<String>? = null
    override fun chooseServerAlias(keyType: String?, issuers: Array<out java.security.Principal>?, socket: Socket?): String? = null
    override fun getCertificateChain(alias: String?): Array<X509Certificate>? = if (alias == this.alias) certificateChain.copyOf() else null
    override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == this.alias) privateKey else null
}

private class PinnedReceiverTrustManager(expectedReceiverDer: ByteArray) : X509TrustManager {
    private val expected = expectedReceiverDer.copyOf()

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        val leaf = chain?.firstOrNull() ?: throw java.security.cert.CertificateException("Missing receiver certificate")
        leaf.checkValidity()
        if (!isP256PublicKey(leaf.publicKey) || !MessageDigest.isEqual(leaf.publicKey.encoded, expected)) {
            throw java.security.cert.CertificateException("Receiver pin mismatch")
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

private class PinnedTlsTransport(
    private val socket: SSLSocket,
    private val output: BufferedOutputStream,
) : RemoteStreamAuthenticatedTransport {
    private val lock = Any()
    private var closed = false

    override fun send(frame: ByteArray): RemoteStreamTransportSendResult = synchronized(lock) {
        if (closed || socket.isClosed) return@synchronized RemoteStreamTransportSendResult.AUTHENTICATION_LOST
        return@synchronized try {
            // The engine owns a bounded encrypted frame and zeroizes it after SENT.
            output.write(frame)
            output.flush()
            RemoteStreamTransportSendResult.SENT
        } catch (_: java.io.IOException) {
            RemoteStreamTransportSendResult.TRANSPORT_FAILED
        }
    }

    override fun close() = synchronized(lock) {
        if (!closed) {
            closed = true
            runCatching { socket.close() }
        }
    }
}

private class InMemoryEphemeralSessionKey(bytes: ByteArray) : RemoteStreamEphemeralSessionKey {
    private var key = bytes.copyOf()
    override fun copyForImmediateUse(): ByteArray? = key.takeIf { it.isNotEmpty() }?.copyOf()
    override fun destroy() {
        key.fill(0)
        key = ByteArray(0)
    }
}

private fun isP256X509PublicKey(encoded: ByteArray): Boolean = runCatching {
    isP256PublicKey(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded)))
}.getOrDefault(false)

private fun isP256PublicKey(key: PublicKey): Boolean {
    val ec = key as? ECPublicKey ?: return false
    val expected = java.security.AlgorithmParameters.getInstance("EC").run {
        init(ECGenParameterSpec("secp256r1"))
        getParameterSpec(ECParameterSpec::class.java)
    }
    return ec.params.curve == expected.curve && ec.params.generator == expected.generator &&
        ec.params.order == expected.order && ec.params.cofactor == expected.cofactor
}

/** Uses a small bounded compatibility loop instead of newer bulk-read APIs. */
private fun BufferedInputStream.readExactly(destination: ByteArray) {
    var offset = 0
    while (offset < destination.size) {
        val read = read(destination, offset, destination.size - offset)
        if (read < 0) throw java.io.EOFException("Receiver attestation ended early")
        offset += read
    }
}
