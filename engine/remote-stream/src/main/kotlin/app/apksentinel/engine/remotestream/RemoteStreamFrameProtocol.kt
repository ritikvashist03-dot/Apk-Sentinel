package app.apksentinel.engine.remotestream

import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Input is supplied only by a separately reviewed upstream classifier. */
data class RemoteStreamRecord(
    val category: RemoteStreamDataCategory,
    val observedAtMillis: Long,
    val bytes: ByteArray,
)

internal data class QueuedRemoteStreamFrame(
    val sequence: Long,
    val payloadBytes: Int,
    val frame: ByteArray,
)

/**
 * Versioned authenticated-encryption framing for the one outbound stream.
 * Header fields are AES-GCM AAD; raw content never enters the queue unencrypted.
 */
internal class RemoteStreamFrameEncoder(
    sessionKey: ByteArray,
    private val random: SecureRandom = SecureRandom(),
) {
    private var key = sessionKey.copyOf()

    init { require(key.size == AES_256_KEY_BYTES) }

    fun encode(record: RemoteStreamRecord, sequence: Long, maximumRecordBytes: Int): QueuedRemoteStreamFrame? {
        if (key.isEmpty() || record.bytes.size > maximumRecordBytes || sequence <= 0L) return null
        var nonce: ByteArray? = null
        var header: ByteArray? = null
        var plaintext: ByteArray? = null
        return try {
            val activeNonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
            nonce = activeNonce
            val activeHeader = ByteBuffer.allocate(HEADER_BYTES)
                .putInt(MAGIC)
                .put(VERSION)
                .put(record.category.ordinal.toByte())
                .putShort(0)
                .putLong(sequence)
                .putLong(record.observedAtMillis)
                .putInt(record.bytes.size)
                .put(activeNonce)
                .array()
            header = activeHeader
            val activePlaintext = record.bytes.copyOf()
            plaintext = activePlaintext
            val encrypted = cipher(Cipher.ENCRYPT_MODE, activeNonce).apply { updateAAD(activeHeader) }.doFinal(activePlaintext)
            val frame = activeHeader + encrypted
            encrypted.fill(0)
            QueuedRemoteStreamFrame(sequence, activePlaintext.size, frame)
        } catch (_: Exception) {
            null
        } finally {
            plaintext?.fill(0)
            nonce?.fill(0)
            header?.fill(0)
        }
    }

    fun destroy() {
        key.fill(0)
        key = ByteArray(0)
    }

    private fun cipher(mode: Int, nonce: ByteArray): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
    }
}

/** Reference receiver verifier, intended for protocol/security tests and a future receiver implementation. */
class RemoteStreamReceiverFrameVerifier(
    sessionKey: ByteArray,
    private val maximumRecordBytes: Int,
    private val allowedCategories: Set<RemoteStreamDataCategory> = RemoteStreamConfiguration.DEFAULT_DATA_CATEGORIES,
) {
    private var key = sessionKey.copyOf()
    private var lastAcceptedSequence = 0L

    init {
        require(key.size == AES_256_KEY_BYTES)
        require(maximumRecordBytes in 1..64 * 1_024)
        require(allowedCategories.isNotEmpty())
    }

    fun verifyAndConsume(
        frame: ByteArray,
        consumer: (RemoteStreamReceivedFrame) -> Unit,
    ): RemoteStreamFrameVerificationResult {
        if (key.isEmpty()) return RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.VERIFIER_CLOSED)
        if (frame.size !in (HEADER_BYTES + GCM_TAG_BYTES)..(HEADER_BYTES + maximumRecordBytes + GCM_TAG_BYTES)) {
            return RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.INVALID_LENGTH)
        }
        val header = frame.copyOfRange(0, HEADER_BYTES)
        val parsed = try {
            parseHeader(header, frame.size)
        } catch (_: RuntimeException) {
            null
        }
        if (parsed == null) {
            header.fill(0)
            return RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.INVALID_HEADER)
        }
        if (parsed.sequence != lastAcceptedSequence + 1L) {
            header.fill(0)
            parsed.nonce.fill(0)
            return RemoteStreamFrameVerificationResult.Rejected(
                if (parsed.sequence <= lastAcceptedSequence) RemoteStreamFrameRejection.REPLAYED else RemoteStreamFrameRejection.OUT_OF_ORDER,
            )
        }
        if (parsed.category !in allowedCategories) {
            header.fill(0)
            parsed.nonce.fill(0)
            return RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.CATEGORY_NOT_ALLOWED)
        }
        val encrypted = frame.copyOfRange(HEADER_BYTES, frame.size)
        val plaintext = try {
            cipher(Cipher.DECRYPT_MODE, parsed.nonce).apply { updateAAD(header) }.doFinal(encrypted)
        } catch (_: Exception) {
            encrypted.fill(0)
            header.fill(0)
            parsed.nonce.fill(0)
            return RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.AUTHENTICATION_FAILED)
        }
        encrypted.fill(0)
        header.fill(0)
        parsed.nonce.fill(0)
        if (plaintext.size != parsed.payloadLength) {
            plaintext.fill(0)
            return RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.INVALID_LENGTH)
        }
        val received = RemoteStreamReceivedFrame(parsed.sequence, parsed.observedAtMillis, parsed.category, plaintext)
        return try {
            consumer(received)
            lastAcceptedSequence = parsed.sequence
            RemoteStreamFrameVerificationResult.Accepted(
                RemoteStreamReceivedFrameMetadata(parsed.sequence, parsed.observedAtMillis, parsed.category, plaintext.size),
            )
        } catch (_: RuntimeException) {
            RemoteStreamFrameVerificationResult.Rejected(RemoteStreamFrameRejection.CONSUMER_FAILED)
        } finally {
            received.zeroize()
        }
    }

    fun close() {
        key.fill(0)
        key = ByteArray(0)
        lastAcceptedSequence = 0L
    }

    private fun parseHeader(header: ByteArray, frameSize: Int): ParsedFrameHeader? {
        if (header.size != HEADER_BYTES) return null
        val buffer = ByteBuffer.wrap(header)
        if (buffer.int != MAGIC || buffer.get() != VERSION) return null
        val categoryIndex = buffer.get().toInt()
        if (categoryIndex !in RemoteStreamDataCategory.entries.indices || buffer.short.toInt() != 0) return null
        val sequence = buffer.long
        val timestamp = buffer.long
        val payloadLength = buffer.int
        val nonce = ByteArray(NONCE_BYTES).also(buffer::get)
        if (sequence <= 0L || timestamp <= 0L || payloadLength !in 1..maximumRecordBytes ||
            frameSize != HEADER_BYTES + payloadLength + GCM_TAG_BYTES
        ) {
            nonce.fill(0)
            return null
        }
        return ParsedFrameHeader(sequence, timestamp, RemoteStreamDataCategory.entries[categoryIndex], payloadLength, nonce)
    }

    private fun cipher(mode: Int, nonce: ByteArray): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
    }
}

/** A callback-only view; its byte copy is wiped immediately after the verifier callback returns. */
class RemoteStreamReceivedFrame internal constructor(
    val sequence: Long,
    val observedAtMillis: Long,
    val category: RemoteStreamDataCategory,
    private val bytes: ByteArray,
) {
    private var closed = false

    val size: Int get() = if (closed) 0 else bytes.size

    fun <T> useReadOnlyBytes(block: (ByteBuffer) -> T): T {
        check(!closed) { "Frame content has been zeroized." }
        return block(ByteBuffer.wrap(bytes).asReadOnlyBuffer())
    }

    internal fun zeroize() {
        bytes.fill(0)
        closed = true
    }
}

data class RemoteStreamReceivedFrameMetadata(
    val sequence: Long,
    val observedAtMillis: Long,
    val category: RemoteStreamDataCategory,
    val byteCount: Int,
)

sealed interface RemoteStreamFrameVerificationResult {
    data class Accepted(val metadata: RemoteStreamReceivedFrameMetadata) : RemoteStreamFrameVerificationResult
    data class Rejected(val reason: RemoteStreamFrameRejection) : RemoteStreamFrameVerificationResult
}

enum class RemoteStreamFrameRejection {
    VERIFIER_CLOSED,
    INVALID_LENGTH,
    INVALID_HEADER,
    REPLAYED,
    OUT_OF_ORDER,
    CATEGORY_NOT_ALLOWED,
    AUTHENTICATION_FAILED,
    CONSUMER_FAILED,
}

private data class ParsedFrameHeader(
    val sequence: Long,
    val observedAtMillis: Long,
    val category: RemoteStreamDataCategory,
    val payloadLength: Int,
    val nonce: ByteArray,
)

internal const val MAGIC: Int = 0x41505352 // APSR
internal const val VERSION: Byte = 1
internal const val NONCE_BYTES: Int = 12
internal const val GCM_TAG_BITS: Int = 128
internal const val GCM_TAG_BYTES: Int = 16
internal const val AES_256_KEY_BYTES: Int = 32
internal const val HEADER_BYTES: Int = 4 + 1 + 1 + 2 + 8 + 8 + 4 + NONCE_BYTES
