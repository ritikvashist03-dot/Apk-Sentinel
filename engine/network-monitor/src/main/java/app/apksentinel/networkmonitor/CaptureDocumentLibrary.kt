package app.apksentinel.networkmonitor

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.SecureStorageKey
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** A user-owned capture document is metadata here; packet bytes never enter this catalog. */
enum class CaptureDocumentFormat { PCAP, PCAPNG, HAR, UNKNOWN }
enum class CaptureDocumentOrigin { USER_CREATED, USER_OPENED }
enum class CaptureDocumentAvailability { AVAILABLE, MISSING, ACCESS_REVOKED, UNKNOWN }

data class CaptureDocumentRecord(
    val id: String,
    val uri: String,
    val displayName: String,
    val format: CaptureDocumentFormat,
    val origin: CaptureDocumentOrigin,
    val measuredBytes: Long?,
    val createdAtMillis: Long?,
    val lastOpenedAtMillis: Long,
    val availability: CaptureDocumentAvailability,
    val persistedGrant: Boolean,
) {
    init {
        require(id.length in 1..96 && uri.length in 1..2_048)
        require(displayName.length in 1..160)
        require(measuredBytes == null || measuredBytes >= 0L)
        require(createdAtMillis == null || createdAtMillis >= 0L)
        require(lastOpenedAtMillis >= 0L)
    }
}

data class CaptureLibraryLimits(
    val maximumEntries: Int = 128,
    val maximumMetadataBytes: Int = 96 * 1_024,
) {
    init {
        require(maximumEntries in 1..512)
        require(maximumMetadataBytes in 4_096..512 * 1_024)
    }
}

interface CaptureDocumentMetadataReader {
    fun read(uri: String): CaptureDocumentRead
}

data class CaptureDocumentRead(
    val displayName: String,
    val format: CaptureDocumentFormat,
    val measuredBytes: Long?,
    val createdAtMillis: Long?,
    val availability: CaptureDocumentAvailability,
    val persistedGrant: Boolean,
)

enum class CaptureMetadataPersistenceState { READY, MISSING, UNAVAILABLE, CORRUPT, REJECTED }
enum class CaptureMetadataWriteOutcome { WRITTEN, UNAVAILABLE, REJECTED }
enum class CaptureMetadataRemoveOutcome { REMOVED, UNAVAILABLE, REJECTED }

sealed interface CaptureMetadataReadOutcome {
    data object Missing : CaptureMetadataReadOutcome
    data class Available(val bytes: ByteArray) : CaptureMetadataReadOutcome
    data object Unavailable : CaptureMetadataReadOutcome
}

data class CaptureDocumentMutationResult(
    val record: CaptureDocumentRecord?,
    val outcome: CaptureMetadataWriteOutcome,
)

data class CaptureDocumentListMutationResult(
    val records: List<CaptureDocumentRecord>,
    val outcome: CaptureMetadataWriteOutcome,
)

data class CaptureDocumentEraseResult(
    val removedCount: Int,
    val outcome: CaptureMetadataRemoveOutcome,
)

/** Android SAF metadata read. It never enumerates a directory or shared storage. */
class AndroidCaptureDocumentMetadataReader(
    private val resolver: ContentResolver,
) : CaptureDocumentMetadataReader {
    override fun read(uri: String): CaptureDocumentRead {
        val parsed = runCatching { Uri.parse(uri) }.getOrNull()
            ?: return CaptureDocumentRead("capture", CaptureDocumentFormat.UNKNOWN, null, null, CaptureDocumentAvailability.MISSING, false)
        val persisted = resolver.persistedUriPermissions.any { it.uri == parsed && it.isReadPermission }
        val name = runCatching {
            resolver.query(parsed, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) cursor.getString(0) else null
            }
        }.getOrNull()?.takeIf { it.isNotBlank() } ?: "capture"
        val size = runCatching {
            resolver.query(parsed, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getLong(0) else null
            }
        }.getOrNull()?.takeIf { it >= 0L }
        val availability = runCatching {
            resolver.openAssetFileDescriptor(parsed, "r")?.use { }
            CaptureDocumentAvailability.AVAILABLE
        }.getOrElse {
            if (persisted) CaptureDocumentAvailability.ACCESS_REVOKED else CaptureDocumentAvailability.MISSING
        }
        return CaptureDocumentRead(name.take(160), formatFor(name), size, null, availability, persisted)
    }

    private fun formatFor(name: String): CaptureDocumentFormat = when (name.substringAfterLast('.', "").lowercase()) {
        "pcap" -> CaptureDocumentFormat.PCAP
        "pcapng" -> CaptureDocumentFormat.PCAPNG
        "har" -> CaptureDocumentFormat.HAR
        else -> CaptureDocumentFormat.UNKNOWN
    }
}

/**
 * Small catalog backed by an optionally encrypted key/value store. The encoded
 * value is bounded and contains only URI/display metadata; erase never deletes
 * a user document and only asks the host to release its app-owned grants.
 */
class CaptureDocumentLibrary(
    private val metadataStore: CaptureMetadataStore = InMemoryCaptureMetadataStore(),
    private val limits: CaptureLibraryLimits = CaptureLibraryLimits(),
    private val clock: EpochClock = SystemEpochClock,
) {
    private val lock = Any()
    private var persistenceState: CaptureMetadataPersistenceState = CaptureMetadataPersistenceState.READY
    private var records: List<CaptureDocumentRecord> = when (val stored = runCatching { metadataStore.read() }
        .getOrElse { CaptureMetadataReadOutcome.Unavailable }) {
        CaptureMetadataReadOutcome.Missing -> {
            persistenceState = CaptureMetadataPersistenceState.MISSING
            emptyList()
        }
        CaptureMetadataReadOutcome.Unavailable -> {
            persistenceState = CaptureMetadataPersistenceState.UNAVAILABLE
            emptyList()
        }
        is CaptureMetadataReadOutcome.Available -> {
            val decoded = decode(stored.bytes)
            if (!decoded.valid) persistenceState = CaptureMetadataPersistenceState.CORRUPT
            stored.bytes.fill(0)
            decoded.records.takeLast(limits.maximumEntries)
        }
    }

    fun snapshot(): List<CaptureDocumentRecord> = synchronized(lock) { records.toList() }
    fun persistenceState(): CaptureMetadataPersistenceState = synchronized(lock) { persistenceState }

    fun recordOpened(uri: String, reader: CaptureDocumentMetadataReader): CaptureDocumentRecord =
        recordOpenedOutcome(uri, reader).record ?: CaptureDocumentRecord(
            id = stableId(uri), uri = uri, displayName = "capture", format = CaptureDocumentFormat.UNKNOWN,
            origin = CaptureDocumentOrigin.USER_OPENED, measuredBytes = null, createdAtMillis = null,
            lastOpenedAtMillis = clock.nowMillis().coerceAtLeast(0L), availability = CaptureDocumentAvailability.UNKNOWN,
            persistedGrant = false,
        )

    fun recordOpenedOutcome(uri: String, reader: CaptureDocumentMetadataReader): CaptureDocumentMutationResult {
        require(uri.length in 1..2_048)
        val read = reader.read(uri)
        val now = clock.nowMillis().coerceAtLeast(0L)
        return synchronized(lock) {
            val old = records.firstOrNull { it.uri == uri }
            val value = CaptureDocumentRecord(
                id = old?.id ?: stableId(uri),
                uri = uri,
                displayName = read.displayName.take(160).ifBlank { "capture" },
                format = read.format,
                origin = old?.origin ?: CaptureDocumentOrigin.USER_OPENED,
                measuredBytes = read.measuredBytes,
                createdAtMillis = read.createdAtMillis ?: old?.createdAtMillis,
                lastOpenedAtMillis = now,
                availability = read.availability,
                persistedGrant = read.persistedGrant,
            )
            val outcome = persistLocked((records.filterNot { it.uri == uri } + value).takeLast(limits.maximumEntries))
            CaptureDocumentMutationResult(if (outcome == CaptureMetadataWriteOutcome.WRITTEN) value else old, outcome)
        }
    }

    fun recordCreated(uri: String, reader: CaptureDocumentMetadataReader): CaptureDocumentRecord =
        recordCreatedOutcome(uri, reader).record ?: CaptureDocumentRecord(
            id = stableId(uri), uri = uri, displayName = "capture", format = CaptureDocumentFormat.UNKNOWN,
            origin = CaptureDocumentOrigin.USER_CREATED, measuredBytes = null, createdAtMillis = null,
            lastOpenedAtMillis = clock.nowMillis().coerceAtLeast(0L), availability = CaptureDocumentAvailability.UNKNOWN,
            persistedGrant = false,
        )

    fun recordCreatedOutcome(uri: String, reader: CaptureDocumentMetadataReader): CaptureDocumentMutationResult {
        require(uri.length in 1..2_048)
        val read = reader.read(uri)
        val now = clock.nowMillis().coerceAtLeast(0L)
        return synchronized(lock) {
            val old = records.firstOrNull { it.uri == uri }
            val value = CaptureDocumentRecord(
                id = old?.id ?: stableId(uri),
                uri = uri,
                displayName = read.displayName.take(160).ifBlank { "capture" },
                format = read.format,
                origin = CaptureDocumentOrigin.USER_CREATED,
                measuredBytes = read.measuredBytes,
                createdAtMillis = read.createdAtMillis ?: old?.createdAtMillis,
                lastOpenedAtMillis = now,
                availability = read.availability,
                persistedGrant = read.persistedGrant,
            )
            val outcome = persistLocked((records.filterNot { it.uri == uri } + value).takeLast(limits.maximumEntries))
            CaptureDocumentMutationResult(if (outcome == CaptureMetadataWriteOutcome.WRITTEN) value else old, outcome)
        }
    }

    fun refresh(reader: CaptureDocumentMetadataReader): List<CaptureDocumentRecord> = refreshOutcome(reader).records

    fun refreshOutcome(reader: CaptureDocumentMetadataReader): CaptureDocumentListMutationResult = synchronized(lock) {
        val updated = records.map { old ->
            val read = reader.read(old.uri)
            old.copy(
                displayName = read.displayName.take(160).ifBlank { old.displayName },
                format = read.format,
                measuredBytes = read.measuredBytes,
                createdAtMillis = read.createdAtMillis ?: old.createdAtMillis,
                availability = read.availability,
                persistedGrant = read.persistedGrant,
            )
        }
        val outcome = persistLocked(updated)
        CaptureDocumentListMutationResult(records.toList(), outcome)
    }

    /** Reconciles the extension-derived row with an actually parsed capture format. */
    fun updateFormat(uri: String, format: CaptureDocumentFormat): CaptureDocumentRecord? = updateFormatOutcome(uri, format)?.record

    fun updateFormatOutcome(uri: String, format: CaptureDocumentFormat): CaptureDocumentMutationResult? = synchronized(lock) {
        val old = records.firstOrNull { it.uri == uri } ?: return@synchronized null
        val updated = old.copy(format = format)
        val outcome = persistLocked(records.map { if (it.id == old.id) updated else it })
        CaptureDocumentMutationResult(if (outcome == CaptureMetadataWriteOutcome.WRITTEN) updated else old, outcome)
    }

    /**
     * Forget only this catalog row and its app-owned persisted read grant.
     * The SAF provider document is user-owned and is never deleted here.
     */
    fun forget(uri: String, releaseGrant: (String) -> Unit = {}): Boolean =
        forgetOutcome(uri, releaseGrant).removedCount == 1

    fun forgetOutcome(uri: String, releaseGrant: (String) -> Unit = {}): CaptureDocumentEraseResult = synchronized(lock) {
        val old = records.firstOrNull { it.uri == uri }
            ?: return@synchronized CaptureDocumentEraseResult(0, CaptureMetadataRemoveOutcome.REJECTED)
        val outcome = persistLocked(records.filterNot { it.uri == uri }).toRemoveOutcome()
        if (outcome == CaptureMetadataRemoveOutcome.REMOVED && old.persistedGrant) runCatching { releaseGrant(old.uri) }
        CaptureDocumentEraseResult(if (outcome == CaptureMetadataRemoveOutcome.REMOVED) 1 else 0, outcome)
    }

    fun erase(releaseGrant: (String) -> Unit = {}): Int = eraseOutcome(releaseGrant).removedCount

    fun eraseOutcome(releaseGrant: (String) -> Unit = {}): CaptureDocumentEraseResult = synchronized(lock) {
        val old = records
        val outcome = runCatching { metadataStore.remove() }
            .getOrElse { CaptureMetadataRemoveOutcome.UNAVAILABLE }
        if (outcome == CaptureMetadataRemoveOutcome.REMOVED) {
            records = emptyList()
            persistenceState = CaptureMetadataPersistenceState.MISSING
            old.filter { it.persistedGrant }.forEach { runCatching { releaseGrant(it.uri) } }
        } else {
            persistenceState = outcome.toPersistenceState()
        }
        CaptureDocumentEraseResult(if (outcome == CaptureMetadataRemoveOutcome.REMOVED) old.size else 0, outcome)
    }

    private fun persistLocked(candidate: List<CaptureDocumentRecord>): CaptureMetadataWriteOutcome {
        var bounded = candidate.takeLast(limits.maximumEntries)
        var encoded = encode(bounded)
            ?: return CaptureMetadataWriteOutcome.REJECTED.also { persistenceState = CaptureMetadataPersistenceState.REJECTED }
        while (encoded.size > limits.maximumMetadataBytes && bounded.isNotEmpty()) {
            bounded = bounded.drop(1)
            encoded = encode(bounded)
                ?: return CaptureMetadataWriteOutcome.REJECTED.also { persistenceState = CaptureMetadataPersistenceState.REJECTED }
        }
        val writeOutcome = runCatching { metadataStore.write(encoded) }
            .getOrElse { CaptureMetadataWriteOutcome.UNAVAILABLE }
        encoded.fill(0)
        if (writeOutcome == CaptureMetadataWriteOutcome.WRITTEN) {
            records = bounded
            persistenceState = CaptureMetadataPersistenceState.READY
        } else {
            persistenceState = writeOutcome.toPersistenceState()
        }
        return writeOutcome
    }

    private fun stableId(uri: String): String = "cd-" + MessageDigest.getInstance("SHA-256")
        .digest(uri.encodeToByteArray()).joinToString("") { byte -> "%02x".format(byte) }

    private fun encode(values: List<CaptureDocumentRecord>): ByteArray? = runCatching {
        ByteArrayOutputStream().also { output ->
            DataOutputStream(output).use { data ->
                data.writeInt(MAGIC); data.writeShort(VERSION); data.writeInt(values.size)
                values.forEach { item ->
                    data.writeUTF(item.id); data.writeUTF(item.uri); data.writeUTF(item.displayName)
                    data.writeByte(item.format.ordinal); data.writeByte(item.origin.ordinal)
                    data.writeLong(item.measuredBytes ?: -1L); data.writeLong(item.createdAtMillis ?: -1L)
                    data.writeLong(item.lastOpenedAtMillis); data.writeByte(item.availability.ordinal)
                    data.writeBoolean(item.persistedGrant)
                }
            }
        }.toByteArray()
    }.getOrNull()

    private data class DecodeResult(val records: List<CaptureDocumentRecord>, val valid: Boolean)

    private fun decode(bytes: ByteArray?): DecodeResult = try {
        if (bytes == null || bytes.size < 10 || bytes.size > limits.maximumMetadataBytes) return DecodeResult(emptyList(), false)
        DataInputStream(ByteArrayInputStream(bytes)).use { data ->
            if (data.readInt() != MAGIC || data.readUnsignedShort() != VERSION) return DecodeResult(emptyList(), false)
            val count = data.readInt()
            if (count !in 0..limits.maximumEntries) return DecodeResult(emptyList(), false)
            val values = ArrayList<CaptureDocumentRecord>(count)
            repeat(count) {
                val id = data.readUTF(); val uri = data.readUTF(); val name = data.readUTF()
                val format = CaptureDocumentFormat.entries.getOrNull(data.readUnsignedByte()) ?: return DecodeResult(emptyList(), false)
                val origin = CaptureDocumentOrigin.entries.getOrNull(data.readUnsignedByte()) ?: return DecodeResult(emptyList(), false)
                val size = data.readLong(); val created = data.readLong(); val opened = data.readLong()
                val availability = CaptureDocumentAvailability.entries.getOrNull(data.readUnsignedByte()) ?: return DecodeResult(emptyList(), false)
                val grant = data.readBoolean()
                if (id.length !in 1..96 || uri.length !in 1..2_048 || name.length !in 1..160 || opened < 0L) {
                    return DecodeResult(emptyList(), false)
                }
                values += CaptureDocumentRecord(id, uri, name, format, origin, size.takeIf { it >= 0L }, created.takeIf { it >= 0L }, opened, availability, grant)
            }
            if (data.available() != 0) DecodeResult(emptyList(), false) else DecodeResult(values, true)
        }
    } catch (_: Exception) {
        DecodeResult(emptyList(), false)
    }

    private companion object { const val MAGIC = 0x4150434C; const val VERSION = 1 }
}

interface CaptureMetadataStore {
    fun read(): CaptureMetadataReadOutcome
    fun write(value: ByteArray): CaptureMetadataWriteOutcome
    fun remove(): CaptureMetadataRemoveOutcome
}

class InMemoryCaptureMetadataStore : CaptureMetadataStore {
    private var value: ByteArray? = null
    override fun read(): CaptureMetadataReadOutcome = value?.copyOf()?.let(CaptureMetadataReadOutcome::Available)
        ?: CaptureMetadataReadOutcome.Missing
    override fun write(value: ByteArray): CaptureMetadataWriteOutcome { this.value = value.copyOf(); return CaptureMetadataWriteOutcome.WRITTEN }
    override fun remove(): CaptureMetadataRemoveOutcome { value = null; return CaptureMetadataRemoveOutcome.REMOVED }
}

/** Android composition for the catalog. The backing preference contains ciphertext only. */
class AndroidEncryptedCaptureMetadataStore(context: android.content.Context) : CaptureMetadataStore {
    private val application = context.applicationContext
    private val storage = AndroidKeystoreEncryptedStorage(
        preferences = application.getSharedPreferences(PREFERENCES_NAME, android.content.Context.MODE_PRIVATE),
        keyAlias = KEY_ALIAS,
        namespace = STORAGE_NAMESPACE,
    )
    private val key = SecureStorageKey(STORAGE_KEY)

    override fun read(): CaptureMetadataReadOutcome = when (val result = storage.read(key)) {
        is app.apksentinel.core.security.SecureStorageResult.Success -> result.value?.let(CaptureMetadataReadOutcome::Available)
            ?: CaptureMetadataReadOutcome.Missing
        is app.apksentinel.core.security.SecureStorageResult.Failure -> CaptureMetadataReadOutcome.Unavailable
    }

    override fun write(value: ByteArray): CaptureMetadataWriteOutcome {
        return when (storage.write(key, value)) {
            is app.apksentinel.core.security.SecureStorageResult.Success -> CaptureMetadataWriteOutcome.WRITTEN
            is app.apksentinel.core.security.SecureStorageResult.Failure -> CaptureMetadataWriteOutcome.UNAVAILABLE
        }
    }

    override fun remove(): CaptureMetadataRemoveOutcome {
        return when (storage.remove(key)) {
            is app.apksentinel.core.security.SecureStorageResult.Success -> CaptureMetadataRemoveOutcome.REMOVED
            is app.apksentinel.core.security.SecureStorageResult.Failure -> CaptureMetadataRemoveOutcome.UNAVAILABLE
        }
    }

    fun eraseEncryptionKey(): Boolean = storage.deleteEncryptionKey()

    private companion object {
        const val PREFERENCES_NAME = "apk_sentinel_capture_catalog"
        const val KEY_ALIAS = "apk_sentinel_capture_catalog_v1"
        const val STORAGE_NAMESPACE = "apk_sentinel_capture_catalog"
        const val STORAGE_KEY = "capture-document-catalog-v1"
    }
}

private fun CaptureMetadataWriteOutcome.toPersistenceState(): CaptureMetadataPersistenceState = when (this) {
    CaptureMetadataWriteOutcome.WRITTEN -> CaptureMetadataPersistenceState.READY
    CaptureMetadataWriteOutcome.UNAVAILABLE -> CaptureMetadataPersistenceState.UNAVAILABLE
    CaptureMetadataWriteOutcome.REJECTED -> CaptureMetadataPersistenceState.REJECTED
}

private fun CaptureMetadataWriteOutcome.toRemoveOutcome(): CaptureMetadataRemoveOutcome = when (this) {
    CaptureMetadataWriteOutcome.WRITTEN -> CaptureMetadataRemoveOutcome.REMOVED
    CaptureMetadataWriteOutcome.UNAVAILABLE -> CaptureMetadataRemoveOutcome.UNAVAILABLE
    CaptureMetadataWriteOutcome.REJECTED -> CaptureMetadataRemoveOutcome.REJECTED
}

private fun CaptureMetadataRemoveOutcome.toPersistenceState(): CaptureMetadataPersistenceState = when (this) {
    CaptureMetadataRemoveOutcome.REMOVED -> CaptureMetadataPersistenceState.MISSING
    CaptureMetadataRemoveOutcome.UNAVAILABLE -> CaptureMetadataPersistenceState.UNAVAILABLE
    CaptureMetadataRemoveOutcome.REJECTED -> CaptureMetadataPersistenceState.REJECTED
}
