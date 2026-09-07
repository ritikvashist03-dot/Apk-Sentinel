package app.apksentinel.mobile

import android.content.Context
import java.io.File
import java.util.ArrayDeque
import java.util.Locale

internal enum class LocalDataCategory {
    ENCRYPTED_HISTORIES,
    THREAT_DATA,
    DISPLAY_AND_SECURITY_PREFERENCES,
    REPORT_AND_WORK_CACHE,
    OTHER_APP_PRIVATE_DATA,
}

internal data class LocalDataCategorySize(
    val category: LocalDataCategory,
    val bytes: Long,
    val files: Int,
)

internal data class LocalDataInventorySnapshot(
    val categories: List<LocalDataCategorySize>,
    val totalBytes: Long,
    val inspectedEntries: Int,
    val truncated: Boolean,
    val failed: Boolean,
)

/**
 * Bounded, read-only inventory of APK Sentinel's internal data directory.
 * Call from a background dispatcher. Symlinks and paths outside dataDir are never followed.
 */
internal object LocalDataInventory {
    fun inspect(context: Context, maximumEntries: Int = 4_096, maximumDepth: Int = 8): LocalDataInventorySnapshot {
        require(maximumEntries in 1..32_768)
        require(maximumDepth in 1..16)
        val root = runCatching { File(context.applicationInfo.dataDir).canonicalFile }.getOrNull()
            ?: return failedSnapshot()
        if (!root.isDirectory) return failedSnapshot()

        val totals = LocalDataCategory.entries.associateWith { MutableCategorySize() }.toMutableMap()
        val pending = ArrayDeque<PathToInspect>().apply { add(PathToInspect(root, 0)) }
        var inspected = 0
        var truncated = false
        var failed = false

        while (pending.isNotEmpty()) {
            if (inspected >= maximumEntries) {
                truncated = true
                break
            }
            val current = pending.removeFirst()
            val children = runCatching { current.file.listFiles() }.getOrNull()
            if (children == null) {
                failed = true
                continue
            }
            children.forEach { child ->
                if (inspected >= maximumEntries) {
                    truncated = true
                    return@forEach
                }
                inspected++
                val canonical = runCatching { child.canonicalFile }.getOrNull()
                if (canonical == null || !canonical.toPath().startsWith(root.toPath())) {
                    failed = true
                    return@forEach
                }
                // A canonical path differing from the absolute path indicates a link or alias.
                if (canonical.absolutePath != child.absoluteFile.toPath().normalize().toFile().absolutePath) return@forEach
                when {
                    canonical.isFile -> {
                        val relative = canonical.relativeTo(root).invariantSeparatorsPath
                        val category = classify(relative)
                        val bucket = requireNotNull(totals[category])
                        bucket.files = (bucket.files + 1).coerceAtMost(Int.MAX_VALUE)
                        bucket.bytes = saturatingAdd(bucket.bytes, canonical.length().coerceAtLeast(0L))
                    }
                    canonical.isDirectory && current.depth < maximumDepth -> pending.add(PathToInspect(canonical, current.depth + 1))
                    canonical.isDirectory -> truncated = true
                }
            }
        }

        val categories = LocalDataCategory.entries.map { category ->
            val size = requireNotNull(totals[category])
            LocalDataCategorySize(category, size.bytes, size.files)
        }
        return LocalDataInventorySnapshot(
            categories = categories,
            totalBytes = categories.fold(0L) { total, value -> saturatingAdd(total, value.bytes) },
            inspectedEntries = inspected,
            truncated = truncated,
            failed = failed,
        )
    }

    internal fun classify(relativePath: String): LocalDataCategory {
        val normalized = relativePath.replace('\\', '/').lowercase(Locale.ROOT)
        return when {
            normalized.startsWith("cache/") || normalized.startsWith("code_cache/") ->
                LocalDataCategory.REPORT_AND_WORK_CACHE
            normalized == "shared_prefs/threat_feed_encrypted.xml" -> LocalDataCategory.THREAT_DATA
            normalized in ENCRYPTED_HISTORY_FILES -> LocalDataCategory.ENCRYPTED_HISTORIES
            normalized.startsWith("shared_prefs/") -> LocalDataCategory.DISPLAY_AND_SECURITY_PREFERENCES
            else -> LocalDataCategory.OTHER_APP_PRIVATE_DATA
        }
    }

    private fun failedSnapshot() = LocalDataInventorySnapshot(
        categories = LocalDataCategory.entries.map { LocalDataCategorySize(it, 0L, 0) },
        totalBytes = 0L,
        inspectedEntries = 0,
        truncated = false,
        failed = true,
    )

    private fun saturatingAdd(left: Long, right: Long): Long =
        if (right > Long.MAX_VALUE - left) Long.MAX_VALUE else left + right

    private data class PathToInspect(val file: File, val depth: Int)
    private data class MutableCategorySize(var bytes: Long = 0L, var files: Int = 0)

    private val ENCRYPTED_HISTORY_FILES = setOf(
        "shared_prefs/apk_sentinel_network_history.xml",
        "shared_prefs/apk_sentinel_capture_catalog.xml",
        "shared_prefs/network_session_selection_secure.xml",
        "shared_prefs/network_history_policy_secure.xml",
        "shared_prefs/installed_app_snapshot_secure.xml",
        "shared_prefs/posture_observation_history.xml",
        "shared_prefs/remote_stream_pairing_encrypted.xml",
        "shared_prefs/${PrivacyDeletionReceiptController.PREFERENCES}.xml",
    )
}
