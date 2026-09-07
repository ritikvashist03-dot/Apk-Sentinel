package app.apksentinel.mobile

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import app.apksentinel.core.security.AndroidKeystoreEncryptedStorage
import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SafeTextNormalizer
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import app.apksentinel.networkmonitor.FirewallPolicyAction
import app.apksentinel.networkmonitor.FirewallPolicyRule
import app.apksentinel.networkmonitor.FirewallPolicyRuleDraft
import app.apksentinel.networkmonitor.MonitorLifecycleState
import app.apksentinel.networkmonitor.NetworkMonitorRuntime
import app.apksentinel.networkmonitor.DurableHistoryRetentionPolicy
import app.apksentinel.networkmonitor.TransportProtocol
import app.apksentinel.networkmonitor.VpnAppSelection
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale

internal enum class NetworkAppSelectionMode { ALL_APPS_EXCEPT, ONLY_APPS }

internal data class NetworkSelectableApp(
    val label: String,
    val packageName: String,
    val isSystem: Boolean,
)

internal object InstalledAppSelectionCatalog {
    const val MAX_APPS = 512
    const val MAX_VISIBLE_APPS = 48
    fun read(context: Context): List<NetworkSelectableApp> = runCatching {
        val manager = context.packageManager
        val installed = if (android.os.Build.VERSION.SDK_INT >= 33) {
            manager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION") manager.getInstalledApplications(PackageManager.GET_META_DATA)
        }
        installed
            .asSequence()
            .filter { it.packageName != context.packageName }
            .map { info ->
                NetworkSelectableApp(
                    label = info.safeLabel(manager),
                    packageName = info.packageName,
                    isSystem = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                )
            }
            .sortedWith(
                compareBy<NetworkSelectableApp, String>(String.CASE_INSENSITIVE_ORDER) { app -> app.label }
                    .thenBy { app -> app.packageName },
            )
            .take(MAX_APPS)
            .toList()
    }.getOrDefault(emptyList())

    fun filter(apps: List<NetworkSelectableApp>, query: String): List<NetworkSelectableApp> {
        val needle = query.trim().lowercase(Locale.ROOT)
        return apps.filter { needle.isBlank() || it.label.lowercase(Locale.ROOT).contains(needle) || it.packageName.lowercase(Locale.ROOT).contains(needle) }
            .take(MAX_VISIBLE_APPS)
    }

    private fun ApplicationInfo.safeLabel(manager: PackageManager): String = runCatching {
        normalizeInstalledAppLabel(manager.getApplicationLabel(this).toString(), packageName)
    }.getOrDefault(packageName)
}

internal fun normalizeInstalledAppLabel(rawLabel: String?, packageName: String): String =
    SafeTextNormalizer.normalizeDisplayText(rawLabel, packageName, maxCodePoints = 96)

internal data class NetworkAppSelection(
    val mode: NetworkAppSelectionMode = NetworkAppSelectionMode.ALL_APPS_EXCEPT,
    val packageNames: Set<String> = emptySet(),
) {
    init {
        require(packageNames.size <= 128)
        require(packageNames.all(::isValidPackageName))
        require(mode != NetworkAppSelectionMode.ONLY_APPS || packageNames.isNotEmpty())
    }

    fun toVpnSelection(): VpnAppSelection = when (mode) {
        NetworkAppSelectionMode.ALL_APPS_EXCEPT -> VpnAppSelection.AllAppsExcept(packageNames)
        NetworkAppSelectionMode.ONLY_APPS -> VpnAppSelection.OnlyApps(packageNames)
    }

    companion object {
        fun parse(mode: String?, packages: Set<String>): NetworkAppSelection? = runCatching {
            NetworkAppSelection(
                mode = NetworkAppSelectionMode.entries.firstOrNull { it.name == mode }
                    ?: return null,
                packageNames = packages,
            )
        }.getOrNull()
    }
}

/** Strict, bounded plaintext framing. The controller encrypts this before it reaches disk. */
internal object NetworkAppSelectionCodec {
    const val VERSION = 1
    const val MAX_BYTES = 16 * 1_024
    private const val MAX_PACKAGES = 128

    fun encode(selection: NetworkAppSelection): ByteArray {
        require(selection.packageNames.size <= MAX_PACKAGES)
        val lines = buildList {
            add("APK_SENTINEL_NETWORK_SELECTION_VERSION=$VERSION")
            add("mode=${selection.mode.name}")
            add("count=${selection.packageNames.size}")
            selection.packageNames.sorted().forEachIndexed { index, packageName ->
                add("package.$index=$packageName")
            }
        }
        return (lines.joinToString("\n") + "\n").toByteArray(StandardCharsets.US_ASCII).also {
            require(it.size <= MAX_BYTES)
        }
    }

    fun decode(bytes: ByteArray): NetworkAppSelection? {
        if (bytes.isEmpty() || bytes.size > MAX_BYTES) return null
        if (bytes.any { it.toInt() !in 0x20..0x7e && it.toInt() != '\n'.code }) return null
        val lines = runCatching { String(bytes, StandardCharsets.US_ASCII).split('\n') }.getOrNull() ?: return null
        if (lines.size < 4 || lines.last().isNotEmpty()) return null
        if (lines[0] != "APK_SENTINEL_NETWORK_SELECTION_VERSION=$VERSION") return null
        val mode = lines[1].substringAfter("mode=", missingDelimiterValue = "__missing__")
            .takeIf { lines[1].startsWith("mode=") }
        val count = lines[2].substringAfter("count=", missingDelimiterValue = "__missing__")
            .takeIf { lines[2].startsWith("count=") }?.toIntOrNull()
            ?.takeIf { it in 0..MAX_PACKAGES }
            ?: return null
        if (lines.size != count + 4 || mode == null) return null
        val packages = buildSet {
            repeat(count) { index ->
                val line = lines[index + 3]
                if (!line.startsWith("package.$index=")) return null
                val packageName = line.substringAfter('=').takeIf(::isValidPackageName) ?: return null
                if (!add(packageName)) return null
            }
        }
        return NetworkAppSelection.parse(mode, packages)
    }
}

/**
 * Encrypted durable app-selection state with a bounded codec. A legacy plaintext value is read
 * only to migrate it; it is removed only after the encrypted write succeeds. If encryption is
 * temporarily unavailable, the valid legacy value remains available for the current UI instead
 * of silently reverting the user's active selection.
 */
internal class NetworkAppSelectionStoreController(
    private val storage: EncryptedStorage,
    private val readLegacy: () -> NetworkAppSelection? = { null },
    private val clearLegacy: () -> Boolean = { true },
    private val deleteEncryptionKey: () -> Boolean = { true },
) {
    fun load(): NetworkAppSelection {
        return when (val result = storage.read(KEY)) {
            is SecureStorageResult.Success -> {
                val bytes = result.value ?: return migrateLegacy()
                try {
                    NetworkAppSelectionCodec.decode(bytes) ?: NetworkAppSelection()
                } finally {
                    bytes.fill(0)
                }
            }
            is SecureStorageResult.Failure -> migrateLegacy()
        }
    }

    fun save(selection: NetworkAppSelection): Boolean {
        val encoded = runCatching { NetworkAppSelectionCodec.encode(selection) }.getOrNull() ?: return false
        return try {
            when (storage.write(KEY, encoded)) {
                is SecureStorageResult.Failure -> false
                is SecureStorageResult.Success -> clearLegacy()
            }
        } finally {
            encoded.fill(0)
        }
    }

    /** Removes encrypted data, its dedicated key, and any pre-encryption legacy keys. */
    fun erase(): Boolean {
        val removed = storage.remove(KEY) is SecureStorageResult.Success
        val legacyCleared = runCatching { clearLegacy() }.getOrDefault(false)
        val keyDeleted = if (removed) runCatching { deleteEncryptionKey() }.getOrDefault(false) else false
        return removed && keyDeleted && legacyCleared
    }

    private fun migrateLegacy(): NetworkAppSelection {
        val legacy = runCatching { readLegacy() }.getOrNull() ?: return NetworkAppSelection()
        // A failed migration deliberately leaves the legacy value intact for a subsequent read.
        save(legacy)
        return legacy
    }

    companion object {
        private val KEY = SecureStorageKey("network.selection.v1")
    }
}

internal object NetworkAppSelectionStore {
    private const val SECURE_PREFERENCES = "network_session_selection_secure"
    private const val LEGACY_PREFERENCES = "network_session_selection"
    private const val MODE = "mode"
    private const val PACKAGES = "packages"

    fun load(context: Context): NetworkAppSelection = controller(context).load()

    fun save(context: Context, selection: NetworkAppSelection): Boolean = controller(context).save(selection)

    fun clear(context: Context): Boolean = controller(context).erase()

    private fun controller(context: Context): NetworkAppSelectionStoreController {
        val application = context.applicationContext
        val secure = AndroidKeystoreEncryptedStorage(
            preferences = application.getSharedPreferences(SECURE_PREFERENCES, Context.MODE_PRIVATE),
            keyAlias = "apk_sentinel.network_selection.v1",
            namespace = "apk_sentinel_network_selection",
        )
        val legacy = application.getSharedPreferences(LEGACY_PREFERENCES, Context.MODE_PRIVATE)
        return NetworkAppSelectionStoreController(
            storage = secure,
            readLegacy = {
                NetworkAppSelection.parse(
                    legacy.getString(MODE, NetworkAppSelectionMode.ALL_APPS_EXCEPT.name),
                    legacy.getStringSet(PACKAGES, emptySet()).orEmpty().toSet(),
                )
            },
            clearLegacy = { legacy.edit().clear().commit() },
            deleteEncryptionKey = secure::deleteEncryptionKey,
        )
    }
}

/** Retention is a durable network setting too; keep it encrypted and migrate the old key. */
internal object NetworkHistoryPolicyStore {
    private const val SECURE_PREFERENCES = "network_history_policy_secure"
    private const val LEGACY_PREFERENCES = "network_history_policy"
    private const val POLICY_KEY = "retention_policy"
    private const val MAX_BYTES = 128
    private val KEY = SecureStorageKey("network.history_policy.v1")

    fun load(context: Context): DurableHistoryRetentionPolicy {
        val application = context.applicationContext
        val secure = storage(application)
        return when (val result = secure.read(KEY)) {
            is SecureStorageResult.Success -> {
                result.value?.let { bytes ->
                    try {
                        decode(bytes) ?: DurableHistoryRetentionPolicy.SEVEN_DAYS
                    } finally {
                        bytes.fill(0)
                    }
                } ?: migrateLegacy(application, secure)
            }
            is SecureStorageResult.Failure -> readLegacy(application) ?: DurableHistoryRetentionPolicy.SEVEN_DAYS
        }
    }

    fun save(context: Context, value: DurableHistoryRetentionPolicy): Boolean {
        val application = context.applicationContext
        val secure = storage(application)
        val encoded = encode(value)
        val stored = secure.write(KEY, encoded) is SecureStorageResult.Success
        encoded.fill(0)
        if (!stored) return false
        return application.getSharedPreferences(LEGACY_PREFERENCES, Context.MODE_PRIVATE).edit().clear().commit()
    }

    fun clear(context: Context): Boolean {
        val application = context.applicationContext
        val secure = storage(application)
        val removed = secure.remove(KEY) is SecureStorageResult.Success
        val legacyCleared = application.getSharedPreferences(LEGACY_PREFERENCES, Context.MODE_PRIVATE).edit().clear().commit()
        val keyDeleted = if (removed) secure.deleteEncryptionKey() else false
        return removed && legacyCleared && keyDeleted
    }

    internal fun encode(value: DurableHistoryRetentionPolicy): ByteArray =
        "APK_SENTINEL_NETWORK_HISTORY_POLICY_VERSION=1\npolicy=${value.name}\n"
            .toByteArray(StandardCharsets.US_ASCII).also { require(it.size <= MAX_BYTES) }

    internal fun decode(bytes: ByteArray): DurableHistoryRetentionPolicy? {
        if (bytes.isEmpty() || bytes.size > MAX_BYTES) return null
        if (bytes.any { it.toInt() !in 0x20..0x7e && it.toInt() != '\n'.code }) return null
        val lines = String(bytes, StandardCharsets.US_ASCII).split('\n')
        if (lines.size != 3 || lines[2].isNotEmpty() || lines[0] != "APK_SENTINEL_NETWORK_HISTORY_POLICY_VERSION=1") return null
        val name = lines[1].substringAfter("policy=", missingDelimiterValue = "__missing__")
            .takeIf { lines[1].startsWith("policy=") }
        return DurableHistoryRetentionPolicy.entries.firstOrNull { it.name == name }
    }

    private fun migrateLegacy(context: Context, secure: AndroidKeystoreEncryptedStorage): DurableHistoryRetentionPolicy {
        val legacy = readLegacy(context) ?: return DurableHistoryRetentionPolicy.SEVEN_DAYS
        val encoded = encode(legacy)
        val stored = try {
            secure.write(KEY, encoded) is SecureStorageResult.Success
        } finally {
            encoded.fill(0)
        }
        if (stored) context.getSharedPreferences(LEGACY_PREFERENCES, Context.MODE_PRIVATE).edit().clear().commit()
        // Return the legacy value even if Keystore is unavailable so the active UI does not jump.
        return legacy
    }

    private fun readLegacy(context: Context): DurableHistoryRetentionPolicy? =
        context.getSharedPreferences(LEGACY_PREFERENCES, Context.MODE_PRIVATE)
            .getString(POLICY_KEY, null)
            ?.let { value -> DurableHistoryRetentionPolicy.entries.firstOrNull { it.name == value } }

    private fun storage(context: Context): AndroidKeystoreEncryptedStorage = AndroidKeystoreEncryptedStorage(
        preferences = context.getSharedPreferences(SECURE_PREFERENCES, Context.MODE_PRIVATE),
        keyAlias = "apk_sentinel.network_history_policy.v1",
        namespace = "apk_sentinel_network_history_policy",
    )
}

internal data class PortableNetworkSettings(
    val version: Int = PortableSettingsCodec.VERSION,
    val historyPolicy: String,
    val appSelection: NetworkAppSelection,
    val firewallRules: List<FirewallPolicyRule> = emptyList(),
)

internal data class PortableSettingsPreview(
    val settings: PortableNetworkSettings?,
    val conflicts: Set<PortableSettingsConflict> = emptySet(),
    val error: PortableSettingsError? = null,
)

internal enum class PortableSettingsConflict { ACTIVE_SESSION, REPLACES_APP_SELECTION, REPLACES_FIREWALL_RULES, REPLACES_HISTORY_POLICY }
internal enum class PortableSettingsError { EMPTY, UNSUPPORTED_VERSION, MALFORMED, TOO_LARGE, ACTIVE_SESSION }

internal sealed interface PortableSettingsApplyResult {
    data class Applied(val preview: PortableSettingsPreview, val nextSessionOnly: Boolean) : PortableSettingsApplyResult
    data class Rejected(val error: PortableSettingsError) : PortableSettingsApplyResult
}

/** Versioned, bounded text format. It contains no credentials, keys, grants, captures, or consents. */
internal object PortableSettingsCodec {
    const val VERSION = 1
    private const val MAX_BYTES = 512 * 1_024
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(settings: PortableNetworkSettings): ByteArray {
        require(settings.version == VERSION)
        val lines = buildList {
            add("APK_SENTINEL_SETTINGS_VERSION=$VERSION")
            add("historyPolicy=${settings.historyPolicy}")
            add("selectionMode=${settings.appSelection.mode.name}")
            add("selectionPackages=${encodeValue(settings.appSelection.packageNames.sorted().joinToString("\u001f"))}")
            add("ruleCount=${settings.firewallRules.size}")
            settings.firewallRules.forEachIndexed { index, rule -> add("rule.$index=${encodeValue(encodeRule(rule))}") }
        }
        return (lines.joinToString("\n") + "\n").toByteArray(StandardCharsets.UTF_8).also {
            require(it.size <= MAX_BYTES)
        }
    }

    fun decode(bytes: ByteArray): PortableSettingsPreview {
        if (bytes.isEmpty()) return PortableSettingsPreview(null, error = PortableSettingsError.EMPTY)
        if (bytes.size > MAX_BYTES) return PortableSettingsPreview(null, error = PortableSettingsError.TOO_LARGE)
        val map = runCatching {
            bytes.toString(StandardCharsets.UTF_8).lineSequence().filter { it.isNotBlank() }.associate {
                val split = it.indexOf('=')
                require(split > 0)
                it.substring(0, split) to it.substring(split + 1)
            }
        }.getOrNull() ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        val version = map["APK_SENTINEL_SETTINGS_VERSION"]?.toIntOrNull()
        if (version != VERSION) return PortableSettingsPreview(null, error = PortableSettingsError.UNSUPPORTED_VERSION)
        val policy = map["historyPolicy"] ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        if (DurableHistoryRetentionPolicy.entries.none { it.name == policy }) return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        val mode = map["selectionMode"] ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        val packages = decodeValue(map["selectionPackages"].orEmpty())?.split('\u001f')?.filter { it.isNotBlank() }?.toSet()
            ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        val selection = NetworkAppSelection.parse(mode, packages)
            ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        val count = map["ruleCount"]?.toIntOrNull()?.takeIf { it in 0..128 }
            ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
        val rules = buildList {
            repeat(count) { index ->
                val value = decodeValue(map["rule.$index"].orEmpty()) ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
                decodeRule(value)?.let(::add) ?: return PortableSettingsPreview(null, error = PortableSettingsError.MALFORMED)
            }
        }
        val settings = PortableNetworkSettings(version, policy, selection, rules)
        return PortableSettingsPreview(settings)
    }

    private fun encodeValue(value: String): String = encoder.encodeToString(value.toByteArray(StandardCharsets.UTF_8))
    private fun decodeValue(value: String): String? = runCatching { decoder.decode(value).toString(StandardCharsets.UTF_8) }.getOrNull()
    private fun encodeRule(rule: FirewallPolicyRule): String = listOf(
        rule.id, rule.action.name, rule.priority.toString(), rule.enabled.toString(),
        rule.appUids.sorted().joinToString(","), rule.appPackageNames.sorted().joinToString(","),
        rule.destinationCidrs.sortedBy { it.toString() }.joinToString(",") { it.toString() },
        rule.domainNames.sorted().joinToString(","), rule.protocols.sortedBy { it.name }.joinToString(",") { it.name },
        rule.destinationPortRange?.first?.toString().orEmpty(), rule.destinationPortRange?.last?.toString().orEmpty(),
        rule.expiresAtMillis?.toString().orEmpty(), rule.unsupportedScopes.joinToString(",") { it.name }, rule.safetyMode.name,
    ).joinToString("\u001f")

    private fun decodeRule(value: String): FirewallPolicyRule? = runCatching {
        val fields = value.split('\u001f')
        require(fields.size == 14)
        val ports = if (fields[9].isBlank() || fields[10].isBlank()) null else IntRange(fields[9].toInt(), fields[10].toInt())
        FirewallPolicyRule(
            id = fields[0], action = FirewallPolicyAction.valueOf(fields[1]), priority = fields[2].toInt(), enabled = fields[3].toBooleanStrict(),
            appUids = fields[4].csvInts(), appPackageNames = fields[5].csv(), destinationCidrs = fields[6].csv().mapNotNull { app.apksentinel.networkmonitor.IpCidr.parse(it) }.toSet(),
            domainNames = fields[7].csv(), protocols = fields[8].csv().map { TransportProtocol.valueOf(it) }.toSet(), destinationPortRange = ports,
            expiresAtMillis = fields[11].takeIf { it.isNotBlank() }?.toLong(),
            unsupportedScopes = fields[12].csv().map { app.apksentinel.networkmonitor.FirewallPolicyUnsupportedScope.valueOf(it) }.toSet(),
            safetyMode = app.apksentinel.networkmonitor.FirewallPolicySafetyMode.valueOf(fields[13]),
        )
    }.getOrNull()

    private fun String.csv(): Set<String> = split(',').filter { it.isNotBlank() }.toSet()
    private fun String.csvInts(): Set<Int> = csv().map { it.toInt() }.toSet()
}

internal object NetworkSettingsPortability {
    fun export(context: Context, firewall: List<FirewallPolicyRule>): ByteArray = PortableSettingsCodec.encode(
        PortableNetworkSettings(
            historyPolicy = NetworkHistoryComposition.currentPolicy().name,
            appSelection = NetworkAppSelectionStore.load(context),
            firewallRules = firewall,
        ),
    )

    fun preview(context: Context, bytes: ByteArray): PortableSettingsPreview {
        val parsed = PortableSettingsCodec.decode(bytes)
        val settings = parsed.settings ?: return parsed
        val conflicts = buildSet {
            if (NetworkMonitorRuntime.currentStatus().state in setOf(MonitorLifecycleState.STARTING, MonitorLifecycleState.ACTIVE, MonitorLifecycleState.STOPPING)) add(PortableSettingsConflict.ACTIVE_SESSION)
            if (settings.appSelection != NetworkAppSelectionStore.load(context)) add(PortableSettingsConflict.REPLACES_APP_SELECTION)
            if (settings.historyPolicy != NetworkHistoryComposition.currentPolicy().name) add(PortableSettingsConflict.REPLACES_HISTORY_POLICY)
            val existingRules = FirewallPolicyComposition.controller()?.current()?.rules.orEmpty()
            if (settings.firewallRules != existingRules) add(PortableSettingsConflict.REPLACES_FIREWALL_RULES)
        }
        return parsed.copy(conflicts = conflicts)
    }

    fun apply(context: Context, preview: PortableSettingsPreview, confirmed: Boolean): PortableSettingsApplyResult {
        val settings = preview.settings ?: return PortableSettingsApplyResult.Rejected(preview.error ?: PortableSettingsError.MALFORMED)
        val activeNow = NetworkMonitorRuntime.currentStatus().state in setOf(MonitorLifecycleState.STARTING, MonitorLifecycleState.ACTIVE, MonitorLifecycleState.STOPPING)
        if (!confirmed || activeNow || PortableSettingsConflict.ACTIVE_SESSION in preview.conflicts) {
            return PortableSettingsApplyResult.Rejected(if (activeNow || PortableSettingsConflict.ACTIVE_SESSION in preview.conflicts) PortableSettingsError.ACTIVE_SESSION else PortableSettingsError.MALFORMED)
        }
        if (!NetworkAppSelectionStore.save(context, settings.appSelection)) return PortableSettingsApplyResult.Rejected(PortableSettingsError.MALFORMED)
        val controller = FirewallPolicyComposition.controller()
        controller?.let { policy ->
            policy.current().rules.forEach { policy.remove(it.id) }
            settings.firewallRules.forEach { rule -> policy.upsert(rule.toDraftForImport()) }
        }
        // The retention policy is intentionally future-session scoped. The live controller is
        // not swapped under an active monitor; its persisted preference is changed by the next
        // composition initialization.
        val policy = DurableHistoryRetentionPolicy.entries.firstOrNull { it.name == settings.historyPolicy }
            ?: return PortableSettingsApplyResult.Rejected(PortableSettingsError.MALFORMED)
        val policySaved = NetworkHistoryPolicyStore.save(context, policy)
        if (!policySaved) return PortableSettingsApplyResult.Rejected(PortableSettingsError.MALFORMED)
        return PortableSettingsApplyResult.Applied(preview, nextSessionOnly = true)
    }

    private fun FirewallPolicyRule.toDraftForImport() = FirewallPolicyRuleDraft(
        id = id, action = action, priority = priority, enabled = enabled, appUids = appUids,
        appPackageNames = appPackageNames, destinationCidrs = destinationCidrs.map { it.toString() }.toSet(),
        domainNames = domainNames, protocols = protocols, destinationPortRange = destinationPortRange,
        expiresAtMillis = expiresAtMillis, unsupportedScopes = unsupportedScopes, safetyMode = safetyMode,
    )
}

private fun isValidPackageName(value: String): Boolean =
    Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+").matches(value)
