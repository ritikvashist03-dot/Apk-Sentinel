package app.apksentinel.mobile

import app.apksentinel.networkmonitor.FirewallPolicyAction
import app.apksentinel.networkmonitor.FirewallPolicyRule
import app.apksentinel.networkmonitor.FirewallPolicySafetyMode
import app.apksentinel.networkmonitor.IpCidr
import app.apksentinel.networkmonitor.DurableHistoryRetentionPolicy
import app.apksentinel.networkmonitor.TransportProtocol
import app.apksentinel.core.security.EncryptedStorage
import app.apksentinel.core.security.SecureStorageFailure
import app.apksentinel.core.security.SecureStorageKey
import app.apksentinel.core.security.SecureStorageResult
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkSessionSettingsTest {
    @Test
    fun versionedCodecRoundTripsSelectionAndNarrowRuleWithoutSecrets() {
        val rule = FirewallPolicyRule(
            id = "allow-https",
            action = FirewallPolicyAction.ALLOW,
            priority = 0,
            enabled = true,
            appUids = emptySet(),
            appPackageNames = setOf("com.example.app"),
            destinationCidrs = setOf(requireNotNull(IpCidr.parse("203.0.113.0/24"))),
            domainNames = setOf("example.test"),
            protocols = setOf(TransportProtocol.TCP),
            destinationPortRange = 443..443,
            expiresAtMillis = null,
            unsupportedScopes = emptySet(),
            safetyMode = FirewallPolicySafetyMode.ATTRIBUTED_APP_ONLY,
        )
        val original = PortableNetworkSettings(
            historyPolicy = "SEVEN_DAYS",
            appSelection = NetworkAppSelection(NetworkAppSelectionMode.ONLY_APPS, setOf("com.example.app")),
            firewallRules = listOf(rule),
        )

        val decoded = PortableSettingsCodec.decode(PortableSettingsCodec.encode(original))

        assertEquals(null, decoded.error)
        assertEquals(original, decoded.settings)
    }

    @Test
    fun codecRejectsOversizedAndFutureVersionsBeforeApplying() {
        assertEquals(PortableSettingsError.TOO_LARGE, PortableSettingsCodec.decode(ByteArray(512 * 1_024 + 1)).error)
        val future = "APK_SENTINEL_SETTINGS_VERSION=2\n".toByteArray()
        assertEquals(PortableSettingsError.UNSUPPORTED_VERSION, PortableSettingsCodec.decode(future).error)
    }

    @Test
    fun onlyAppsRequiresAtLeastOneValidPackage() {
        assertTrue(NetworkAppSelection.parse(NetworkAppSelectionMode.ONLY_APPS.name, emptySet()) == null)
        assertTrue(NetworkAppSelection.parse(NetworkAppSelectionMode.ONLY_APPS.name, setOf("com.example.app")) != null)
        assertTrue(NetworkAppSelection.parse(NetworkAppSelectionMode.ONLY_APPS.name, setOf("not valid")) == null)
    }

    @Test
    fun installedAppPickerSearchIsBoundedAndMatchesLabelOrPackage() {
        val apps = listOf(
            NetworkSelectableApp("Camera", "com.example.camera", false),
            NetworkSelectableApp("Notes", "com.example.notes", false),
        )
        assertEquals(listOf("com.example.camera"), InstalledAppSelectionCatalog.filter(apps, "cam").map { it.packageName })
        assertEquals(listOf("com.example.notes"), InstalledAppSelectionCatalog.filter(apps, "NOTES").map { it.packageName })
    }

    @Test
    fun installedAppLabelsRemoveBidiControlsAndStayBoundedWithPackageFallback() {
        val normalized = normalizeInstalledAppLabel("Invoice\u202Egpj.exe\n" + "x".repeat(200), "com.example.invoice")

        assertFalse(normalized.contains('\u202E'))
        assertFalse(normalized.contains('\n'))
        assertTrue(normalized.codePointCount(0, normalized.length) <= 96)
        assertEquals("com.example.invoice", normalizeInstalledAppLabel("\u202E\n", "com.example.invoice"))
    }

    @Test
    fun selectionCodecRejectsCorruptionAndOversizedPayloads() {
        assertNull(NetworkAppSelectionCodec.decode("not a selection\n".toByteArray(StandardCharsets.US_ASCII)))
        assertNull(NetworkAppSelectionCodec.decode(ByteArray(NetworkAppSelectionCodec.MAX_BYTES + 1)))
        val valid = NetworkAppSelectionCodec.encode(NetworkAppSelection(NetworkAppSelectionMode.ONLY_APPS, setOf("com.example.app")))
        assertNotNull(NetworkAppSelectionCodec.decode(valid))
        assertNull(NetworkAppSelectionCodec.decode(valid + byteArrayOf('x'.code.toByte())))
    }

    @Test
    fun encryptedHistoryPolicyCodecIsBoundedAndFailsClosed() {
        val encoded = NetworkHistoryPolicyStore.encode(DurableHistoryRetentionPolicy.THIRTY_DAYS)
        assertEquals(DurableHistoryRetentionPolicy.THIRTY_DAYS, NetworkHistoryPolicyStore.decode(encoded))
        assertNull(NetworkHistoryPolicyStore.decode("policy=THIRTY_DAYS\n".toByteArray(StandardCharsets.US_ASCII)))
        assertNull(NetworkHistoryPolicyStore.decode(ByteArray(129)))
    }

    @Test
    fun failedEncryptionRetainsLegacySelectionWithoutClearingIt() {
        val legacy = NetworkAppSelection(NetworkAppSelectionMode.ONLY_APPS, setOf("com.example.app"))
        val storage = TestSelectionStorage().also { it.failRead = true; it.failWrite = true }
        val cleared = AtomicBoolean(false)
        val controller = NetworkAppSelectionStoreController(
            storage = storage,
            readLegacy = { legacy },
            clearLegacy = { cleared.set(true); true },
        )

        assertEquals(legacy, controller.load())
        assertFalse(cleared.get())
    }

    @Test
    fun corruptedEncryptedSelectionFailsClosedInsteadOfFallingBackToPlaintext() {
        val storage = TestSelectionStorage().also { it.bytes = "corrupt".toByteArray(StandardCharsets.US_ASCII) }
        val controller = NetworkAppSelectionStoreController(
            storage = storage,
            readLegacy = { NetworkAppSelection(NetworkAppSelectionMode.ONLY_APPS, setOf("com.example.app")) },
        )

        assertEquals(NetworkAppSelection(), controller.load())
    }

    @Test
    fun successfulMigrationClearsLegacyAndEraseRemovesCiphertextAndKey() {
        val legacy = NetworkAppSelection(NetworkAppSelectionMode.ONLY_APPS, setOf("com.example.app"))
        val storage = TestSelectionStorage()
        val legacyCleared = AtomicBoolean(false)
        val keyDeleted = AtomicBoolean(false)
        val controller = NetworkAppSelectionStoreController(
            storage = storage,
            readLegacy = { legacy },
            clearLegacy = { legacyCleared.set(true); true },
            deleteEncryptionKey = { keyDeleted.set(true); true },
        )

        assertEquals(legacy, controller.load())
        assertTrue(legacyCleared.get())
        assertNotNull(storage.bytes)
        assertTrue(controller.erase())
        assertNull(storage.bytes)
        assertTrue(keyDeleted.get())
    }

    private class TestSelectionStorage : EncryptedStorage {
        var bytes: ByteArray? = null
        var failRead = false
        var failWrite = false

        override fun write(key: SecureStorageKey, plaintext: ByteArray): SecureStorageResult<Unit> {
            if (failWrite) return SecureStorageResult.Failure(SecureStorageFailure.BACKING_STORE_FAILURE)
            bytes = plaintext.copyOf()
            return SecureStorageResult.Success(Unit)
        }

        override fun read(key: SecureStorageKey): SecureStorageResult<ByteArray?> =
            if (failRead) SecureStorageResult.Failure(SecureStorageFailure.BACKING_STORE_FAILURE)
            else SecureStorageResult.Success(bytes?.copyOf())

        override fun remove(key: SecureStorageKey): SecureStorageResult<Unit> {
            bytes = null
            return SecureStorageResult.Success(Unit)
        }
    }
}
