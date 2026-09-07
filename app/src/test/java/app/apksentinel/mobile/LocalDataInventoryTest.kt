package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Test

class LocalDataInventoryTest {
    @Test fun classifiesOnlyKnownEncryptedStoresAsHistory() {
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/apk_sentinel_network_history.xml"))
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/network_session_selection_secure.xml"))
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/network_history_policy_secure.xml"))
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/installed_app_snapshot_secure.xml"))
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/posture_observation_history.xml"))
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/remote_stream_pairing_encrypted.xml"))
        assertEquals(LocalDataCategory.ENCRYPTED_HISTORIES, LocalDataInventory.classify("shared_prefs/privacy_deletion_receipt.xml"))
        assertEquals(LocalDataCategory.THREAT_DATA, LocalDataInventory.classify("shared_prefs/threat_feed_encrypted.xml"))
        assertEquals(LocalDataCategory.DISPLAY_AND_SECURITY_PREFERENCES, LocalDataInventory.classify("shared_prefs/app_language.xml"))
        assertEquals(LocalDataCategory.REPORT_AND_WORK_CACHE, LocalDataInventory.classify("cache/redacted-reports/a.pdf"))
        assertEquals(LocalDataCategory.OTHER_APP_PRIVATE_DATA, LocalDataInventory.classify("files/other.bin"))
    }
}
