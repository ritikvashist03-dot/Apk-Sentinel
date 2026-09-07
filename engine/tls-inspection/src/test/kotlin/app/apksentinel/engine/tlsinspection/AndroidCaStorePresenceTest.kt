package app.apksentinel.engine.tlsinspection

import app.apksentinel.engine.tlsinspection.android.AndroidCaStoreCertificateInstallationVerifier
import app.apksentinel.engine.tlsinspection.android.AndroidCertificateInstallApiRoute
import app.apksentinel.engine.tlsinspection.android.AndroidCertificateInstallRoutePolicy
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidCaStorePresenceTest {
    @Test
    fun malformedOrMissingPublicDerIsUnknownAndNeverInstalled() {
        val result = AndroidCaStoreCertificateInstallationVerifier.verifyPresence(byteArrayOf(1, 2, 3))
        assertEquals(AndroidCaStorePresence.CA_STORE_UNKNOWN, result.presence)
    }

    @Test
    fun typedPresenceVocabularyIsExplicit() {
        assertEquals(
            setOf("CA_STORE_PRESENT", "CA_STORE_NOT_PRESENT", "CA_STORE_UNKNOWN"),
            AndroidCaStorePresence.entries.map { it.name }.toSet(),
        )
    }

    @Test
    fun installerRoutesAreApiGuardedAndExportIsNotInstall() {
        assertEquals(AndroidCertificateInstallApiRoute.KEYCHAIN_USER_INSTALLER, AndroidCertificateInstallRoutePolicy.forApi(26))
        assertEquals(AndroidCertificateInstallApiRoute.KEYCHAIN_USER_INSTALLER, AndroidCertificateInstallRoutePolicy.forApi(29))
        assertEquals(AndroidCertificateInstallApiRoute.SAF_PUBLIC_EXPORT, AndroidCertificateInstallRoutePolicy.forApi(30))
        assertEquals(AndroidCertificateInstallApiRoute.SAF_PUBLIC_EXPORT, AndroidCertificateInstallRoutePolicy.forApi(36))
        assertEquals(AndroidCertificateInstallApiRoute.UNSUPPORTED, AndroidCertificateInstallRoutePolicy.forApi(37))
    }
}
