package app.apksentinel.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLanguageTest {
    @Test
    fun storedValuesResolveToTheSupportedSelection() {
        assertEquals(AppLanguage.SYSTEM_DEFAULT, AppLanguage.fromStorage(null))
        assertEquals(AppLanguage.SYSTEM_DEFAULT, AppLanguage.fromStorage("unexpected"))
        assertEquals(AppLanguage.ENGLISH, AppLanguage.fromStorage("en"))
        assertEquals(AppLanguage.HINDI, AppLanguage.fromStorage("hi"))
    }

    @Test
    fun onboardingLanguagePolicySeparatesFreshInstallFromExplicitSystemDefault() {
        val freshInstall = OnboardingLanguageState(selected = null)
        assertFalse(freshInstall.actionsEnabled)
        AppLanguage.entries.forEach { assertFalse(freshInstall.isSelected(it)) }

        val explicitSystemDefault = OnboardingLanguageState(AppLanguage.SYSTEM_DEFAULT)
        assertTrue(explicitSystemDefault.actionsEnabled)
        assertTrue(explicitSystemDefault.isSelected(AppLanguage.SYSTEM_DEFAULT))
        assertFalse(explicitSystemDefault.isSelected(AppLanguage.ENGLISH))
    }

    @Test
    fun api33LocalePolicyLeavesPlatformLocaleUntouchedWithoutLocalPreference() {
        assertEquals(null, platformLocaleLanguageTags(null))
        assertEquals("", platformLocaleLanguageTags(AppLanguage.SYSTEM_DEFAULT))
        assertEquals("en", platformLocaleLanguageTags(AppLanguage.ENGLISH))
        assertEquals("hi", platformLocaleLanguageTags(AppLanguage.HINDI))
    }
}
