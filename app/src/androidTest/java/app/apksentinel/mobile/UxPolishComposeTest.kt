package app.apksentinel.mobile

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertExists
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.createComposeRule
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.hasStateDescription
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.Density
import androidx.test.platform.app.InstrumentationRegistry
import app.apksentinel.design.ApkSentinelTheme
import app.apksentinel.design.KeyValueRow
import app.apksentinel.design.LocalSentinelMotion
import app.apksentinel.design.ProvideSentinelAccessibilityPreferences
import app.apksentinel.design.SentinelToggleRow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** Device-independent Compose coverage for the owned UX contract. No network or root is used. */
class UxPolishComposeTest {
    @get:Rule
    val composeRule = createComposeRule()

    @Test
    fun onboardingKeepsPrimaryActionsGatedUntilLanguageIsChosen() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        target.getSharedPreferences("app_language", Context.MODE_PRIVATE).edit().clear().commit()
        var completed = false

        composeRule.setContent {
            ApkSentinelTheme {
                OnboardingScreen(
                    onComplete = { completed = true },
                    onLanguageSelected = { _, _ -> true },
                )
            }
        }

        val next = target.getString(R.string.ux_onboarding_next)
        val skip = target.getString(R.string.ux_onboarding_skip)
        val englishOption = target.getString(R.string.language_english_content_description)
        composeRule.onNodeWithText(next).assertIsNotEnabled()
        composeRule.onNodeWithText(skip).assertIsNotEnabled()
        composeRule.onNodeWithContentDescription(englishOption).performClick()
        composeRule.onNodeWithText(next).assertIsEnabled()
        assertTrue(!completed)
    }

    @Test
    fun primaryNavigationSpeaksLabelsAndSelectedStateWhileHiddenRoutesStayOut() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        composeRule.setContent {
            ApkSentinelTheme {
                SentinelBottomNavigation(destination = Destination.APPS, onDestinationSelected = {})
            }
        }

        composeRule.onNodeWithContentDescription(target.getString(R.string.ux_destination_overview)).assertExists()
        composeRule.onNodeWithContentDescription(target.getString(R.string.ux_destination_apps)).assertIsSelected()
        composeRule.onNodeWithContentDescription(target.getString(R.string.ux_destination_network)).assertExists()
        assertTrue(Destination.PRIVACY !in Destination.entries.filter { it.showInPrimaryNavigation })
        assertTrue(Destination.HELP !in Destination.entries.filter { it.showInPrimaryNavigation })
        assertEquals(Destination.PRIVACY, restoredDestinationOrHome(Destination.PRIVACY.name))
    }

    @Test
    fun largeTextStacksTechnicalValuesInsteadOfSqueezingThem() {
        composeRule.setContent {
            CompositionLocalProvider(LocalDensity provides Density(density = 1f, fontScale = 2f)) {
                ApkSentinelTheme {
                    KeyValueRow(label = "Package", value = "com.example.सुरक्षा")
                }
            }
        }

        val label = composeRule.onNodeWithText("Package").getUnclippedBoundsInRoot()
        val value = composeRule.onNodeWithText("com.example.सुरक्षा").getUnclippedBoundsInRoot()
        assertTrue("technical value should reflow below its label", value.top > label.bottom)
    }

    @Test
    fun settingsExposeSpokenStateAndReduceMotionIsImmediate() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        composeRule.setContent {
            ProvideSentinelAccessibilityPreferences(highContrast = true, reduceMotion = true) {
                ApkSentinelTheme {
                    Column {
                        SentinelToggleRow(
                            title = "High contrast",
                            description = "Use stronger boundaries",
                            checked = true,
                            onCheckedChange = {},
                        )
                        androidx.compose.material3.Text(LocalSentinelMotion.current.contentChangeDurationMillis.toString())
                    }
                }
            }
        }

        composeRule.onNodeWithText("High contrast").assert(
            hasStateDescription(target.getString(app.apksentinel.design.R.string.sentinel_state_on)),
        )
        composeRule.onNodeWithText("0").assertExists()
    }

    @Test
    fun englishAndHindiUxResourcesAreAvailable() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val englishConfiguration = Configuration(target.resources.configuration).apply {
            setLocales(LocaleList.forLanguageTags("en"))
        }
        val english = target.createConfigurationContext(englishConfiguration)
        assertEquals("Choose your language", english.getString(R.string.ux_onboarding_language_title))
        val hindiConfiguration = Configuration(target.resources.configuration).apply {
            setLocales(LocaleList.forLanguageTags("hi"))
        }
        val hindi = target.createConfigurationContext(hindiConfiguration)
        assertEquals("अपनी भाषा चुनें", hindi.getString(R.string.ux_onboarding_language_title))
        assertEquals("चयनित", hindi.getString(R.string.ux_navigation_selected))
    }
}
