package app.apksentinel.mobile

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.animation.core.tween
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.apksentinel.design.FullWidthPrimaryAction
import app.apksentinel.design.LocalSentinelMotion
import app.apksentinel.design.SentinelCard

internal object OnboardingAccessibilityContract {
    /** One live region on the incoming heading prevents duplicate page announcements. */
    const val LIVE_REGION_NODE_COUNT = 1

    fun pageAnnouncement(
        title: String,
        progress: String,
        sentenceSeparator: String = "।",
    ): String = "$title$sentenceSeparator $progress"

    fun contentChangeDurationMillis(reducedMotion: Boolean, configuredDurationMillis: Int): Int =
        if (reducedMotion) 0 else configuredDurationMillis.coerceAtLeast(0)
}

@Composable
internal fun OnboardingScreen(
    onComplete: () -> Unit,
    onLanguageSelected: ((android.content.Context, AppLanguage) -> Boolean)? = null,
) {
    val context = LocalContext.current
    var selectedLanguage by rememberSaveable { mutableStateOf(AppLocaleController.explicitSelection(context)) }
    var page by rememberSaveable { mutableIntStateOf(0) }
    val languageState = OnboardingLanguageState(selectedLanguage)
    val pages = listOf(
        Triple(R.string.ux_onboarding_understand_title, R.string.ux_onboarding_understand_body, R.string.ux_onboarding_understand_detail),
        Triple(R.string.ux_onboarding_private_title, R.string.ux_onboarding_private_body, R.string.ux_onboarding_private_detail),
        Triple(R.string.ux_onboarding_honest_title, R.string.ux_onboarding_honest_body, R.string.ux_onboarding_honest_detail),
    )
    val motion = LocalSentinelMotion.current
    val selectLanguage: (AppLanguage) -> Boolean = onLanguageSelected?.let { callback ->
        { language -> callback(context, language) }
    } ?: { language -> AppLocaleController.select(context, language) }
    Column(
        Modifier
            .fillMaxSize()
            // This screen renders before the Scaffold, so it has to consume the system bar
            // insets itself; without this the title sits under the status bar clock.
            .windowInsetsPadding(WindowInsets.systemBars)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 22.dp, vertical = 20.dp),
        verticalArrangement = Arrangement.spacedBy(28.dp),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.ux_onboarding_language_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.ux_onboarding_language_body), style = MaterialTheme.typography.bodyMedium)
            LanguageSelector(
                selected = selectedLanguage,
                onSelected = { language ->
                    if (selectLanguage(language)) {
                        selectedLanguage = language
                    }
                },
            )
            if (!languageState.actionsEnabled) Text(stringResource(R.string.ux_onboarding_language_required), style = MaterialTheme.typography.bodySmall)
            Text(
                stringResource(R.string.ux_onboarding_progress, page + 1, pages.size),
                modifier = Modifier.semantics {
                    progressBarRangeInfo = ProgressBarRangeInfo(
                        current = (page + 1).toFloat(),
                        range = 1f..pages.size.toFloat(),
                        steps = pages.size - 2,
                    )
                },
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.primary,
            )
            Spacer(Modifier.height(12.dp))
            AnimatedContent(
                targetState = page,
                transitionSpec = {
                    val durationMillis = OnboardingAccessibilityContract.contentChangeDurationMillis(
                        reducedMotion = motion.reducedMotion,
                        configuredDurationMillis = motion.contentChangeDurationMillis,
                    )
                    if (durationMillis == 0) {
                        EnterTransition.None togetherWith ExitTransition.None
                    } else {
                        fadeIn(tween(durationMillis)) togetherWith fadeOut(tween(durationMillis))
                    }
                },
            ) { pageIndex ->
                val current = pages[pageIndex]
                val pageAnnouncement = OnboardingAccessibilityContract.pageAnnouncement(
                    title = stringResource(current.first),
                    progress = stringResource(R.string.ux_onboarding_progress, pageIndex + 1, pages.size),
                    sentenceSeparator = stringResource(R.string.ux_onboarding_accessibility_separator),
                )
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        stringResource(current.first),
                        // The incoming heading is the single polite live region. Its localized
                        // title plus progress is announced once; the visible progress text stays
                        // a normal, non-live semantics node to avoid duplicate TalkBack speech.
                        modifier = Modifier.semantics {
                            heading()
                            liveRegion = LiveRegionMode.Polite
                            contentDescription = pageAnnouncement
                        },
                        style = MaterialTheme.typography.headlineMedium,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(stringResource(current.second), style = MaterialTheme.typography.bodyLarge)
                    SentinelCard {
                        Text(stringResource(current.third), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            FullWidthPrimaryAction(
                label = stringResource(if (page == pages.lastIndex) R.string.ux_onboarding_start else R.string.ux_onboarding_next),
                onClick = { if (page == pages.lastIndex) onComplete() else page++ },
                enabled = languageState.actionsEnabled,
            )
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                TextButton(onClick = onComplete, enabled = languageState.actionsEnabled) { Text(stringResource(R.string.ux_onboarding_skip)) }
            }
            Text(stringResource(R.string.ux_onboarding_no_terms_consent), style = MaterialTheme.typography.bodySmall)
        }
    }
}
