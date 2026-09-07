package app.apksentinel.design

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.sp

/**
 * APK Sentinel's fixed semantic palette. Dynamic colour is intentionally not used: a status
 * should retain its meaning regardless of the phone wallpaper.
 */
internal val SentinelLight = lightColorScheme(
    primary = Color(0xFF0B6554),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD8F0E9),
    onPrimaryContainer = Color(0xFF003D31),
    secondary = Color(0xFF4B635B),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFD2E9DF),
    onSecondaryContainer = Color(0xFF233A32),
    tertiary = Color(0xFF875400),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFFDEA6),
    onTertiaryContainer = Color(0xFF2A1800),
    error = Color(0xFFA7352D),
    onError = Color.White,
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410001),
    background = Color(0xFFF4F7F6),
    onBackground = Color(0xFF14211E),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF14211E),
    surfaceVariant = Color(0xFFE1E9E5),
    onSurfaceVariant = Color(0xFF52625D),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF3F8F6),
    surfaceContainer = Color(0xFFEDF4F1),
    surfaceContainerHigh = Color(0xFFE7EFEC),
    surfaceContainerHighest = Color(0xFFE1E9E6),
    outline = Color(0xFF6D7C77),
    outlineVariant = Color(0xFFCBD5D1),
)

internal val SentinelDark = darkColorScheme(
    primary = Color(0xFF6FD6B9),
    onPrimary = Color(0xFF00382D),
    primaryContainer = Color(0xFF1C4036),
    onPrimaryContainer = Color(0xFFB9F3DD),
    secondary = Color(0xFFB4CCC3),
    onSecondary = Color(0xFF20382F),
    secondaryContainer = Color(0xFF354D44),
    onSecondaryContainer = Color(0xFFD0E9DF),
    tertiary = Color(0xFFF2BA62),
    onTertiary = Color(0xFF462A00),
    tertiaryContainer = Color(0xFF674000),
    onTertiaryContainer = Color(0xFFFFDEA6),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = Color(0xFF0D1513),
    onBackground = Color(0xFFEEF6F3),
    surface = Color(0xFF14201D),
    onSurface = Color(0xFFEEF6F3),
    surfaceVariant = Color(0xFF404944),
    onSurfaceVariant = Color(0xFFAFBDB8),
    surfaceContainerLowest = Color(0xFF080F0D),
    surfaceContainerLow = Color(0xFF161F1C),
    surfaceContainer = Color(0xFF1A2421),
    surfaceContainerHigh = Color(0xFF242E2B),
    surfaceContainerHighest = Color(0xFF2F3936),
    outline = Color(0xFF899993),
    outlineVariant = Color(0xFF41504B),
)

internal val SentinelLightHighContrast = SentinelLight.copy(
    primary = Color(0xFF004C3E),
    onSurface = Color(0xFF0B1412),
    onSurfaceVariant = Color(0xFF27332F),
    outline = Color(0xFF2D3A35),
    error = Color(0xFF8E1511),
)

internal val SentinelDarkHighContrast = SentinelDark.copy(
    primary = Color(0xFFA8F5D8),
    onPrimary = Color(0xFF00281F),
    onSurface = Color.White,
    onSurfaceVariant = Color(0xFFD6E3DE),
    outline = Color(0xFFC8D7D1),
    error = Color(0xFFFFDAD6),
)

private val SentinelTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 32.sp,
        lineHeight = 40.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 32.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 28.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 16.sp,
        lineHeight = 24.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
)

/** Motion tokens let the app honour an explicit in-app reduced-motion preference. */
@Immutable
data class SentinelMotion(
    val reducedMotion: Boolean = false,
    val pressDurationMillis: Int = if (reducedMotion) 0 else 100,
    val stateChangeDurationMillis: Int = if (reducedMotion) 0 else 180,
    val contentChangeDurationMillis: Int = if (reducedMotion) 0 else 220,
)

val LocalSentinelMotion = staticCompositionLocalOf { SentinelMotion() }

/** Accessibility preferences supplied by the process shell; defaults preserve current behaviour. */
@Immutable
data class SentinelAccessibilityPreferences(
    val highContrast: Boolean = false,
    val reduceMotion: Boolean = false,
)

val LocalSentinelAccessibilityPreferences = staticCompositionLocalOf { SentinelAccessibilityPreferences() }

/**
 * Supplies an in-app accessibility preference without forcing feature modules to know where it
 * is stored. The shell should derive these values from a user-visible setting and, where Android
 * exposes an equivalent setting, initialise from that setting.
 */
@Composable
fun ProvideSentinelAccessibilityPreferences(
    highContrast: Boolean,
    reduceMotion: Boolean,
    content: @Composable () -> Unit,
) {
    CompositionLocalProvider(
        LocalSentinelAccessibilityPreferences provides SentinelAccessibilityPreferences(
            highContrast = highContrast,
            reduceMotion = reduceMotion,
        ),
        content = content,
    )
}

/** Semantic status colours are separate from Material's brand colours. */
@Immutable
data class SentinelStatusPalette(
    val good: Color,
    val onGood: Color,
    val goodContainer: Color,
    val onGoodContainer: Color,
    val review: Color,
    val onReview: Color,
    val reviewContainer: Color,
    val onReviewContainer: Color,
    val urgent: Color,
    val onUrgent: Color,
    val urgentContainer: Color,
    val onUrgentContainer: Color,
    val information: Color,
    val onInformation: Color,
    val informationContainer: Color,
    val onInformationContainer: Color,
)

internal val SentinelLightStatusPalette = SentinelStatusPalette(
    good = Color(0xFF146B49),
    onGood = Color(0xFF003823),
    goodContainer = Color(0xFFC1F2D3),
    onGoodContainer = Color(0xFF00301D),
    review = Color(0xFF875400),
    onReview = Color(0xFF2A1800),
    reviewContainer = Color(0xFFFFDEA6),
    onReviewContainer = Color(0xFF2A1800),
    urgent = Color(0xFFA7352D),
    onUrgent = Color(0xFF410001),
    urgentContainer = Color(0xFFFFDAD6),
    onUrgentContainer = Color(0xFF410001),
    information = Color(0xFF2D5F87),
    onInformation = Color(0xFF002E4C),
    informationContainer = Color(0xFFD0E6FF),
    onInformationContainer = Color(0xFF002E4C),
)

internal val SentinelDarkStatusPalette = SentinelStatusPalette(
    good = Color(0xFF69D49B),
    onGood = Color(0xFF003823),
    goodContainer = Color(0xFF0A5032),
    onGoodContainer = Color(0xFFA5F0C6),
    review = Color(0xFFF2BA62),
    onReview = Color(0xFF462A00),
    reviewContainer = Color(0xFF674000),
    onReviewContainer = Color(0xFFFFDEA6),
    urgent = Color(0xFFFFB4AB),
    onUrgent = Color(0xFF690005),
    urgentContainer = Color(0xFF93000A),
    onUrgentContainer = Color(0xFFFFDAD6),
    information = Color(0xFFA9C7EC),
    onInformation = Color(0xFF003355),
    informationContainer = Color(0xFF174A6C),
    onInformationContainer = Color(0xFFD3E7FF),
)

internal val SentinelLightHighContrastStatusPalette = SentinelLightStatusPalette.copy(
    good = Color(0xFF00452A),
    onGood = Color(0xFF001A0E),
    goodContainer = Color(0xFFB5F6CF),
    review = Color(0xFF5C3500),
    onReview = Color(0xFF1F1000),
    reviewContainer = Color(0xFFFFD27D),
    urgent = Color(0xFF7A0007),
    onUrgent = Color(0xFF2B0002),
    urgentContainer = Color(0xFFFFC7C2),
    information = Color(0xFF003E67),
    onInformation = Color(0xFF001A2B),
    informationContainer = Color(0xFFBBDFFF),
    onGoodContainer = Color(0xFF00170C),
    onReviewContainer = Color(0xFF1F1000),
    onUrgentContainer = Color(0xFF2B0002),
    onInformationContainer = Color(0xFF001A2B),
)

internal val SentinelDarkHighContrastStatusPalette = SentinelDarkStatusPalette.copy(
    good = Color(0xFFA5F4C6),
    onGood = Color.White,
    goodContainer = Color(0xFF004225),
    review = Color(0xFFFFD18A),
    onReview = Color.White,
    reviewContainer = Color(0xFF553100),
    urgent = Color(0xFFFFDAD6),
    onUrgent = Color.White,
    urgentContainer = Color(0xFF710006),
    information = Color(0xFFD0E6FF),
    onInformation = Color.White,
    informationContainer = Color(0xFF003C5F),
    onGoodContainer = Color(0xFFD6FFE8),
    onReviewContainer = Color(0xFFFFE7BE),
    onUrgentContainer = Color(0xFFFFE9E6),
    onInformationContainer = Color(0xFFE6F2FF),
)

val LocalSentinelStatusPalette = staticCompositionLocalOf { SentinelLightStatusPalette }

/**
 * Applies the fixed APK Sentinel palette and typography.
 *
 * The process shell may wrap this theme in [ProvideSentinelAccessibilityPreferences] to wire a
 * user preference without changing feature APIs.
 */
@Composable
fun ApkSentinelTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val accessibility = LocalSentinelAccessibilityPreferences.current
    val colors = when {
        darkTheme && accessibility.highContrast -> SentinelDarkHighContrast
        darkTheme -> SentinelDark
        accessibility.highContrast -> SentinelLightHighContrast
        else -> SentinelLight
    }
    val statusPalette = when {
        darkTheme && accessibility.highContrast -> SentinelDarkHighContrastStatusPalette
        darkTheme -> SentinelDarkStatusPalette
        accessibility.highContrast -> SentinelLightHighContrastStatusPalette
        else -> SentinelLightStatusPalette
    }
    val featureTilePalette = if (darkTheme) SentinelDarkFeatureTilePalette else SentinelLightFeatureTilePalette

    MaterialTheme(
        colorScheme = colors,
        typography = SentinelTypography,
    ) {
        CompositionLocalProvider(
            LocalSentinelMotion provides SentinelMotion(reducedMotion = accessibility.reduceMotion),
            LocalSentinelStatusPalette provides statusPalette,
            LocalSentinelFeatureTilePalette provides featureTilePalette,
        ) {
            // MaterialTheme sets the colour scheme but NOT LocalContentColor - only a
            // Surface does. Without this, any screen drawn outside a Scaffold (the
            // onboarding flow returns before one) inherits Compose's default black text
            // and is invisible in dark mode. This makes the correct content colour the
            // floor for the whole app rather than something each screen must remember.
            Surface(
                modifier = Modifier.fillMaxSize(),
                color = MaterialTheme.colorScheme.background,
                contentColor = MaterialTheme.colorScheme.onBackground,
                content = content,
            )
        }
    }
}
