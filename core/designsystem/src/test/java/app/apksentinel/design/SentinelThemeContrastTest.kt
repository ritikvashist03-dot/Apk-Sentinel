package app.apksentinel.design

import androidx.compose.material3.ColorScheme
import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards every semantic foreground/background pairing the design system hands to a screen,
 * in BOTH the light and dark palettes.
 *
 * This exists because [SentinelStatusLabel] once paired each status container with the
 * bright base tone's `on*` colour (e.g. `goodContainer` with `onGood`) instead of its own
 * `on*Container` colour. That read fine in light mode, where containers are pale, but in
 * dark mode both colours are dark and the pairing measured roughly 1.3:1 -- a status chip
 * that was there but invisible. A plain visual pass on one theme would not have caught it;
 * only checking both themes' actual contrast numbers does.
 *
 * The math below is the standard WCAG 2.x contrast-ratio formula:
 * `(L1 + 0.05) / (L2 + 0.05)`, where L1/L2 are the relative luminances of the lighter and
 * darker colour and each channel is linearised from sRGB before the 0.2126/0.7152/0.0722
 * weighting is applied. Body text must clear 4.5:1; large (>=18sp, or >=14sp bold) text may
 * clear 3:1.
 */
class SentinelThemeContrastTest {

    private fun linearize(channel: Float): Double {
        val c = channel.toDouble()
        return if (c <= 0.03928) c / 12.92 else Math.pow((c + 0.055) / 1.055, 2.4)
    }

    private fun relativeLuminance(color: Color): Double =
        0.2126 * linearize(color.red) + 0.7152 * linearize(color.green) + 0.0722 * linearize(color.blue)

    private fun contrastRatio(a: Color, b: Color): Double {
        val la = relativeLuminance(a)
        val lb = relativeLuminance(b)
        val lighter = maxOf(la, lb)
        val darker = minOf(la, lb)
        return (lighter + 0.05) / (darker + 0.05)
    }

    private fun assertAccessible(
        label: String,
        foreground: Color,
        background: Color,
        minimum: Double = NORMAL_TEXT_MINIMUM,
    ) {
        val ratio = contrastRatio(foreground, background)
        assertTrue(
            "$label must clear ${minimum}:1 but measured %.2f:1 (fg=$foreground, bg=$background)"
                .format(ratio),
            ratio >= minimum,
        )
    }

    // ---- SentinelStatusPalette --------------------------------------------------------

    @Test
    fun lightStatusPaletteContainersAreReadable() = assertStatusPaletteContainers("light", SentinelLightStatusPalette)

    @Test
    fun darkStatusPaletteContainersAreReadable() = assertStatusPaletteContainers("dark", SentinelDarkStatusPalette)

    @Test
    fun lightHighContrastStatusPaletteContainersAreReadable() =
        assertStatusPaletteContainers("light-high-contrast", SentinelLightHighContrastStatusPalette)

    @Test
    fun darkHighContrastStatusPaletteContainersAreReadable() =
        assertStatusPaletteContainers("dark-high-contrast", SentinelDarkHighContrastStatusPalette)

    private fun assertStatusPaletteContainers(name: String, palette: SentinelStatusPalette) {
        assertAccessible("[$name] onGoodContainer/goodContainer", palette.onGoodContainer, palette.goodContainer)
        assertAccessible("[$name] onReviewContainer/reviewContainer", palette.onReviewContainer, palette.reviewContainer)
        assertAccessible("[$name] onUrgentContainer/urgentContainer", palette.onUrgentContainer, palette.urgentContainer)
        assertAccessible(
            "[$name] onInformationContainer/informationContainer",
            palette.onInformationContainer,
            palette.informationContainer,
        )
    }

    // The bright base tones (good/review/urgent/information) are also drawn directly as
    // text/icon colour on a plain surface -- e.g. SentinelLoadingRow's spinner tint and any
    // future status text that skips the container entirely.
    @Test
    fun lightStatusPaletteBaseTonesReadOnSurface() = assertStatusPaletteOnSurface("light", SentinelLightStatusPalette, SentinelLight)

    @Test
    fun darkStatusPaletteBaseTonesReadOnSurface() = assertStatusPaletteOnSurface("dark", SentinelDarkStatusPalette, SentinelDark)

    private fun assertStatusPaletteOnSurface(name: String, palette: SentinelStatusPalette, scheme: ColorScheme) {
        assertAccessible("[$name] good/surface", palette.good, scheme.surface)
        assertAccessible("[$name] review/surface", palette.review, scheme.surface)
        assertAccessible("[$name] urgent/surface", palette.urgent, scheme.surface)
        assertAccessible("[$name] information/surface", palette.information, scheme.surface)
    }

    // ---- Core Material colour scheme ---------------------------------------------------

    @Test
    fun lightColorSchemeCorePairsAreReadable() = assertColorScheme("light", SentinelLight)

    @Test
    fun darkColorSchemeCorePairsAreReadable() = assertColorScheme("dark", SentinelDark)

    @Test
    fun lightHighContrastColorSchemeCorePairsAreReadable() = assertColorScheme("light-high-contrast", SentinelLightHighContrast)

    @Test
    fun darkHighContrastColorSchemeCorePairsAreReadable() = assertColorScheme("dark-high-contrast", SentinelDarkHighContrast)

    private fun assertColorScheme(name: String, scheme: ColorScheme) {
        assertAccessible("[$name] onPrimary/primary", scheme.onPrimary, scheme.primary)
        assertAccessible("[$name] onPrimaryContainer/primaryContainer", scheme.onPrimaryContainer, scheme.primaryContainer)
        assertAccessible("[$name] onSecondary/secondary", scheme.onSecondary, scheme.secondary)
        assertAccessible("[$name] onSecondaryContainer/secondaryContainer", scheme.onSecondaryContainer, scheme.secondaryContainer)
        assertAccessible("[$name] onTertiary/tertiary", scheme.onTertiary, scheme.tertiary)
        assertAccessible("[$name] onTertiaryContainer/tertiaryContainer", scheme.onTertiaryContainer, scheme.tertiaryContainer)
        assertAccessible("[$name] onError/error", scheme.onError, scheme.error)
        assertAccessible("[$name] onErrorContainer/errorContainer", scheme.onErrorContainer, scheme.errorContainer)
        assertAccessible("[$name] onBackground/background", scheme.onBackground, scheme.background)
        assertAccessible("[$name] onSurface/surface", scheme.onSurface, scheme.surface)
        assertAccessible("[$name] onSurfaceVariant/surface", scheme.onSurfaceVariant, scheme.surface)
        assertAccessible("[$name] onSurfaceVariant/surfaceVariant", scheme.onSurfaceVariant, scheme.surfaceVariant)
        assertAccessible("[$name] onSurface/surfaceContainerLowest", scheme.onSurface, scheme.surfaceContainerLowest)
        assertAccessible("[$name] onSurface/surfaceContainerLow", scheme.onSurface, scheme.surfaceContainerLow)
        assertAccessible("[$name] onSurface/surfaceContainer", scheme.onSurface, scheme.surfaceContainer)
        assertAccessible("[$name] onSurface/surfaceContainerHigh", scheme.onSurface, scheme.surfaceContainerHigh)
        assertAccessible("[$name] onSurface/surfaceContainerHighest", scheme.onSurface, scheme.surfaceContainerHighest)
        // Outline is a boundary/large-glyph colour, never body text, so the large-text floor applies.
        assertAccessible("[$name] outline/surface", scheme.outline, scheme.surface, minimum = LARGE_TEXT_MINIMUM)
    }

    // ---- Home-screen feature tile palette ----------------------------------------------

    @Test
    fun lightFeatureTilePaletteContainersAreReadable() = assertFeatureTilePalette("light", SentinelLightFeatureTilePalette)

    @Test
    fun darkFeatureTilePaletteContainersAreReadable() = assertFeatureTilePalette("dark", SentinelDarkFeatureTilePalette)

    private fun assertFeatureTilePalette(name: String, palette: SentinelFeatureTilePalette) {
        for (tone in SentinelFeatureTileColor.entries) {
            val (container, content) = palette.colorsFor(tone)
            assertAccessible("[$name] on${tone}Container/${tone}Container", content, container)
        }
    }

    private companion object {
        const val NORMAL_TEXT_MINIMUM = 4.5
        const val LARGE_TEXT_MINIMUM = 3.0
    }
}
