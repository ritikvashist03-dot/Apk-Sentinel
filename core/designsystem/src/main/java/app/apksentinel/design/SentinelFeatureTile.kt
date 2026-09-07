package app.apksentinel.design

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * One of eight distinct pastel tones a home-screen feature tile can take. Kept as an enum
 * (rather than a raw [Color] parameter) so every tile's colour always resolves through
 * [SentinelFeatureTilePalette] and never as a hardcoded hex value in a screen.
 */
enum class SentinelFeatureTileColor {
    BLUE,
    LAVENDER,
    PINK,
    GREEN,
    PEACH,
    CYAN,
    MINT,
    YELLOW,
}

/**
 * Container/content colour pairs for each [SentinelFeatureTileColor], for one theme (light or
 * dark). In light theme these are pale pastels with a dark, saturated label colour; in dark
 * theme they are deep muted tones with a light label colour — never a pale pastel with light
 * text, which is illegible. Every pair below clears 7:1 contrast (see design review notes),
 * well past the 4.5:1 minimum for body text.
 */
@Immutable
data class SentinelFeatureTilePalette(
    val blueContainer: Color,
    val onBlueContainer: Color,
    val lavenderContainer: Color,
    val onLavenderContainer: Color,
    val pinkContainer: Color,
    val onPinkContainer: Color,
    val greenContainer: Color,
    val onGreenContainer: Color,
    val peachContainer: Color,
    val onPeachContainer: Color,
    val cyanContainer: Color,
    val onCyanContainer: Color,
    val mintContainer: Color,
    val onMintContainer: Color,
    val yellowContainer: Color,
    val onYellowContainer: Color,
) {
    fun colorsFor(color: SentinelFeatureTileColor): Pair<Color, Color> = when (color) {
        SentinelFeatureTileColor.BLUE -> blueContainer to onBlueContainer
        SentinelFeatureTileColor.LAVENDER -> lavenderContainer to onLavenderContainer
        SentinelFeatureTileColor.PINK -> pinkContainer to onPinkContainer
        SentinelFeatureTileColor.GREEN -> greenContainer to onGreenContainer
        SentinelFeatureTileColor.PEACH -> peachContainer to onPeachContainer
        SentinelFeatureTileColor.CYAN -> cyanContainer to onCyanContainer
        SentinelFeatureTileColor.MINT -> mintContainer to onMintContainer
        SentinelFeatureTileColor.YELLOW -> yellowContainer to onYellowContainer
    }
}

internal val SentinelLightFeatureTilePalette = SentinelFeatureTilePalette(
    blueContainer = Color(0xFFD3E4FB),
    onBlueContainer = Color(0xFF12365E),
    lavenderContainer = Color(0xFFE4DBFA),
    onLavenderContainer = Color(0xFF3B2A66),
    pinkContainer = Color(0xFFFBDCE8),
    onPinkContainer = Color(0xFF6B1338),
    greenContainer = Color(0xFFD7F0DA),
    onGreenContainer = Color(0xFF134A22),
    peachContainer = Color(0xFFFBE3CE),
    onPeachContainer = Color(0xFF6E3300),
    cyanContainer = Color(0xFFCFEFF3),
    onCyanContainer = Color(0xFF0C4A52),
    mintContainer = Color(0xFFD3F3E6),
    onMintContainer = Color(0xFF0E4A34),
    yellowContainer = Color(0xFFFAEEC2),
    onYellowContainer = Color(0xFF5C4900),
)

internal val SentinelDarkFeatureTilePalette = SentinelFeatureTilePalette(
    blueContainer = Color(0xFF1B3A5C),
    onBlueContainer = Color(0xFFCFE0FA),
    lavenderContainer = Color(0xFF332457),
    onLavenderContainer = Color(0xFFE4D9FA),
    pinkContainer = Color(0xFF5C1A38),
    onPinkContainer = Color(0xFFFBD9E6),
    greenContainer = Color(0xFF1C3F26),
    onGreenContainer = Color(0xFFCDEED3),
    peachContainer = Color(0xFF5C3813),
    onPeachContainer = Color(0xFFFBDFC4),
    cyanContainer = Color(0xFF153E44),
    onCyanContainer = Color(0xFFC7EBF0),
    mintContainer = Color(0xFF173F30),
    onMintContainer = Color(0xFFCCF1E1),
    yellowContainer = Color(0xFF4A3D0F),
    onYellowContainer = Color(0xFFF5E7B4),
)

val LocalSentinelFeatureTilePalette = staticCompositionLocalOf { SentinelLightFeatureTilePalette }

/**
 * One feature, one tap, one glance. A large rounded tile with a centred icon above a short
 * bold label and nothing else — no body text, no counts, no status prose. The whole tile is
 * a single accessibility node with one [contentDescription], so a screen reader announces it
 * once rather than reading the icon and label as two separate stops.
 */
@Composable
fun SentinelFeatureTile(
    label: String,
    icon: Painter,
    color: SentinelFeatureTileColor,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    contentDescription: String = label,
) {
    val (container, content) = LocalSentinelFeatureTilePalette.current.colorsFor(color)
    Surface(
        modifier = modifier
            .sizeIn(minWidth = 48.dp, minHeight = 48.dp)
            // Slightly wider than tall. A square tile at three columns still reads as a
            // square target but wastes a third of the screen on a tall phone, which is what
            // pushed the lower tiles below the fold.
            .aspectRatio(1.08f)
            .clickable(role = Role.Button, onClick = onClick)
            .clearAndSetSemantics { this.contentDescription = contentDescription },
        shape = RoundedCornerShape(28.dp),
        color = container,
        contentColor = content,
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 6.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(icon, contentDescription = null, modifier = Modifier.sizeIn(minWidth = 30.dp, minHeight = 30.dp))
            Spacer(Modifier.padding(top = 6.dp))
            androidx.compose.material3.Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
                maxLines = 2,
            )
        }
    }
}

/** One tile's content plus the action it performs, for use with [SentinelFeatureGrid]. */
@Immutable
data class SentinelFeatureTileSpec(
    val label: String,
    val icon: Painter,
    val color: SentinelFeatureTileColor,
    val onClick: () -> Unit,
    val contentDescription: String = label,
)

/**
 * Lays feature tiles out in a simple, non-lazy grid: two columns on a normal phone width,
 * three once the available width allows it. Deliberately not a [androidx.compose.foundation.lazy.grid.LazyVerticalGrid]:
 * this grid lives inside an already vertically-scrolling screen, and a lazy grid needs a
 * bounded height to nest in a scrollable column, which a short, fixed list of feature tiles
 * does not need.
 */
@Composable
fun SentinelFeatureGrid(
    tiles: List<SentinelFeatureTileSpec>,
    modifier: Modifier = Modifier,
) {
    BoxWithConstraints(modifier = modifier.fillMaxWidth()) {
        // Three across on an ordinary phone. Two made each tile roughly half the screen
        // wide and, being square, half the screen tall, so only three rows fit and most of
        // the features sat below the fold.
        val columns = if (maxWidth >= 320.dp) 3 else 2
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            tiles.chunked(columns).forEach { row ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    row.forEach { spec ->
                        SentinelFeatureTile(
                            label = spec.label,
                            icon = spec.icon,
                            color = spec.color,
                            onClick = spec.onClick,
                            contentDescription = spec.contentDescription,
                            modifier = Modifier.weight(1f),
                        )
                    }
                    repeat(columns - row.size) {
                        Spacer(modifier = Modifier.weight(1f))
                    }
                }
            }
        }
    }
}
