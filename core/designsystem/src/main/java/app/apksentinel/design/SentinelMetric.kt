package app.apksentinel.design

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * A single countable fact, shown large enough to read at a glance.
 *
 * Deliberately a COUNT, never a score. This product's own parity contract rules out a
 * single safety score ("No misleading single safety score; one clear next action"), so
 * these tiles carry things that are literally true and checkable — how many apps were
 * indexed, how many connections were seen — and leave interpretation to the row's tone.
 *
 * The whole tile is one accessibility node reading "value, label", because a screen
 * reader landing on a bare number is useless.
 */
@Composable
fun SentinelMetricTile(
    value: String,
    label: String,
    modifier: Modifier = Modifier,
    tone: SentinelStatusTone = SentinelStatusTone.NEUTRAL,
    onClick: (() -> Unit)? = null,
) {
    val palette = LocalSentinelStatusPalette.current
    val container = when (tone) {
        SentinelStatusTone.GOOD -> palette.goodContainer
        SentinelStatusTone.REVIEW -> palette.reviewContainer
        SentinelStatusTone.URGENT -> palette.urgentContainer
        SentinelStatusTone.INFORMATION -> palette.informationContainer
        SentinelStatusTone.NEUTRAL -> MaterialTheme.colorScheme.surfaceContainerHigh
    }
    val content = when (tone) {
        SentinelStatusTone.GOOD -> palette.onGoodContainer
        SentinelStatusTone.REVIEW -> palette.onReviewContainer
        SentinelStatusTone.URGENT -> palette.onUrgentContainer
        SentinelStatusTone.INFORMATION -> palette.onInformationContainer
        SentinelStatusTone.NEUTRAL -> MaterialTheme.colorScheme.onSurface
    }
    Surface(
        modifier = modifier
            .heightIn(min = 88.dp)
            .then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .clearAndSetSemantics { contentDescription = "$value $label" },
        shape = RoundedCornerShape(18.dp),
        color = container,
        contentColor = content,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
            )
            Text(
                label,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/**
 * Lays metric tiles side by side, and stacks them once text is scaled up — three columns
 * of wrapped words is worse than three rows.
 */
@Composable
fun SentinelMetricRow(
    modifier: Modifier = Modifier,
    tiles: List<@Composable (Modifier) -> Unit>,
) {
    val stack = LocalDensity.current.fontScale >= 1.3f
    if (stack) {
        Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            tiles.forEach { tile -> tile(Modifier.fillMaxWidth()) }
        }
    } else {
        Row(
            modifier = modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.Top,
        ) {
            tiles.forEach { tile -> tile(Modifier.weight(1f)) }
        }
    }
}

/**
 * A proportion shown as a bar rather than a sentence — "12 of 47 reviewed" is easier to
 * feel than to parse. Not a score: both numbers are shown so the bar cannot mislead.
 */
@Composable
fun SentinelCoverageBar(
    label: String,
    completed: Int,
    total: Int,
    modifier: Modifier = Modifier,
) {
    val safeTotal = total.coerceAtLeast(0)
    val safeCompleted = completed.coerceIn(0, if (safeTotal == 0) 0 else safeTotal)
    val fraction = if (safeTotal == 0) 0f else safeCompleted.toFloat() / safeTotal.toFloat()
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clearAndSetSemantics { contentDescription = "$label. $safeCompleted of $safeTotal." },
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(
                "$safeCompleted / $safeTotal",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.End,
            )
        }
        androidx.compose.material3.LinearProgressIndicator(
            progress = { fraction },
            modifier = Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.primary,
            trackColor = MaterialTheme.colorScheme.surfaceContainerHighest,
        )
    }
}
