package app.apksentinel.design

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.border
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp

/** A calm surface with an intentionally generous touch and reading rhythm. */
@Composable
fun SentinelCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        content = {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) { content() }
        },
    )
}

/** Headings carry a TalkBack heading semantic without changing existing call sites. */
@Composable
fun SectionTitle(
    title: String,
    detail: String? = null,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(
            text = title,
            modifier = Modifier.semantics { heading() },
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.SemiBold,
        )
        if (!detail.isNullOrBlank()) {
            Text(
                text = detail,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** A single labelled, large secondary action. Long Hindi strings can wrap instead of clipping. */
@Composable
fun FullWidthOutlinedAction(
    label: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    var focused by remember { mutableStateOf(false) }
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .onFocusChanged { focused = it.isFocused }
            .border(
                width = if (focused) 2.dp else 0.dp,
                color = if (focused) MaterialTheme.colorScheme.primary else Color.Transparent,
                shape = RoundedCornerShape(12.dp),
            ),
        colors = ButtonDefaults.outlinedButtonColors(),
    ) {
        Text(
            text = label,
            modifier = Modifier.fillMaxWidth(),
            textAlign = TextAlign.Center,
        )
    }
}

/** A single labelled, large primary action for future feature adoption. */
@Composable
fun FullWidthPrimaryAction(
    label: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    modifier: Modifier = Modifier,
) {
    var focused by remember { mutableStateOf(false) }
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .onFocusChanged { focused = it.isFocused }
            .border(
                width = if (focused) 2.dp else 0.dp,
                color = if (focused) MaterialTheme.colorScheme.primary else Color.Transparent,
                shape = RoundedCornerShape(12.dp),
            ),
    ) {
        Text(
            text = label,
            modifier = Modifier.fillMaxWidth(),
            textAlign = TextAlign.Center,
        )
    }
}

/**
 * Adapts a label/value pair for large text instead of squeezing or truncating either side.
 * Values are selectable because hashes, package IDs, and IP addresses are often copied for review.
 */
@Composable
fun KeyValueRow(
    label: String,
    value: String,
    content: @Composable RowScope.() -> Unit = {},
) {
    val stackValues = LocalDensity.current.fontScale >= 1.3f
    if (stackValues) {
        Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SelectionContainer(modifier = Modifier.weight(1f)) {
                    Text(
                        text = value,
                        style = MaterialTheme.typography.bodyMedium.copy(textDirection = TextDirection.Ltr),
                        fontWeight = FontWeight.Medium,
                    )
                }
                content()
            }
        }
    } else {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(
                text = label,
                modifier = Modifier.weight(0.42f),
                style = MaterialTheme.typography.bodyMedium,
            )
            Row(
                modifier = Modifier.weight(0.58f),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SelectionContainer(modifier = Modifier.weight(1f)) {
                    Text(
                        text = value,
                        style = MaterialTheme.typography.bodyMedium.copy(textDirection = TextDirection.Ltr),
                        fontWeight = FontWeight.Medium,
                        textAlign = TextAlign.End,
                    )
                }
                content()
            }
        }
    }
}

enum class SentinelStatusTone {
    GOOD,
    REVIEW,
    URGENT,
    INFORMATION,
    NEUTRAL,
}

/** A text-first status label; colour reinforces rather than carries its meaning. */
@Composable
fun SentinelStatusLabel(
    label: String,
    tone: SentinelStatusTone,
    modifier: Modifier = Modifier,
) {
    val palette = LocalSentinelStatusPalette.current
    // Pair each container with its OWN on-container colour. This previously used onGood /
    // onReview / onUrgent / onInformation, which are authored for the bright base tone and
    // are very dark. Against a LIGHT container that reads fine, but in dark mode the
    // containers are dark too, so every status chip rendered dark-on-dark and was
    // effectively invisible (goodContainer #0A5032 on onGood #003823 is roughly 1.3:1).
    val colors = when (tone) {
        SentinelStatusTone.GOOD -> palette.goodContainer to palette.onGoodContainer
        SentinelStatusTone.REVIEW -> palette.reviewContainer to palette.onReviewContainer
        SentinelStatusTone.URGENT -> palette.urgentContainer to palette.onUrgentContainer
        SentinelStatusTone.INFORMATION -> palette.informationContainer to palette.onInformationContainer
        SentinelStatusTone.NEUTRAL -> MaterialTheme.colorScheme.surfaceVariant to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(12.dp),
        color = colors.first,
        contentColor = colors.second,
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            style = MaterialTheme.typography.labelLarge,
        )
    }
}

/**
 * An entire setting row acts as one 56dp switch target, with a spoken on/off consequence.
 * The nested Switch has no click handler so TalkBack does not expose two competing controls.
 */
@Composable
fun SentinelToggleRow(
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    enabled: Boolean = true,
    onStateLabel: String? = null,
    offStateLabel: String? = null,
    modifier: Modifier = Modifier,
) {
    val resolvedOnStateLabel = onStateLabel ?: stringResource(R.string.sentinel_state_on)
    val resolvedOffStateLabel = offStateLabel ?: stringResource(R.string.sentinel_state_off)
    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .toggleable(
                value = checked,
                enabled = enabled,
                role = Role.Switch,
                onValueChange = onCheckedChange,
            )
            .semantics(mergeDescendants = true) {
                stateDescription = if (checked) resolvedOnStateLabel else resolvedOffStateLabel
            }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = null, enabled = enabled)
    }
}

fun ColorScheme.statusColor(isGood: Boolean, isWarning: Boolean = false): Color = when {
    isGood -> primary
    isWarning -> tertiary
    else -> error
}
