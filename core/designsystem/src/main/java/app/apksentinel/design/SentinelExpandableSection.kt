package app.apksentinel.design

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * One level of the part → subpart structure: a titled section that starts collapsed and
 * shows a one-line summary of what is inside.
 *
 * The screens here were long flat scrolls where a technical subsection sat at the same
 * visual level as a primary action, so a non-technical reader met everything at once.
 * Collapsing by default means the page answers "what is here?" before "what are the
 * details?", and the summary line means opening a section is an informed choice rather
 * than a guess.
 *
 * Expansion state is saveable, so rotating the device does not collapse everything the
 * user had opened. Motion is skipped when the user has asked for reduced motion.
 */
@Composable
fun SentinelExpandableSection(
    title: String,
    summary: String,
    modifier: Modifier = Modifier,
    icon: Painter? = null,
    chevron: Painter? = null,
    statusLabel: String? = null,
    statusTone: SentinelStatusTone = SentinelStatusTone.NEUTRAL,
    initiallyExpanded: Boolean = false,
    /**
     * Renders as a plain row with a divider rather than a filled, rounded container. Use
     * this when several sections sit together as a list: repeated containers read as a
     * stack of boxes rather than a list of choices.
     */
    flat: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    var expanded by rememberSaveable(title) { mutableStateOf(initiallyExpanded) }
    val motion = LocalSentinelMotion.current
    val showDecoration = LocalDensity.current.fontScale < 1.3f
    val rotation by animateFloatAsState(
        targetValue = if (expanded) 90f else 0f,
        animationSpec = tween(if (motion.reducedMotion) 0 else motion.contentChangeDurationMillis),
        label = "sentinel-section-chevron",
    )
    val expandLabel = stringResource(
        if (expanded) R.string.sentinel_section_expanded else R.string.sentinel_section_collapsed,
    )
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = if (flat) RectangleShape else RoundedCornerShape(20.dp),
        color = if (flat) Color.Transparent else MaterialTheme.colorScheme.surfaceContainerLow,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 64.dp)
                    .clickable(role = Role.Button) { expanded = !expanded }
                    .semantics { stateDescription = expandLabel }
                    .padding(
                        horizontal = if (flat) 4.dp else 18.dp,
                        vertical = 14.dp,
                    ),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (icon != null && showDecoration) {
                    Icon(icon, contentDescription = null, modifier = Modifier.size(24.dp))
                }
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(3.dp),
                ) {
                    Text(
                        title,
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        summary,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (statusLabel != null) {
                        SentinelStatusLabel(label = statusLabel, tone = statusTone)
                    }
                }
                if (chevron != null && showDecoration) {
                    Icon(
                        chevron,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp).rotate(rotation),
                    )
                }
            }
            AnimatedVisibility(
                visible = expanded,
                enter = if (motion.reducedMotion) fadeIn(tween(0)) else fadeIn() + expandVertically(),
                exit = if (motion.reducedMotion) fadeOut(tween(0)) else fadeOut() + shrinkVertically(),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(
                        start = if (flat) 4.dp else 18.dp,
                        end = if (flat) 4.dp else 18.dp,
                        bottom = 18.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    content = content,
                )
            }
            // A flat row has no container of its own, so a divider is what separates it
            // from the next item in the list.
            if (flat) HorizontalDivider()
        }
    }
}
