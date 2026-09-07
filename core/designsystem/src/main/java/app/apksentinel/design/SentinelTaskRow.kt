package app.apksentinel.design

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * One task, one tap.
 *
 * The overview previously stacked identical cards that each ended in a full-width button,
 * so every task carried the same visual weight and nothing read as "do this first". This
 * makes the whole row the target: the user scans a title, a plain-language line and a
 * status, then taps anywhere on it.
 *
 * At a large font scale the leading icon and trailing chevron are dropped rather than
 * squeezing the text column, since the text is what carries the meaning.
 */
@Composable
fun SentinelTaskRow(
    title: String,
    supportingText: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: Painter? = null,
    chevron: Painter? = null,
    statusLabel: String? = null,
    statusTone: SentinelStatusTone = SentinelStatusTone.NEUTRAL,
    emphasis: Boolean = false,
) {
    val compactDecoration = LocalDensity.current.fontScale < 1.3f
    Card(
        modifier = modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (emphasis) {
                MaterialTheme.colorScheme.primaryContainer
            } else {
                MaterialTheme.colorScheme.surfaceContainerLow
            },
            contentColor = if (emphasis) {
                MaterialTheme.colorScheme.onPrimaryContainer
            } else {
                MaterialTheme.colorScheme.onSurface
            },
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 72.dp)
                .padding(horizontal = 18.dp, vertical = 14.dp),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (icon != null && compactDecoration) {
                Icon(icon, contentDescription = null, modifier = Modifier.size(26.dp))
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    supportingText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (statusLabel != null) {
                    SentinelStatusLabel(label = statusLabel, tone = statusTone)
                }
            }
            if (chevron != null && compactDecoration) {
                Icon(chevron, contentDescription = null, modifier = Modifier.size(22.dp))
            }
        }
    }
}
