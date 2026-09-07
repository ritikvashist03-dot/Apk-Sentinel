package app.apksentinel.design

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp

/**
 * Reveals a long list in bounded pages inside an already-scrolling screen.
 *
 * Screens here are built on a plain scrolling [Column], so a lazy list cannot be nested
 * without an infinite-height measure failure. The previous workaround was a hard
 * `take(n)`/`takeLast(n)` at the call site, which silently discarded the user's own
 * evidence with no way to reach it. This keeps composition bounded while still making
 * every record reachable.
 *
 * The reveal count deliberately does NOT reset when [items] grows: several callers are
 * fed by a one-second poll, and collapsing the list under the user on every tick would
 * be worse than the truncation it replaces.
 */
@Composable
fun <T> SentinelPagedList(
    items: List<T>,
    modifier: Modifier = Modifier,
    initialVisibleCount: Int = 20,
    pageSize: Int = 50,
    verticalArrangement: Arrangement.Vertical = Arrangement.spacedBy(6.dp),
    itemContent: @Composable (T) -> Unit,
) {
    var visibleCount by rememberSaveable { mutableIntStateOf(initialVisibleCount) }
    val shownCount = minOf(visibleCount, items.size)
    val remaining = items.size - shownCount
    Column(modifier = modifier, verticalArrangement = verticalArrangement) {
        for (index in 0 until shownCount) {
            itemContent(items[index])
        }
        if (items.size > initialVisibleCount) {
            Text(
                stringResource(R.string.sentinel_list_showing, shownCount, items.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (remaining > 0) {
            FullWidthOutlinedAction(
                label = stringResource(R.string.sentinel_list_show_more, minOf(remaining, pageSize)),
                onClick = { visibleCount = shownCount + pageSize },
            )
        } else if (shownCount > initialVisibleCount) {
            FullWidthOutlinedAction(
                label = stringResource(R.string.sentinel_list_show_less),
                onClick = { visibleCount = initialVisibleCount },
            )
        }
    }
}
