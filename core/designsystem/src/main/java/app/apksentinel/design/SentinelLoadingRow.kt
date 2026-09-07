package app.apksentinel.design

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/**
 * A visible "this is working" state.
 *
 * The app previously had no progress indicator of any kind — long operations such as
 * enumerating every installed package or parsing an APK showed a line of static text at
 * best, which is indistinguishable from being stuck. The spinner carries the fact that
 * something is happening; the label says what.
 *
 * The row is a polite live region so TalkBack announces the change rather than leaving a
 * screen-reader user with no feedback at all.
 */
@Composable
fun SentinelLoadingRow(
    label: String,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .semantics { liveRegion = LiveRegionMode.Polite },
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(20.dp),
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(label, style = MaterialTheme.typography.bodyMedium)
    }
}
