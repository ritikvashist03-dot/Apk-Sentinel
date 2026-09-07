package app.apksentinel.design

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp

/** Width classes use the current app window configuration, including split-screen and resize. */
enum class SentinelWindowWidth {
    COMPACT,
    MEDIUM,
    EXPANDED,
}

@Composable
fun currentSentinelWindowWidth(): SentinelWindowWidth = when (LocalConfiguration.current.screenWidthDp) {
    in Int.MIN_VALUE..599 -> SentinelWindowWidth.COMPACT
    in 600..839 -> SentinelWindowWidth.MEDIUM
    else -> SentinelWindowWidth.EXPANDED
}

enum class SentinelContentWidth {
    READING,
    DATA,
}

/**
 * Centres screen content at a readable width while retaining full-width compact layouts.
 * Use [READING] for forms/explanations and [DATA] for list-detail or technical evidence surfaces.
 */
@Composable
fun SentinelResponsiveColumn(
    modifier: Modifier = Modifier,
    contentWidth: SentinelContentWidth = SentinelContentWidth.READING,
    readingMaxWidth: Dp = 720.dp,
    contentPadding: PaddingValues? = null,
    verticalArrangement: Arrangement.Vertical = Arrangement.spacedBy(16.dp),
    content: @Composable ColumnScope.() -> Unit,
) {
    val windowWidth = currentSentinelWindowWidth()
    val maximumWidth = when (contentWidth) {
        SentinelContentWidth.READING -> readingMaxWidth
        SentinelContentWidth.DATA -> 1_200.dp
    }
    val resolvedPadding = contentPadding ?: PaddingValues(
        horizontal = when (windowWidth) {
            SentinelWindowWidth.COMPACT -> 20.dp
            SentinelWindowWidth.MEDIUM -> 24.dp
            SentinelWindowWidth.EXPANDED -> 32.dp
        },
        vertical = 16.dp,
    )
    Box(modifier = modifier.fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = maximumWidth)
                .fillMaxWidth()
                .padding(resolvedPadding),
            verticalArrangement = verticalArrangement,
            content = content,
        )
    }
}
