package app.apksentinel.mobile

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import app.apksentinel.design.SentinelResponsiveColumn

/** Shared scroll and width behavior for destination content. */
@Composable
internal fun ScreenColumn(padding: PaddingValues, content: @Composable () -> Unit) {
    val fontScale = LocalDensity.current.fontScale
    val sectionSpacing = if (fontScale >= 1.3f) 18.dp else 14.dp
    Column(
        Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        SentinelResponsiveColumn(verticalArrangement = Arrangement.spacedBy(sectionSpacing)) { content() }
    }
}
