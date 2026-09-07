package app.apksentinel.mobile

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

@Composable
internal fun LanguageSelector(selected: AppLanguage?, onSelected: (AppLanguage) -> Unit) {
    Column(Modifier.selectableGroup()) {
        AppLanguage.entries.forEach { option ->
            val isSelected = option == selected
            val label = stringResource(option.labelResource())
            val optionContentDescription = stringResource(option.contentDescriptionResource())
            val optionStateDescription = stringResource(
                if (isSelected) R.string.ux_language_selected else R.string.ux_language_not_selected,
            )
            androidx.compose.foundation.layout.Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp)
                    .padding(vertical = 6.dp)
                    .semantics {
                        contentDescription = optionContentDescription
                        stateDescription = optionStateDescription
                    }
                    .selectable(
                        selected = isSelected,
                        onClick = { onSelected(option) },
                        role = Role.RadioButton,
                    ),
            ) {
                RadioButton(selected = isSelected, onClick = null)
                Column {
                    Text(label, style = MaterialTheme.typography.titleSmall)
                    Text(stringResource(option.descriptionResource()), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

private fun AppLanguage.labelResource(): Int = when (this) {
    AppLanguage.SYSTEM_DEFAULT -> R.string.language_system_default
    AppLanguage.ENGLISH -> R.string.language_english
    AppLanguage.HINDI -> R.string.language_hindi
}

private fun AppLanguage.descriptionResource(): Int = when (this) {
    AppLanguage.SYSTEM_DEFAULT -> R.string.language_system_default_description
    AppLanguage.ENGLISH -> R.string.language_english_description
    AppLanguage.HINDI -> R.string.language_hindi_description
}

private fun AppLanguage.contentDescriptionResource(): Int = when (this) {
    AppLanguage.SYSTEM_DEFAULT -> R.string.language_system_default_content_description
    AppLanguage.ENGLISH -> R.string.language_english_content_description
    AppLanguage.HINDI -> R.string.language_hindi_content_description
}
