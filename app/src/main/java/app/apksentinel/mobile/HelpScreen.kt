package app.apksentinel.mobile

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import app.apksentinel.design.FullWidthOutlinedAction
import app.apksentinel.design.KeyValueRow
import app.apksentinel.design.SectionTitle
import app.apksentinel.design.SentinelCard
import app.apksentinel.design.SentinelExpandableSection

/** Local-first support and recovery. No diagnostic data is attached to external handoffs. */
@Composable
internal fun HelpScreen(padding: PaddingValues) {
    val context = LocalContext.current
    var handoffNotice by rememberSaveable { mutableStateOf<String?>(null) }
    val releaseIdentity = releaseIdentityOrNull(
        publisherName = BuildConfig.LEGAL_PUBLISHER_NAME,
        supportEmail = BuildConfig.SUPPORT_EMAIL,
        privacyPolicyUrl = BuildConfig.PRIVACY_POLICY_URL,
        effectiveDate = BuildConfig.TERMS_EFFECTIVE_DATE,
    )

    fun open(intent: Intent) {
        val opened = runCatching {
            val resolved = intent.resolveActivity(context.packageManager) ?: return@runCatching false
            context.startActivity(intent.setComponent(resolved))
            true
        }.getOrDefault(false)
        handoffNotice = context.getString(if (opened) R.string.help_handoff_opened else R.string.help_handoff_unavailable)
    }

    ScreenColumn(padding) {
        SectionTitle(stringResource(R.string.help_title), stringResource(R.string.help_subtitle))
        SentinelExpandableSection(
            title = stringResource(R.string.help_method_title),
            summary = stringResource(R.string.help_method_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.help_method_body))
            KeyValueRow(stringResource(R.string.help_version_label), BuildConfig.VERSION_NAME)
        }
        SentinelExpandableSection(
            title = stringResource(R.string.help_network_title),
            summary = stringResource(R.string.help_network_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.help_network_body))
            FullWidthOutlinedAction(
                label = stringResource(R.string.help_open_vpn_settings),
                onClick = { open(Intent(Settings.ACTION_VPN_SETTINGS)) },
            )
            FullWidthOutlinedAction(
                label = stringResource(R.string.help_open_notification_settings),
                onClick = { open(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)) },
            )
        }
        SentinelExpandableSection(
            title = stringResource(R.string.help_visibility_title),
            summary = stringResource(R.string.help_visibility_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.help_visibility_body))
        }
        SentinelExpandableSection(
            title = stringResource(R.string.help_data_title),
            summary = stringResource(R.string.help_data_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.help_data_body))
            Text(stringResource(R.string.help_export_body), style = MaterialTheme.typography.bodySmall)
        }
        SentinelExpandableSection(
            title = stringResource(R.string.help_uninstall_title),
            summary = stringResource(R.string.help_uninstall_summary),
            flat = true,
        ) {
            Text(stringResource(R.string.help_uninstall_body))
            FullWidthOutlinedAction(
                label = stringResource(R.string.help_open_security_settings),
                onClick = { open(Intent(Settings.ACTION_SECURITY_SETTINGS)) },
            )
            FullWidthOutlinedAction(
                label = stringResource(R.string.help_open_app_settings),
                onClick = { open(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${context.packageName}"))) },
            )
        }
        SentinelExpandableSection(
            title = stringResource(R.string.help_support_title),
            summary = stringResource(R.string.help_support_summary),
            flat = true,
        ) {
            if (releaseIdentity == null) {
                Text(stringResource(R.string.help_support_unconfigured))
            } else {
                Text(stringResource(R.string.help_support_body, releaseIdentity.supportEmail))
                FullWidthOutlinedAction(
                    label = stringResource(R.string.help_email_support),
                    onClick = {
                        open(
                        Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:${Uri.encode(releaseIdentity.supportEmail)}"))
                            .putExtra(Intent.EXTRA_SUBJECT, context.getString(R.string.help_email_subject)),
                        )
                    },
                )
            }
            Text(stringResource(R.string.help_support_privacy), style = MaterialTheme.typography.bodySmall)
        }
        handoffNotice?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}
