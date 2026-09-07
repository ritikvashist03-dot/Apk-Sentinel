package app.apksentinel.feature.device

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import java.io.File
import java.time.LocalDate
import java.time.YearMonth
import java.time.temporal.ChronoUnit

enum class CheckState { PASS, ATTENTION, UNKNOWN }

enum class PostureEvidenceMode {
    AUTOMATICALLY_OBSERVED,
    PARTLY_OBSERVED,
    USER_GUIDED_REVIEW,
    UNAVAILABLE,
}

internal fun rootIndicatorState(indicatorFound: Boolean): CheckState =
    if (indicatorFound) CheckState.ATTENTION else CheckState.UNKNOWN

internal fun securityPatchState(raw: String, currentMonth: YearMonth): CheckState {
    if (raw.isBlank()) return CheckState.UNKNOWN
    val patchMonth = runCatching { YearMonth.parse(raw.take(7)) }.getOrNull()
        ?: return CheckState.UNKNOWN
    val ageMonths = ChronoUnit.MONTHS.between(patchMonth, currentMonth)
    return when {
        ageMonths < 0 -> CheckState.UNKNOWN
        ageMonths <= 3 -> CheckState.PASS
        else -> CheckState.ATTENTION
    }
}

data class PostureCheck(
    val id: String,
    val title: String,
    val explanation: String,
    val state: CheckState,
    val action: PostureAction? = null,
    val evidenceMode: PostureEvidenceMode = PostureEvidenceMode.AUTOMATICALLY_OBSERVED,
)

enum class PostureAction { OPEN_SECURITY, OPEN_DEVELOPER, OPEN_UPDATE, OPEN_SETTINGS_HOME }

data class DevicePostureSnapshot(
    val checks: List<PostureCheck>,
    val generatedAtMillis: Long,
) {
    val coverage: PostureCoverage
        get() = PostureCoverage(
            resultCount = checks.count { it.state != CheckState.UNKNOWN },
            verifiedCount = checks.count {
                it.state != CheckState.UNKNOWN &&
                    it.evidenceMode == PostureEvidenceMode.AUTOMATICALLY_OBSERVED
            },
            partialResultCount = checks.count {
                it.state != CheckState.UNKNOWN &&
                    it.evidenceMode == PostureEvidenceMode.PARTLY_OBSERVED
            },
            attentionCount = checks.count { it.state == CheckState.ATTENTION },
            unknownCount = checks.count { it.state == CheckState.UNKNOWN },
        )
}

data class PostureCoverage(
    val resultCount: Int,
    val verifiedCount: Int,
    val partialResultCount: Int,
    val attentionCount: Int,
    val unknownCount: Int,
)

class DevicePostureRepository(private val context: Context) {
    fun snapshot(): DevicePostureSnapshot {
        val checks = buildList {
            add(screenLockCheck())
            add(securityPatchCheck())
            add(developerOptionsCheck())
            add(usbDebuggingCheck())
            add(rootIndicatorCheck())
            add(platformEncryptionCheck())
            add(installSourcesReview())
            add(specialAccessReview())
            add(certificatesAndManagementReview())
        }
        return DevicePostureSnapshot(checks, System.currentTimeMillis())
    }

    private fun screenLockCheck(): PostureCheck {
        val manager = context.getSystemService(KeyguardManager::class.java)
        val secure = runCatching { manager?.isDeviceSecure }.getOrNull()
        return PostureCheck(
            id = "screen_lock",
            title = context.getString(R.string.check_screen_lock_title),
            explanation = when (secure) {
                true -> context.getString(R.string.check_screen_lock_active)
                false -> context.getString(R.string.check_screen_lock_inactive)
                null -> context.getString(R.string.check_screen_lock_unknown)
            },
            state = when (secure) {
                true -> CheckState.PASS
                false -> CheckState.ATTENTION
                null -> CheckState.UNKNOWN
            },
            action = if (secure == true) null else PostureAction.OPEN_SECURITY,
        )
    }

    private fun securityPatchCheck(): PostureCheck {
        val raw = Build.VERSION.SECURITY_PATCH
        val state = securityPatchState(raw, YearMonth.from(LocalDate.now()))
        return PostureCheck(
            id = "security_patch",
            title = context.getString(R.string.check_security_patch_title),
            explanation = when {
                raw.isBlank() -> context.getString(R.string.check_security_patch_missing)
                state == CheckState.PASS -> context.getString(R.string.check_security_patch_current, raw)
                state == CheckState.ATTENTION -> context.getString(R.string.check_security_patch_old, raw)
                else -> context.getString(R.string.check_security_patch_invalid, raw)
            },
            state = state,
            action = if (state == CheckState.PASS) null else PostureAction.OPEN_UPDATE,
        )
    }

    private fun developerOptionsCheck(): PostureCheck {
        val enabled = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        }.getOrNull()
        return PostureCheck(
            "developer_options",
            context.getString(R.string.check_developer_options_title),
            when (enabled) {
                true -> context.getString(R.string.check_developer_options_on)
                false -> context.getString(R.string.check_developer_options_off)
                null -> context.getString(R.string.check_developer_options_unknown)
            },
            when (enabled) { true -> CheckState.ATTENTION; false -> CheckState.PASS; null -> CheckState.UNKNOWN },
            if (enabled == false) null else PostureAction.OPEN_DEVELOPER,
        )
    }

    private fun usbDebuggingCheck(): PostureCheck {
        val enabled = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        }.getOrNull()
        return PostureCheck(
            "usb_debugging",
            context.getString(R.string.check_usb_debugging_title),
            when (enabled) {
                true -> context.getString(R.string.check_usb_debugging_on)
                false -> context.getString(R.string.check_usb_debugging_off)
                null -> context.getString(R.string.check_usb_debugging_unknown)
            },
            when (enabled) { true -> CheckState.ATTENTION; false -> CheckState.PASS; null -> CheckState.UNKNOWN },
            if (enabled == false) null else PostureAction.OPEN_DEVELOPER,
        )
    }

    private fun rootIndicatorCheck(): PostureCheck {
        val indicators = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/magisk")
        val found = indicators.any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true
        return PostureCheck(
            "root_indicators",
            context.getString(R.string.check_root_indicators_title),
            if (found) context.getString(R.string.check_root_indicators_found) else context.getString(R.string.check_root_indicators_not_found),
            rootIndicatorState(found),
            evidenceMode = PostureEvidenceMode.PARTLY_OBSERVED,
        )
    }

    @Suppress("DEPRECATION")
    private fun platformEncryptionCheck(): PostureCheck {
        val status = runCatching {
            context.getSystemService(DevicePolicyManager::class.java)?.storageEncryptionStatus
        }.getOrNull()
        val active = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE ||
            status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER
        val inactive = status == DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE
        return PostureCheck(
            "platform_encryption",
            context.getString(R.string.check_storage_protection_title),
            when {
                active -> context.getString(R.string.check_storage_protection_active)
                inactive -> context.getString(R.string.check_storage_protection_inactive)
                else -> context.getString(R.string.check_storage_protection_unknown)
            },
            when { active -> CheckState.PASS; inactive -> CheckState.ATTENTION; else -> CheckState.UNKNOWN },
            if (inactive) PostureAction.OPEN_SECURITY else null,
            PostureEvidenceMode.PARTLY_OBSERVED,
        )
    }

    private fun installSourcesReview() = PostureCheck(
        id = "install_sources_review",
        title = context.getString(R.string.check_install_sources_title),
        explanation = context.getString(R.string.check_install_sources_guided),
        state = CheckState.UNKNOWN,
        action = PostureAction.OPEN_SETTINGS_HOME,
        evidenceMode = PostureEvidenceMode.USER_GUIDED_REVIEW,
    )

    private fun specialAccessReview() = PostureCheck(
        id = "special_access_review",
        title = context.getString(R.string.check_special_access_title),
        explanation = context.getString(R.string.check_special_access_guided),
        state = CheckState.UNKNOWN,
        action = PostureAction.OPEN_SETTINGS_HOME,
        evidenceMode = PostureEvidenceMode.USER_GUIDED_REVIEW,
    )

    private fun certificatesAndManagementReview() = PostureCheck(
        id = "certificates_management_review",
        title = context.getString(R.string.check_certificates_management_title),
        explanation = context.getString(R.string.check_certificates_management_guided),
        state = CheckState.UNKNOWN,
        action = PostureAction.OPEN_SETTINGS_HOME,
        evidenceMode = PostureEvidenceMode.USER_GUIDED_REVIEW,
    )

    fun intentFor(action: PostureAction): Intent = when (action) {
        PostureAction.OPEN_SECURITY -> Intent(Settings.ACTION_SECURITY_SETTINGS)
        PostureAction.OPEN_DEVELOPER -> Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
        PostureAction.OPEN_UPDATE -> Intent(Settings.ACTION_SYSTEM_UPDATE_SETTINGS)
        PostureAction.OPEN_SETTINGS_HOME -> Intent(Settings.ACTION_SETTINGS)
    }.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun isActionAvailable(action: PostureAction): Boolean =
        intentFor(action).resolveActivity(context.packageManager) != null
}
