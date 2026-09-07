package app.apksentinel.mobile

import android.net.Uri
import java.time.LocalDate

internal data class ReleaseIdentity(
    val publisherName: String,
    val supportEmail: String,
    val privacyPolicyUrl: String,
    val effectiveDate: String,
)

internal fun releaseIdentityOrNull(
    publisherName: String,
    supportEmail: String,
    privacyPolicyUrl: String,
    effectiveDate: String,
): ReleaseIdentity? {
    val policyUri = runCatching { Uri.parse(privacyPolicyUrl) }.getOrNull()
    val isPublicHttps = policyUri?.scheme.equals("https", ignoreCase = true) &&
        !policyUri?.host.isNullOrBlank() && policyUri?.userInfo == null && policyUri?.fragment == null
    val hasValidEmail = supportEmail.matches(Regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"))
    val hasValidDate = runCatching { LocalDate.parse(effectiveDate) }.isSuccess
    if (publisherName.isBlank() || !hasValidEmail || !hasValidDate || !isPublicHttps) return null
    return ReleaseIdentity(publisherName, supportEmail, privacyPolicyUrl, effectiveDate)
}
