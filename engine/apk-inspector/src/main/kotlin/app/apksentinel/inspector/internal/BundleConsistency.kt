package app.apksentinel.inspector.internal

import app.apksentinel.inspector.BundleApkEntry
import app.apksentinel.inspector.BundleApkRole
import app.apksentinel.inspector.BundleLimitationCode
import app.apksentinel.inspector.SignatureVerificationStatus
import java.util.Locale

/** Compares bounded nested identity and signer evidence without making install claims. */
internal fun bundleIdentityAndSignerLimitations(
    entries: List<BundleApkEntry>,
): Set<BundleLimitationCode> {
    val limitations = linkedSetOf<BundleLimitationCode>()
    val valid = entries.filter { it.archive?.containsAndroidManifest == true }
    val bases = valid.filter { it.role == BundleApkRole.BASE }
    if (bases.isEmpty()) {
        limitations += BundleLimitationCode.MISSING_BASE
        limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
    }
    if (bases.size > 1) {
        limitations += BundleLimitationCode.DUPLICATE_BASE
        limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
    }
    val base = bases.firstOrNull()
    val baseManifest = base?.manifest
    val baseSigning = base?.signing
    if (baseManifest == null) limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
    if (baseSigning?.status != SignatureVerificationStatus.VERIFIED || baseSigning?.certificates.orEmpty().isEmpty()) {
        limitations += BundleLimitationCode.SIGNER_UNAVAILABLE
        limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
    }
    valid.filter { it.path != base?.path }.forEach { child ->
        val manifest = child.manifest
        if (manifest == null) {
            limitations += BundleLimitationCode.NESTED_EVIDENCE_INCOMPLETE
            limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
        } else if (baseManifest != null && (
            manifest.packageName != baseManifest.packageName ||
                (manifest.versionCode != null && baseManifest.versionCode != null && manifest.versionCode != baseManifest.versionCode) ||
                (manifest.versionName != null && baseManifest.versionName != null && manifest.versionName != baseManifest.versionName)
            )
        ) limitations += BundleLimitationCode.IDENTITY_MISMATCH

        val baseSigners = baseSigning?.certificates.orEmpty().map { normalizeSigner(it.sha256) }.toSet()
        val childSigners = child.signing?.certificates.orEmpty().map { normalizeSigner(it.sha256) }.toSet()
        if (child.signing?.status != SignatureVerificationStatus.VERIFIED || childSigners.isEmpty()) {
            limitations += BundleLimitationCode.SIGNER_UNAVAILABLE
            limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
        }
        if (baseSigners.isNotEmpty() && childSigners.isNotEmpty() && baseSigners != childSigners) {
            limitations += BundleLimitationCode.SIGNER_MISMATCH
            limitations += BundleLimitationCode.IDENTITY_UNAVAILABLE
        }
        if (child.signing?.status == SignatureVerificationStatus.UNAVAILABLE) {
            limitations += BundleLimitationCode.SIGNER_UNAVAILABLE
        }
    }
    if (baseSigning?.status == SignatureVerificationStatus.UNAVAILABLE) {
        limitations += BundleLimitationCode.SIGNER_UNAVAILABLE
    }
    return limitations
}

private fun normalizeSigner(value: String): String = value.filter(Char::isLetterOrDigit).lowercase(Locale.ROOT)
