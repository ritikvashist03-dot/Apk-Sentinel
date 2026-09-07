package app.apksentinel.inspector.internal

import app.apksentinel.inspector.SignatureVerificationStatus
import app.apksentinel.inspector.SigningCertificateSummary
import app.apksentinel.inspector.SigningDiagnosticCode
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.SigningSummary
import app.apksentinel.inspector.SigningUnavailable
import com.android.apksig.ApkVerifier
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Locale

internal data class SigningInspectionOutcome(
    val signing: SigningSummary,
    val failure: SigningUnavailable?,
)

/**
 * ApkVerifier validates APK Signature Scheme v1-v4 when the corresponding
 * signatures are present. Scheme names are read defensively for apksig API
 * compatibility across matching Android build-tool releases.
 */
internal class ApkSigningInspector {
    fun inspect(apkFile: File): SigningInspectionOutcome =
        try {
            val result = ApkVerifier.Builder(apkFile).build().verify()
            val status = if (result.isVerified) {
                SignatureVerificationStatus.VERIFIED
            } else {
                SignatureVerificationStatus.NOT_VERIFIED
            }
            SigningInspectionOutcome(
                signing = SigningSummary(
                    status = status,
                    certificates = result.signerCertificates.map { certificate ->
                        certificate.toSummary()
                    },
                    verifiedSchemes = readVerifiedSchemes(result),
                    diagnostics = if (status == SignatureVerificationStatus.NOT_VERIFIED) {
                        listOf(SigningDiagnosticCode.SIGNATURE_NOT_VALID)
                    } else {
                        emptyList()
                    },
                ),
                failure = null,
            )
        } catch (error: Exception) {
            SigningInspectionOutcome(
                signing = SigningSummary(
                    status = SignatureVerificationStatus.UNAVAILABLE,
                    certificates = emptyList(),
                    verifiedSchemes = emptyList(),
                    diagnostics = listOf(SigningDiagnosticCode.SIGNATURE_VERIFICATION_UNAVAILABLE),
                ),
                failure = SigningUnavailable(
                    code = InspectionFailureCode.SIGNATURE_VERIFICATION_FAILED,
                ),
            )
        }
}

private fun X509Certificate.toSummary(): SigningCertificateSummary =
    SigningCertificateSummary(
        subject = subjectX500Principal.name,
        issuer = issuerX500Principal.name,
        serialNumber = serialNumber.toString(16).uppercase(Locale.ROOT),
        sha256 = MessageDigest.getInstance("SHA-256").digest(encoded).toHexFingerprint(),
        sha1 = MessageDigest.getInstance("SHA-1").digest(encoded).toHexFingerprint(),
    )

private fun readVerifiedSchemes(result: Any): List<String> =
    SIGNATURE_SCHEME_METHODS.mapNotNull { (methodName, schemeName) ->
        val verified = runCatching {
            result.javaClass.getMethod(methodName).invoke(result) as? Boolean
        }.getOrNull()
        schemeName.takeIf { verified == true }
    }

private fun ByteArray.toHexFingerprint(): String =
    joinToString(separator = ":") { byte -> "%02X".format(byte.toInt() and 0xff) }

private val SIGNATURE_SCHEME_METHODS = listOf(
    "isVerifiedUsingV1Scheme" to "v1",
    "isVerifiedUsingV2Scheme" to "v2",
    "isVerifiedUsingV3Scheme" to "v3",
    "isVerifiedUsingV31Scheme" to "v3.1",
    "isVerifiedUsingV4Scheme" to "v4",
)
