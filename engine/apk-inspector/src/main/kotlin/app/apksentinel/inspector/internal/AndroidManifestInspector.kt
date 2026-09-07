package app.apksentinel.inspector.internal

import android.content.pm.ApplicationInfo
import android.content.pm.ActivityInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.content.pm.ServiceInfo
import android.content.pm.FeatureInfo
import android.os.Build
import app.apksentinel.inspector.AndroidManifestUnavailable
import app.apksentinel.inspector.AndroidSdkSummary
import app.apksentinel.inspector.ComponentType
import app.apksentinel.inspector.InspectionLimits
import app.apksentinel.inspector.InspectionFailureCode
import app.apksentinel.inspector.ManifestComponent
import app.apksentinel.inspector.ManifestSummary
import java.io.File

internal data class ManifestInspectionOutcome(
    val manifest: ManifestSummary?,
    val decodedManifest: app.apksentinel.inspector.DecodedManifestText?,
    val failure: AndroidManifestUnavailable?,
)

/**
 * Uses Android's package parser so binary AndroidManifest.xml is supported
 * without an XML decoder. This is local device parsing only.
 */
internal class AndroidManifestInspector(
    private val packageManager: PackageManager,
) {
    @Suppress("DEPRECATION")
    fun inspect(
        apkFile: File,
        limits: InspectionLimits,
    ): ManifestInspectionOutcome {
        val flags = PackageManager.GET_PERMISSIONS or
            PackageManager.GET_ACTIVITIES or
            PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or
            PackageManager.GET_PROVIDERS or
            PackageManager.GET_CONFIGURATIONS

        val packageInfo = try {
            packageManager.getPackageArchiveInfo(apkFile.absolutePath, flags)
        } catch (error: RuntimeException) {
            return ManifestInspectionOutcome(
                manifest = null,
                decodedManifest = null,
                failure = AndroidManifestUnavailable(
                    code = InspectionFailureCode.MANIFEST_PARSE_FAILED,
                ),
            )
        }

        if (packageInfo == null) {
            return ManifestInspectionOutcome(
                manifest = null,
                decodedManifest = null,
                failure = AndroidManifestUnavailable(
                    code = InspectionFailureCode.MANIFEST_NOT_PARSEABLE,
                ),
            )
        }

        val decoded = DecodedManifestRenderer.decodeWithIntentFilters(
            apkFile = apkFile,
            maximumBytes = limits.maxDecodedManifestBytes,
            limits = limits,
        )
        val decodedArtifacts = decoded.getOrNull()
        return ManifestInspectionOutcome(
            manifest = packageInfo.toSummary(limits, decodedArtifacts?.intentFilters),
            decodedManifest = decodedArtifacts?.decodedManifest,
            failure = decoded.exceptionOrNull()?.let {
                AndroidManifestUnavailable(InspectionFailureCode.MANIFEST_TEXT_DECODE_FAILED)
            },
        )
    }
}

@Suppress("DEPRECATION")
private fun PackageInfo.toSummary(
    limits: InspectionLimits,
    intentFilterEvidence: IntentFilterEvidenceCollection?,
): ManifestSummary {
    val applicationInfo = applicationInfo
    val allPermissions = requestedPermissions
        ?.filterNotNull()
        ?.distinct()
        .orEmpty()
    val allComponents = buildList {
        activities.orEmpty().forEach { add(it.toManifestComponent(ComponentType.ACTIVITY, intentFilterEvidence)) }
        services.orEmpty().forEach { add(it.toManifestComponent(ComponentType.SERVICE, intentFilterEvidence)) }
        receivers.orEmpty().forEach { add(it.toManifestComponent(ComponentType.RECEIVER, intentFilterEvidence)) }
        providers.orEmpty().forEach { add(it.toManifestComponent(ComponentType.PROVIDER, intentFilterEvidence)) }
    }
    val allFeatures = reqFeatures.orEmpty().map { feature ->
        app.apksentinel.inspector.HardwareFeatureSummary(
            name = feature.name,
            openGlEsVersion = feature.reqGlEsVersion.takeIf { it != 0 },
            required = (feature.flags and FeatureInfo.FLAG_REQUIRED) != 0,
        )
    }

    return ManifestSummary(
        packageName = packageName.orEmpty(),
        versionName = versionName,
        versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            longVersionCode
        } else {
            versionCode.toLong()
        },
        sdk = AndroidSdkSummary(
            minSdk = applicationInfo?.minSdkVersion,
            targetSdk = applicationInfo?.targetSdkVersion,
        ),
        permissions = allPermissions.take(limits.maxManifestPermissions),
        permissionsTruncated = allPermissions.size > limits.maxManifestPermissions,
        components = allComponents.take(limits.maxManifestComponents),
        componentsTruncated = allComponents.size > limits.maxManifestComponents,
        debugBuild = applicationInfo?.let { info ->
            (info.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        },
        hardwareFeatures = allFeatures.take(limits.maxManifestFeatures),
        hardwareFeaturesTruncated = allFeatures.size > limits.maxManifestFeatures,
        intentFiltersTruncated = intentFilterEvidence?.isTruncated == true,
    )
}

private fun ComponentInfo.toManifestComponent(
    type: ComponentType,
    intentFilterEvidence: IntentFilterEvidenceCollection?,
): ManifestComponent {
    val evidence = intentFilterEvidence?.components?.get(IntentFilterComponentKey(type, name.orEmpty()))
    return ManifestComponent(
        type = type,
        className = name.orEmpty(),
        exported = exported,
        enabled = enabled,
        requiredPermission = when (this) {
            is ActivityInfo -> permission
            is ServiceInfo -> permission
            is ProviderInfo -> readPermission ?: writePermission
            else -> null
        },
        intentFilters = evidence?.filters.orEmpty(),
        intentFiltersTruncated = evidence?.isTruncated == true,
    )
}
