import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URI
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.LocalDate
import java.util.Base64

val releaseKeystorePath = providers.environmentVariable("APK_SENTINEL_KEYSTORE_PATH").orNull
val releaseStorePassword = providers.environmentVariable("APK_SENTINEL_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("APK_SENTINEL_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("APK_SENTINEL_KEY_PASSWORD").orNull
val releaseSigningConfigured = listOf(
    releaseKeystorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }
val threatFeedKeyId = providers.environmentVariable("APK_SENTINEL_THREAT_FEED_KEY_ID").orNull.orEmpty()
val threatFeedPublicKey = providers.environmentVariable("APK_SENTINEL_THREAT_FEED_PUBLIC_KEY_BASE64").orNull.orEmpty()
// Optional, user-triggered update endpoints. Blank is an intentional debug/default state.
val threatFeedUpdateEndpoint = providers.environmentVariable("APK_SENTINEL_THREAT_FEED_UPDATE_ENDPOINT").orNull.orEmpty()
val offlineAttributionUpdateEndpoint = providers.environmentVariable("APK_SENTINEL_OFFLINE_ATTRIBUTION_UPDATE_ENDPOINT").orNull.orEmpty()
val legalPublisherName = providers.environmentVariable("APK_SENTINEL_LEGAL_PUBLISHER_NAME").orNull.orEmpty()
val supportEmail = providers.environmentVariable("APK_SENTINEL_SUPPORT_EMAIL").orNull.orEmpty()
val privacyPolicyUrl = providers.environmentVariable("APK_SENTINEL_PRIVACY_POLICY_URL").orNull.orEmpty()
val termsEffectiveDate = providers.environmentVariable("APK_SENTINEL_TERMS_EFFECTIVE_DATE").orNull.orEmpty()
val threatFeedKeyConfigured = threatFeedKeyId.matches(Regex("[A-Za-z0-9._-]{1,64}")) && threatFeedPublicKey.isNotBlank()
val threatFeedKeyValid = threatFeedKeyConfigured && runCatching {
    val encoded = Base64.getDecoder().decode(threatFeedPublicKey)
    val key = KeyFactory.getInstance("EC")
        .generatePublic(X509EncodedKeySpec(encoded)) as ECPublicKey
    val expected = AlgorithmParameters.getInstance("EC").run {
        init(ECGenParameterSpec("secp256r1"))
        getParameterSpec(ECParameterSpec::class.java)
    }
    key.params.curve == expected.curve &&
        key.params.generator == expected.generator &&
        key.params.order == expected.order &&
        key.params.cofactor == expected.cofactor
}.getOrDefault(false)
val releaseIdentityValid = legalPublisherName.length in 2..120 &&
    supportEmail.matches(Regex("^[^\\s@]{1,64}@[^\\s@]{1,190}\\.[A-Za-z]{2,63}$")) &&
    runCatching {
        val uri = URI(privacyPolicyUrl)
        uri.scheme.equals("https", ignoreCase = true) && uri.host != null && uri.userInfo == null && uri.fragment == null
    }.getOrDefault(false) &&
    runCatching { LocalDate.parse(termsEffectiveDate) }.isSuccess
fun buildConfigString(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "app.apksentinel.mobile"
    compileSdk = 37

    defaultConfig {
        applicationId = "app.apksentinel.mobile"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables.useSupportLibrary = true
        buildConfigField("String", "THREAT_FEED_KEY_ID", buildConfigString(threatFeedKeyId))
        buildConfigField("String", "THREAT_FEED_PUBLIC_KEY_BASE64", buildConfigString(threatFeedPublicKey))
        buildConfigField("String", "THREAT_FEED_UPDATE_ENDPOINT", buildConfigString(threatFeedUpdateEndpoint))
        buildConfigField("String", "OFFLINE_ATTRIBUTION_UPDATE_ENDPOINT", buildConfigString(offlineAttributionUpdateEndpoint))
        buildConfigField("String", "LEGAL_PUBLISHER_NAME", buildConfigString(legalPublisherName))
        buildConfigField("String", "SUPPORT_EMAIL", buildConfigString(supportEmail))
        buildConfigField("String", "PRIVACY_POLICY_URL", buildConfigString(privacyPolicyUrl))
        buildConfigField("String", "TERMS_EFFECTIVE_DATE", buildConfigString(termsEffectiveDate))
    }

    signingConfigs {
        if (releaseSigningConfigured) {
            create("release") {
                storeFile = file(requireNotNull(releaseKeystorePath))
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
                enableV1Signing = true
                enableV2Signing = true
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            if (releaseSigningConfigured) signingConfig = signingConfigs.getByName("release")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += setOf(
            "/META-INF/{AL2.0,LGPL2.1}",
            "META-INF/DEPENDENCIES",
            "META-INF/LICENSE.md",
        )
    }
}

tasks.register("verifyReleaseSigningInputs") {
    group = "verification"
    description = "Fails release artifacts unless all external signing inputs are configured."
    doLast {
        check(releaseSigningConfigured) {
            "Release signing requires APK_SENTINEL_KEYSTORE_PATH, APK_SENTINEL_STORE_PASSWORD, APK_SENTINEL_KEY_ALIAS, and APK_SENTINEL_KEY_PASSWORD."
        }
        check(file(requireNotNull(releaseKeystorePath)).isFile) {
            "APK_SENTINEL_KEYSTORE_PATH does not point to a readable keystore file."
        }
        check(threatFeedKeyValid) {
            "Release builds require a valid key ID and P-256 X.509 public key in APK_SENTINEL_THREAT_FEED_KEY_ID and APK_SENTINEL_THREAT_FEED_PUBLIC_KEY_BASE64."
        }
        check(releaseIdentityValid) {
            "Release builds require APK_SENTINEL_LEGAL_PUBLISHER_NAME, APK_SENTINEL_SUPPORT_EMAIL, a public HTTPS APK_SENTINEL_PRIVACY_POLICY_URL, and an ISO APK_SENTINEL_TERMS_EFFECTIVE_DATE."
        }
    }
}

tasks.matching { it.name == "bundleRelease" || it.name == "assembleRelease" }.configureEach {
    dependsOn("verifyReleaseSigningInputs")
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        freeCompilerArgs.add("-Xannotation-default-target=param-property")
    }
}

dependencies {
    implementation(project(":core:designsystem"))
    implementation(project(":core:model"))
    implementation(project(":core:security"))
    implementation(project(":core:reporting"))
    implementation(project(":feature:device-posture"))
    implementation(project(":feature:app-inspector"))
    implementation(project(":engine:url-inspector"))
    implementation(project(":engine:apk-inspector"))
    implementation(project(":engine:network-monitor"))
    implementation(project(":engine:threat-intel"))
    implementation(project(":engine:tls-inspection"))
    implementation(project(":engine:root-capture"))
    implementation(project(":engine:remote-stream"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)

    implementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)

    testImplementation(libs.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
