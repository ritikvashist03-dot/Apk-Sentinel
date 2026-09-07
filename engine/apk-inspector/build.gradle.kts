import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    // These aliases are deliberately documented in HANDOFF.md. The root catalog
    // owns their versions so this module stays aligned with the application.
    alias(libs.plugins.android.library)
}

android {
    namespace = "app.apksentinel.inspector"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
    }
}

dependencies {
    implementation(libs.android.apksig)
    testImplementation(libs.junit4)
}
