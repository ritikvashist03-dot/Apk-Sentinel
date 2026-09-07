import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins { alias(libs.plugins.android.library) }

android {
    namespace = "app.apksentinel.engine.tlsinspection"
    compileSdk = 37

    defaultConfig { minSdk = 26 }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { compilerOptions { jvmTarget = JvmTarget.JVM_17 } }

dependencies {
    implementation(project(":core:security"))
    implementation(libs.bcprov.jdk18on)
    implementation(libs.bcpkix.jdk18on)
    // Low-level TLS handshake API. JSSE exposes no key material, so a key log is
    // impossible without a stack that does.
    implementation(libs.bctls.jdk18on)
    testImplementation(libs.junit4)
}
