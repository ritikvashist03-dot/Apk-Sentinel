import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins { alias(libs.plugins.android.library) }

android {
    namespace = "app.apksentinel.engine.threatintel"
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
    testImplementation(libs.junit4)
}
