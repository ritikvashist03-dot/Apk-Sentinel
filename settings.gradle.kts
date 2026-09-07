pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "APK Sentinel"
include(":app")
include(":core:designsystem")
include(":core:model")
include(":core:security")
include(":core:reporting")
include(":feature:device-posture")
include(":feature:app-inspector")
include(":engine:url-inspector")
include(":engine:apk-inspector")
include(":engine:network-monitor")
include(":engine:threat-intel")
include(":engine:tls-inspection")
include(":engine:root-capture")
include(":engine:remote-stream")
include(":tools:remote-receiver")
