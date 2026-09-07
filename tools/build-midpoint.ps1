[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$AndroidSdk = $env:ANDROID_SDK_ROOT
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
$resolvedRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$gradleWrapper = Join-Path $resolvedRoot "gradlew.bat"
if (-not (Test-Path -LiteralPath $gradleWrapper -PathType Leaf)) {
    throw "Gradle wrapper not found under $resolvedRoot"
}

if ([string]::IsNullOrWhiteSpace($JavaHome) -or
    -not (Test-Path -LiteralPath (Join-Path $JavaHome "bin\java.exe") -PathType Leaf)) {
    throw "Provide -JavaHome with a JDK/JBR that contains bin\java.exe."
}

if ([string]::IsNullOrWhiteSpace($AndroidSdk)) {
    $localProperties = Join-Path $resolvedRoot "local.properties"
    if (Test-Path -LiteralPath $localProperties -PathType Leaf) {
        $sdkLine = Get-Content -LiteralPath $localProperties |
            Where-Object { $_ -like "sdk.dir=*" } |
            Select-Object -First 1
        if ($sdkLine) {
            $AndroidSdk = $sdkLine.Substring("sdk.dir=".Length).Replace("\:", ":").Replace("\\", "\")
        }
    }
}
if ([string]::IsNullOrWhiteSpace($AndroidSdk) -or
    -not (Test-Path -LiteralPath $AndroidSdk -PathType Container)) {
    throw "Set ANDROID_SDK_ROOT or provide -AndroidSdk."
}

$previousJavaHome = $env:JAVA_HOME
$previousAndroidSdkRoot = $env:ANDROID_SDK_ROOT
$previousAndroidHome = $env:ANDROID_HOME
$env:JAVA_HOME = (Resolve-Path -LiteralPath $JavaHome).Path
$env:ANDROID_SDK_ROOT = (Resolve-Path -LiteralPath $AndroidSdk).Path
$env:ANDROID_HOME = $env:ANDROID_SDK_ROOT

Push-Location $resolvedRoot
try {
    # This is deliberately a compile-only midpoint snapshot. Full static, unit,
    # lint, device, policy, signing, and bundle verification remain later gates.
    & $gradleWrapper --no-daemon --no-configuration-cache :app:assembleDebug
    if ($LASTEXITCODE -ne 0) {
        throw "Midpoint debug APK compilation failed with exit code $LASTEXITCODE."
    }

    $sourceApk = Join-Path $resolvedRoot "app\build\outputs\apk\debug\app-debug.apk"
    if (-not (Test-Path -LiteralPath $sourceApk -PathType Leaf)) {
        throw "Gradle completed without producing $sourceApk"
    }

    $artifactDirectory = Join-Path $resolvedRoot "build\midpoint-artifacts"
    New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss'Z'")
    $artifactPath = Join-Path $artifactDirectory "apk-sentinel-midpoint-unverified-$stamp.apk"
    Copy-Item -LiteralPath $sourceApk -Destination $artifactPath

    $artifact = Get-Item -LiteralPath $artifactPath
    $manifest = [ordered]@{
        product = "APK Sentinel"
        artifactKind = "debug-apk"
        verificationState = "pre-verification"
        createdAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        gradleTask = ":app:assembleDebug"
        path = $artifact.FullName
        bytes = $artifact.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.FullName).Hash.ToLowerInvariant()
        warnings = @(
            "Debug-signed installable snapshot only.",
            "Not release-signed and not suitable for Google Play.",
            "Full tests, lint, device checks, policy checks, APK signing verification, and AAB verification have not run."
        )
    }
    $manifestPath = "$artifactPath.json"
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    Write-Output "Midpoint APK: $artifactPath"
    Write-Output "Evidence: $manifestPath"
    Write-Output "SHA-256: $($manifest.sha256)"
} finally {
    Pop-Location
    $env:JAVA_HOME = $previousJavaHome
    $env:ANDROID_SDK_ROOT = $previousAndroidSdkRoot
    $env:ANDROID_HOME = $previousAndroidHome
}
