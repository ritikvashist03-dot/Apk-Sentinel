[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$AndroidSdk = $env:ANDROID_SDK_ROOT,
    [string]$BundletoolJar = ""
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
if ([string]::IsNullOrWhiteSpace($BundletoolJar)) {
    throw "Provide -BundletoolJar with a reviewed official bundletool release. AAB validation is a release gate."
}
$resolvedBundletool = (Resolve-Path -LiteralPath $BundletoolJar).Path
$javaExecutable = if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME) -and (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    Join-Path $env:JAVA_HOME "bin\java.exe"
} else {
    (Get-Command java.exe -ErrorAction Stop).Source
}
$jarsignerExecutable = Join-Path (Split-Path -Parent $javaExecutable) "jarsigner.exe"
if (-not (Test-Path -LiteralPath $jarsignerExecutable -PathType Leaf)) {
    throw "jarsigner.exe was not found beside the selected Java runtime."
}

if ([string]::IsNullOrWhiteSpace($AndroidSdk)) {
    $localProperties = Join-Path $resolvedRoot "local.properties"
    if (Test-Path -LiteralPath $localProperties) {
        $sdkLine = Get-Content -LiteralPath $localProperties | Where-Object { $_ -like "sdk.dir=*" } | Select-Object -First 1
        if ($sdkLine) {
            $AndroidSdk = $sdkLine.Substring("sdk.dir=".Length).Replace("\:", ":").Replace("\\", "\")
        }
    }
}
if ([string]::IsNullOrWhiteSpace($AndroidSdk) -or -not (Test-Path -LiteralPath $AndroidSdk -PathType Container)) {
    throw "Set ANDROID_SDK_ROOT or provide -AndroidSdk."
}

$requiredEnvironment = @(
    "APK_SENTINEL_KEYSTORE_PATH",
    "APK_SENTINEL_STORE_PASSWORD",
    "APK_SENTINEL_KEY_ALIAS",
    "APK_SENTINEL_KEY_PASSWORD",
    "APK_SENTINEL_THREAT_FEED_KEY_ID",
    "APK_SENTINEL_THREAT_FEED_PUBLIC_KEY_BASE64",
    "APK_SENTINEL_LEGAL_PUBLISHER_NAME",
    "APK_SENTINEL_SUPPORT_EMAIL",
    "APK_SENTINEL_PRIVACY_POLICY_URL",
    "APK_SENTINEL_PRIVACY_POLICY_EFFECTIVE_DATE",
    "APK_SENTINEL_TERMS_EFFECTIVE_DATE"
)
$missing = $requiredEnvironment | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) }
if ($missing.Count -gt 0) {
    throw "Missing release environment variable(s): $($missing -join ', ')"
}

Push-Location $resolvedRoot
try {
    & (Join-Path $resolvedRoot "tools\verify-static.ps1") -ProjectRoot $resolvedRoot
    $privacyPolicyResponse = Invoke-WebRequest `
        -Uri $env:APK_SENTINEL_PRIVACY_POLICY_URL `
        -Method Get `
        -MaximumRedirection 5 `
        -TimeoutSec 20 `
        -UseBasicParsing
    if ($privacyPolicyResponse.StatusCode -lt 200 -or $privacyPolicyResponse.StatusCode -ge 300) {
        throw "The public privacy-policy URL did not return a successful response."
    }
    $resolvedPrivacyPolicyUri = if ($privacyPolicyResponse.BaseResponse.ResponseUri) {
        $privacyPolicyResponse.BaseResponse.ResponseUri
    } elseif ($privacyPolicyResponse.BaseResponse.RequestMessage.RequestUri) {
        $privacyPolicyResponse.BaseResponse.RequestMessage.RequestUri
    } else {
        throw "The final public privacy-policy URL could not be determined."
    }
    $resolvedPrivacyPolicyUrl = $resolvedPrivacyPolicyUri.AbsoluteUri
    if (-not $resolvedPrivacyPolicyUrl.StartsWith("https://", [StringComparison]::OrdinalIgnoreCase)) {
        throw "The public privacy-policy URL redirected away from HTTPS."
    }
    if ($privacyPolicyResponse.Content -notmatch 'APK Sentinel Privacy Policy' -or
        $privacyPolicyResponse.Content -notmatch [regex]::Escape($env:APK_SENTINEL_SUPPORT_EMAIL)) {
        throw "The public privacy-policy page does not contain the expected product title and support address."
    }

    & $gradleWrapper --no-daemon --no-configuration-cache clean test lint bundleRelease assembleRelease
    if ($LASTEXITCODE -ne 0) { throw "Gradle release verification failed with exit code $LASTEXITCODE" }
    $dependencyReportOutput = & $gradleWrapper :app:dependencies --configuration releaseRuntimeClasspath --console=plain 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Release dependency report failed with exit code $LASTEXITCODE" }

    $aab = Get-ChildItem -LiteralPath (Join-Path $resolvedRoot "app\build\outputs\bundle\release") -Filter *.aab | Select-Object -First 1
    $apk = Get-ChildItem -LiteralPath (Join-Path $resolvedRoot "app\build\outputs\apk\release") -Filter *.apk | Select-Object -First 1
    if (-not $aab -or -not $apk) { throw "Expected release AAB/APK artifacts were not found." }

    $apksigner = Get-ChildItem -LiteralPath (Join-Path $AndroidSdk "build-tools") -Recurse -Filter apksigner.bat |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if (-not $apksigner) { throw "apksigner.bat was not found under the Android SDK build-tools directory." }
    $buildToolsDirectory = $apksigner.Directory.FullName
    $aapt2 = Join-Path $buildToolsDirectory "aapt2.exe"
    if (-not (Test-Path -LiteralPath $aapt2 -PathType Leaf)) {
        throw "aapt2.exe was not found beside the selected apksigner."
    }
    $zipalign = Join-Path $buildToolsDirectory "zipalign.exe"
    if (-not (Test-Path -LiteralPath $zipalign -PathType Leaf)) {
        throw "zipalign.exe was not found beside the selected apksigner."
    }

    $apksignerOutput = & $apksigner.FullName verify --verbose --print-certs $apk.FullName 2>&1
    if ($LASTEXITCODE -ne 0) { throw "apksigner verification failed.`n$($apksignerOutput -join [Environment]::NewLine)" }

    $zipalignOutput = & $zipalign -c -P 16 -v 4 $apk.FullName 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Release APK alignment verification failed.`n$($zipalignOutput -join [Environment]::NewLine)" }

    & $javaExecutable -jar $resolvedBundletool validate --bundle $aab.FullName
    if ($LASTEXITCODE -ne 0) { throw "bundletool validation failed." }
    $aabSignatureOutput = & $jarsignerExecutable -verify -verbose -certs $aab.FullName 2>&1
    if ($LASTEXITCODE -ne 0 -or ($aabSignatureOutput -join [Environment]::NewLine) -notmatch '(?i)jar verified') {
        throw "Release AAB JAR-signature verification failed.`n$($aabSignatureOutput -join [Environment]::NewLine)"
    }

    $badgingOutput = & $aapt2 dump badging $apk.FullName 2>&1
    if ($LASTEXITCODE -ne 0) { throw "aapt2 could not inspect the release APK.`n$($badgingOutput -join [Environment]::NewLine)" }
    $packageLine = $badgingOutput | Where-Object { $_ -match '^package:' } | Select-Object -First 1
    $packageMatch = [regex]::Match([string]$packageLine, "name='([^']+)'\s+versionCode='([0-9]+)'\s+versionName='([^']*)'")
    if (-not $packageMatch.Success) { throw "Release APK package/version metadata could not be parsed." }
    $applicationId = $packageMatch.Groups[1].Value
    $versionCode = [long]$packageMatch.Groups[2].Value
    $versionName = $packageMatch.Groups[3].Value
    $minimumSdkLine = $badgingOutput | Where-Object { $_ -match "^sdkVersion:'[0-9]+'$" } | Select-Object -First 1
    $targetSdkLine = $badgingOutput | Where-Object { $_ -match "^targetSdkVersion:'[0-9]+'$" } | Select-Object -First 1
    $minimumSdk = [int]([regex]::Match([string]$minimumSdkLine, "[0-9]+").Value)
    $targetSdk = [int]([regex]::Match([string]$targetSdkLine, "[0-9]+").Value)
    if ($applicationId -ne "app.apksentinel.mobile") { throw "Unexpected release application ID: $applicationId" }
    if ($minimumSdk -ne 26) { throw "Unexpected release minimum SDK: $minimumSdk" }
    if ($targetSdk -lt 36) { throw "Release APK target SDK is below the required API 36 baseline: $targetSdk" }
    if ($badgingOutput -match '(?m)^application-debuggable') { throw "Release APK is marked debuggable." }

    $revision = "unversioned-workspace"
    if (Test-Path -LiteralPath (Join-Path $resolvedRoot ".git")) {
        $candidate = (& git -C $resolvedRoot rev-parse HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $candidate) { $revision = $candidate.Trim() }
    }
    $certificateLine = $apksignerOutput | Where-Object { $_ -match "Signer #1 certificate SHA-256 digest:" } | Select-Object -First 1
    $certificateSha256 = if ($certificateLine) { ($certificateLine -split ":", 2)[1].Trim() } else { "not-parsed" }
    if ($certificateSha256 -eq "not-parsed") { throw "Release signer certificate SHA-256 could not be parsed." }
    $mappingPath = Join-Path $resolvedRoot "app\build\outputs\mapping\release\mapping.txt"
    if (-not (Test-Path -LiteralPath $mappingPath -PathType Leaf)) {
        throw "R8 mapping.txt was not produced for the minified release build."
    }

    $evidenceDirectory = Join-Path $resolvedRoot "build\release-evidence"
    New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    $privacyPolicyPath = & (Join-Path $resolvedRoot "tools\render-privacy-policy.ps1") `
        -ProjectRoot $resolvedRoot `
        -OutputPath (Join-Path $evidenceDirectory "privacy-policy.html")
    if (-not (Test-Path -LiteralPath $privacyPolicyPath -PathType Leaf)) {
        throw "Rendered privacy-policy artifact was not created."
    }
    $dependencyReportPath = Join-Path $evidenceDirectory "dependencies-releaseRuntimeClasspath.txt"
    [IO.File]::WriteAllLines(
        $dependencyReportPath,
        [string[]]$dependencyReportOutput,
        [Text.UTF8Encoding]::new($false)
    )

    $sourceExtensions = @('.kt', '.kts', '.java', '.xml', '.toml', '.properties', '.pro', '.md', '.html', '.ps1', '.bat', '.sh')
    $sourceFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File | Where-Object {
        $relative = $_.FullName.Substring($resolvedRoot.Length).TrimStart('\')
        $excluded = $relative -match '^(build|\.gradle[^\\]*|\.kotlin|\.tooling|wrapper-bootstrap)(\\|$)' -or
            $relative -match '(^|\\)build(\\|$)' -or
            $relative -eq 'local.properties'
        (-not $excluded) -and (
            $_.Extension -in $sourceExtensions -or
            $relative -eq 'gradlew' -or
            $relative -eq 'gradle\wrapper\gradle-wrapper.jar' -or
            $relative -match '^docs\\release\\assets\\.*\.png$'
        )
    } | Sort-Object FullName)
    $sourceEntries = @($sourceFiles | ForEach-Object {
        [ordered]@{
            path = $_.FullName.Substring($resolvedRoot.Length).TrimStart('\').Replace('\', '/')
            bytes = $_.Length
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
        }
    })
    $sourceManifestPath = Join-Path $evidenceDirectory "source-manifest.json"
    [IO.File]::WriteAllText(
        $sourceManifestPath,
        ([ordered]@{ schemaVersion = 1; files = $sourceEntries } | ConvertTo-Json -Depth 5),
        [Text.UTF8Encoding]::new($false)
    )
    $javaVersion = (& $javaExecutable -version 2>&1) -join [Environment]::NewLine
    $wrapperProperties = Get-Content -LiteralPath (Join-Path $resolvedRoot 'gradle\wrapper\gradle-wrapper.properties') -Raw
    $gradleDistribution = [regex]::Match($wrapperProperties, '(?m)^distributionUrl=(.+)$').Groups[1].Value.Trim()
    $versionCatalog = Get-Content -LiteralPath (Join-Path $resolvedRoot 'gradle\libs.versions.toml') -Raw
    $agpVersion = [regex]::Match($versionCatalog, '(?m)^agp\s*=\s*"([^"]+)"').Groups[1].Value
    $verifiedArtifacts = @(
        [ordered]@{ kind = "AAB"; path = $aab.FullName; bytes = $aab.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $aab.FullName).Hash.ToLowerInvariant() },
        [ordered]@{ kind = "APK"; path = $apk.FullName; bytes = $apk.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $apk.FullName).Hash.ToLowerInvariant() },
        [ordered]@{ kind = "R8_MAPPING"; path = $mappingPath; bytes = (Get-Item -LiteralPath $mappingPath).Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $mappingPath).Hash.ToLowerInvariant() }
    )
    $manifest = [ordered]@{
        schemaVersion = 2
        generatedAtUtc = [DateTime]::UtcNow.ToString("o")
        applicationId = $applicationId
        versionName = $versionName
        versionCode = $versionCode
        minimumSdk = $minimumSdk
        targetSdk = $targetSdk
        sourceRevision = $revision
        sourceManifest = [ordered]@{
            path = $sourceManifestPath
            files = $sourceEntries.Count
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceManifestPath).Hash.ToLowerInvariant()
        }
        dependencyReport = [ordered]@{
            path = $dependencyReportPath
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $dependencyReportPath).Hash.ToLowerInvariant()
        }
        toolchain = [ordered]@{
            java = $javaVersion
            gradleDistribution = $gradleDistribution
            androidGradlePlugin = $agpVersion
            androidBuildTools = $apksigner.Directory.Name
            bundletoolSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $resolvedBundletool).Hash.ToLowerInvariant()
        }
        privacyPolicyUrl = $env:APK_SENTINEL_PRIVACY_POLICY_URL
        resolvedPrivacyPolicyUrl = $resolvedPrivacyPolicyUrl
        privacyPolicyHttpStatus = $privacyPolicyResponse.StatusCode
        privacyPolicyEffectiveDate = $env:APK_SENTINEL_PRIVACY_POLICY_EFFECTIVE_DATE
        privacyPolicyArtifact = [ordered]@{
            path = $privacyPolicyPath
            bytes = (Get-Item -LiteralPath $privacyPolicyPath).Length
            sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $privacyPolicyPath).Hash.ToLowerInvariant()
        }
        legalPublisherName = $env:APK_SENTINEL_LEGAL_PUBLISHER_NAME
        certificateSha256 = $certificateSha256
        artifacts = $verifiedArtifacts
        apksignerVerification = ($apksignerOutput -join [Environment]::NewLine)
        apkAlignmentVerification = ($zipalignOutput -join [Environment]::NewLine)
        bundletoolValidated = $true
        aabSignatureVerification = ($aabSignatureOutput -join [Environment]::NewLine)
    }
    $manifestPath = Join-Path $evidenceDirectory "artifact-manifest.json"
    [IO.File]::WriteAllText(
        $manifestPath,
        ($manifest | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false)
    )
    Write-Host "Release artifacts verified. Evidence: $manifestPath"
} finally {
    Pop-Location
}
