[CmdletBinding()]
param(
    [string]$ProjectRoot = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
$resolvedRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$templatePath = Join-Path $resolvedRoot "docs\release\privacy-policy.html"
if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
    throw "Privacy-policy template not found under $resolvedRoot"
}

$publisher = [Environment]::GetEnvironmentVariable("APK_SENTINEL_LEGAL_PUBLISHER_NAME")
$supportEmail = [Environment]::GetEnvironmentVariable("APK_SENTINEL_SUPPORT_EMAIL")
$effectiveDate = [Environment]::GetEnvironmentVariable("APK_SENTINEL_PRIVACY_POLICY_EFFECTIVE_DATE")
if ([string]::IsNullOrWhiteSpace($publisher) -or $publisher.Length -lt 2 -or $publisher.Length -gt 120) {
    throw "APK_SENTINEL_LEGAL_PUBLISHER_NAME must contain 2 to 120 characters."
}
if ($supportEmail -notmatch '^[^\s@]{1,64}@[^\s@]{1,190}\.[A-Za-z]{2,63}$') {
    throw "APK_SENTINEL_SUPPORT_EMAIL must be a valid monitored email address."
}
$parsedDate = [DateTime]::MinValue
if (-not [DateTime]::TryParseExact($effectiveDate, "yyyy-MM-dd", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsedDate)) {
    throw "APK_SENTINEL_PRIVACY_POLICY_EFFECTIVE_DATE must use yyyy-MM-dd."
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $resolvedRoot "build\release-evidence\privacy-policy.html"
} elseif (-not [IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $resolvedRoot $OutputPath
}
$outputDirectory = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

$encodedPublisher = [Net.WebUtility]::HtmlEncode($publisher)
$encodedEmail = [Net.WebUtility]::HtmlEncode($supportEmail)
$rendered = [IO.File]::ReadAllText($templatePath, [Text.Encoding]::UTF8)
$rendered = $rendered.Replace("{{LEGAL_PUBLISHER_NAME}}", $encodedPublisher)
$rendered = $rendered.Replace("{{SUPPORT_EMAIL}}", $encodedEmail)
$rendered = $rendered.Replace("{{PRIVACY_POLICY_EFFECTIVE_DATE}}", $effectiveDate)
if ($rendered -match '\{\{[^}]+\}\}' -or $rendered -match '\[\[[^]]+\]\]') {
    throw "Rendered privacy policy still contains an unresolved placeholder."
}
[IO.File]::WriteAllText($OutputPath, $rendered, [Text.UTF8Encoding]::new($false))
Write-Output (Resolve-Path -LiteralPath $OutputPath).Path
