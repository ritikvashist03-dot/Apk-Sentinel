[CmdletBinding()]
param(
    [string]$ProjectRoot = ""
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $PSScriptRoot
}
$resolvedRoot = (Resolve-Path -LiteralPath $ProjectRoot).Path
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
$failures = [Collections.Generic.List[string]]::new()

function Add-Failure([string]$Message) {
    [void]$failures.Add($Message)
}

function Read-StrictUtf8([string]$Path) {
    try {
        return [IO.File]::ReadAllText($Path, $strictUtf8)
    } catch {
        Add-Failure "Invalid UTF-8: $Path ($($_.Exception.Message))"
        return ""
    }
}

function Get-StringResourceMap([string]$Path) {
    $map = @{}
    $text = Read-StrictUtf8 $Path
    if ([string]::IsNullOrEmpty($text)) { return $map }
    try {
        [xml]$document = $text
        $nodes = @($document.resources.string)
        $duplicates = @($nodes | Group-Object { [string]$_.name } | Where-Object Count -gt 1)
        foreach ($duplicate in $duplicates) {
            Add-Failure "Duplicate string '$($duplicate.Name)' in $Path"
        }
        foreach ($node in $nodes) {
            $name = [string]$node.name
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $map[$name] = [string]$node.InnerText
            }
        }
    } catch {
        Add-Failure "Invalid strings XML: $Path ($($_.Exception.Message))"
    }
    return $map
}

function Get-AggregatedStringResourceMap([string]$ValuesDirectory) {
    $aggregate = @{}
    $owners = @{}
    if (-not (Test-Path -LiteralPath $ValuesDirectory -PathType Container)) {
        return $aggregate
    }
    $resourceFiles = @(Get-ChildItem -LiteralPath $ValuesDirectory -File -Filter *.xml | Sort-Object FullName)
    foreach ($resourceFile in $resourceFiles) {
        $fileMap = Get-StringResourceMap $resourceFile.FullName
        foreach ($name in $fileMap.Keys) {
            if ($aggregate.ContainsKey($name)) {
                Add-Failure "Duplicate string '$name' across $($owners[$name]) and $($resourceFile.FullName)"
                continue
            }
            $aggregate[$name] = $fileMap[$name]
            $owners[$name] = $resourceFile.FullName
        }
    }
    return $aggregate
}

function Get-FormatPlaceholders([string]$Value) {
    return @([regex]::Matches($Value, '%(?:\d+\$)?[-#+ 0,(<]*\d*(?:\.\d+)?[A-Za-z]') |
        ForEach-Object Value |
        Sort-Object)
}

$sourceFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File |
    Where-Object {
        $_.FullName -match '\\src\\' -and
        $_.FullName -notmatch '\\build\\' -and
        $_.Extension -in @('.xml', '.kt', '.java')
    })
foreach ($sourceFile in $sourceFiles) {
    $text = Read-StrictUtf8 $sourceFile.FullName
    if ($sourceFile.Extension -eq '.xml' -and -not [string]::IsNullOrEmpty($text)) {
        try { [xml]$text | Out-Null } catch { Add-Failure "Invalid XML: $($sourceFile.FullName) ($($_.Exception.Message))" }
    }
    if ($text -match '(?m)\b(TODO|FIXME|NotImplementedError)\b') {
        Add-Failure "Unresolved implementation marker in $($sourceFile.FullName)"
    }
    if ($text -match '\uFFFD|(?:\u00C2|\u00C3|\u00E0)[\u0080-\u00BF]') {
        Add-Failure "Source contains replacement/mojibake markers: $($sourceFile.FullName)"
    }
    if ($sourceFile.Extension -in @('.kt', '.java') -and
        $text -match '\.\s*(?:readNBytes|readAllBytes|skipNBytes|transferTo)\s*\(') {
        Add-Failure "Android API 33+ InputStream method is incompatible with minSdk 26 in $($sourceFile.FullName)"
    }
}

$defaultValuesDirectories = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Directory |
    Where-Object {
        $_.FullName -match '\\src\\main\\res\\values$' -and
        $_.FullName -notmatch '\\build\\'
    })
foreach ($defaultValuesDirectory in $defaultValuesDirectories) {
    $resourceRoot = Split-Path -Parent $defaultValuesDirectory.FullName
    $hindiPath = Join-Path $resourceRoot 'values-hi\strings.xml'
    $hindiDirectory = Join-Path $resourceRoot 'values-hi'
    $defaultMap = Get-AggregatedStringResourceMap $defaultValuesDirectory.FullName
    if ($defaultMap.Count -eq 0) { continue }
    if (-not (Test-Path -LiteralPath $hindiDirectory -PathType Container)) {
        Add-Failure "Missing Hindi values directory for $($defaultValuesDirectory.FullName)"
        continue
    }
    $hindiMap = Get-AggregatedStringResourceMap $hindiDirectory
    $hindiFiles = @(Get-ChildItem -LiteralPath $hindiDirectory -File -Filter *.xml)
    $hindiText = ($hindiFiles | ForEach-Object { Read-StrictUtf8 $_.FullName }) -join "`n"
    if ($hindiMap.Count -gt 0 -and $hindiText -notmatch '[\u0900-\u097F]') {
        Add-Failure "Hindi resource set contains no Devanagari text: $hindiDirectory"
    }
    if ($hindiText -match '\uFFFD|(?:\u00C2|\u00C3|\u00E0)[\u0080-\u00BF]') {
        Add-Failure "Hindi resource set contains replacement/mojibake markers: $hindiDirectory"
    }
    if ($hindiText -match '[\u202A-\u202E\u2066-\u2069]') {
        Add-Failure "Hindi resource set contains hidden bidirectional controls: $hindiDirectory"
    }
    foreach ($name in $defaultMap.Keys) {
        if (-not $hindiMap.ContainsKey($name)) {
            Add-Failure "Hindi resource missing '$name' for $($defaultValuesDirectory.FullName)"
            continue
        }
        $defaultFormats = @(Get-FormatPlaceholders $defaultMap[$name])
        $hindiFormats = @(Get-FormatPlaceholders $hindiMap[$name])
        if (($defaultFormats -join '|') -ne ($hindiFormats -join '|')) {
            Add-Failure "Format placeholder mismatch for '$name' in $hindiDirectory"
        }
    }
    foreach ($name in $hindiMap.Keys) {
        if (-not $defaultMap.ContainsKey($name)) {
            Add-Failure "Hindi-only resource '$name' in $hindiDirectory"
        }
    }
}

$moduleBuildFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Filter build.gradle.kts |
    Where-Object {
        $_.DirectoryName -ne $resolvedRoot -and
        $_.FullName -notmatch '\\(build|\.gradle|\.tooling|wrapper-bootstrap)\\'
    })
$settingsText = Read-StrictUtf8 (Join-Path $resolvedRoot 'settings.gradle.kts')
foreach ($buildFile in $moduleBuildFiles) {
    $relativeModule = $buildFile.DirectoryName.Substring($resolvedRoot.Length).TrimStart('\').Replace('\', ':')
    if ($settingsText -notmatch [regex]::Escape("include(`":$relativeModule`")")) {
        Add-Failure "Module is not included in settings.gradle.kts: :$relativeModule"
    }

    $defaultValuesPath = Join-Path $buildFile.DirectoryName 'src\main\res\values'
    if (Test-Path -LiteralPath $defaultValuesPath -PathType Container) {
        $resourceMap = Get-AggregatedStringResourceMap $defaultValuesPath
        $kotlinFiles = @(Get-ChildItem -LiteralPath (Join-Path $buildFile.DirectoryName 'src\main') -Recurse -File -Filter *.kt -ErrorAction SilentlyContinue)
        foreach ($kotlinFile in $kotlinFiles) {
            $kotlinText = Read-StrictUtf8 $kotlinFile.FullName
            foreach ($match in [regex]::Matches($kotlinText, '\bR\.string\.([A-Za-z0-9_]+)')) {
                $resourceName = $match.Groups[1].Value
                if (-not $resourceMap.ContainsKey($resourceName)) {
                    Add-Failure "Missing R.string.$resourceName referenced by $($kotlinFile.FullName)"
                }
            }
        }
    }
}

$gradleFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File |
    Where-Object { $_.Extension -in @('.kts', '.toml') -and $_.FullName -notmatch '\\(build|\.gradle)\\' })
foreach ($gradleFile in $gradleFiles) {
    $gradleText = Read-StrictUtf8 $gradleFile.FullName
    if ($gradleText -match 'org\.jetbrains\.kotlin\.android|kotlin\("android"\)') {
        Add-Failure "AGP 9 built-in Kotlin conflict in $($gradleFile.FullName)"
    }
}

$composeFiles = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -Filter *.kt |
    Where-Object {
        $_.FullName -match '\\src\\main\\' -and
        $_.FullName -notmatch '\\build\\' -and
        (Read-StrictUtf8 $_.FullName) -match 'androidx\.compose'
    })
foreach ($composeFile in $composeFiles) {
    $composeText = Read-StrictUtf8 $composeFile.FullName
    $literalPatterns = @(
        'Text\s*\(\s*"',
        '(?:title|description|label|contentDescription)\s*=\s*"'
    )
    foreach ($pattern in $literalPatterns) {
        if ($composeText -match $pattern) {
            Add-Failure "User-visible hard-coded Compose text in $($composeFile.FullName) matching $pattern"
        }
    }
}

$appMainDirectory = Join-Path $resolvedRoot 'app\src\main\java'
if (Test-Path -LiteralPath $appMainDirectory -PathType Container) {
    $appKotlinFiles = @(Get-ChildItem -LiteralPath $appMainDirectory -Recurse -File -Filter *.kt)
    foreach ($appKotlinFile in $appKotlinFiles) {
        $appKotlinText = Read-StrictUtf8 $appKotlinFile.FullName
        if ($appKotlinText -match 'ReportSection\s*\(\s*"[^"]+"\s*,\s*"' -or
            $appKotlinText -match 'ReportField\s*\(\s*"[^"]+"\s*,\s*"') {
            Add-Failure "Hard-coded user-facing report labels in $($appKotlinFile.FullName)"
        }
    }
}

$powerShellFiles = @(Get-ChildItem -LiteralPath (Join-Path $resolvedRoot 'tools') -File -Filter *.ps1)
foreach ($powerShellFile in $powerShellFiles) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($powerShellFile.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
    foreach ($parseError in @($parseErrors)) {
        Add-Failure "PowerShell parse error in $($powerShellFile.FullName): $($parseError.Message)"
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "ERROR: $_" -ForegroundColor Red }
    throw "Static verification failed with $($failures.Count) issue(s)."
}

Write-Host "Static verification passed: $($sourceFiles.Count) source files, $($defaultValuesDirectories.Count) localized resource sets, and $($moduleBuildFiles.Count) included modules."
