# Offline release helpers

Keep every private-key output outside this repository and outside cloud-synced
folders. The helper refuses to overwrite key files.

```powershell
& 'E:\Apk\jbr\bin\javac.exe' 'D:\Projects\explore\apk-sentinel\tools\ThreatFeedKeyTool.java'
& 'E:\Apk\jbr\bin\java.exe' -cp 'D:\Projects\explore\apk-sentinel\tools' ThreatFeedKeyTool generate 'X:\secure\apk-sentinel-feed-private.pk8' 'X:\secure\apk-sentinel-feed-public-base64.txt'
& 'E:\Apk\jbr\bin\java.exe' -cp 'D:\Projects\explore\apk-sentinel\tools' ThreatFeedKeyTool sign 'X:\secure\apk-sentinel-feed-private.pk8' 'X:\publisher\feed-v1.txt'
```

The final command prints a one-line detached Base64 signature. Save it beside
the feed in the publisher workspace. The helper never downloads or uploads.

## Final release evidence

After all owner-controlled release variables are set and Gradle execution is available, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-release.ps1 `
  -AndroidSdk 'C:\Users\Dell\AppData\Local\Android\Sdk' `
  -BundletoolJar 'X:\reviewed-tools\bundletool-all.jar'
```

Use a reviewed official bundletool release. The script requires bundletool,
renders a publishable privacy-policy file from owner-controlled environment
values, verifies the configured public HTTPS policy page, runs
tests/lint/release builds, validates the AAB, verifies the APK signature, and
writes artifact hashes plus signing evidence to
`build/release-evidence/artifact-manifest.json`. Secret values are never
written to that evidence file. The same gate parses identity/version/SDK data
from the signed APK, rejects a debuggable release, hashes the R8 mapping,
records the JDK/Gradle/AGP/Build Tools/bundletool inputs, writes a deterministic
source-file hash manifest, and captures the release runtime dependency report.

The policy renderer can also be checked independently:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\render-privacy-policy.ps1
```

The source-only preflight is safe to run while Android/Gradle execution is unavailable:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-static.ps1
```

It checks strict UTF-8/XML parsing, complete English/Hindi resource and format-placeholder parity, resource references, module inclusion, the AGP 9 built-in Kotlin rule, PowerShell syntax, implementation markers, and hard-coded Compose UI text. The final release helper runs this preflight automatically before Gradle.

As checked on 11 August 2026, Google's current bundletool release is 1.18.3:
<https://github.com/google/bundletool/releases>. Recheck the official release
page and its asset/hash immediately before downloading; do not copy a JAR from
an unofficial mirror.
