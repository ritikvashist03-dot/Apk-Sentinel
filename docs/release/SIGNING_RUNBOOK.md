# APK Sentinel release signing runbook

The upload key is a long-lived product identity. Losing it, exposing it, or changing the key unexpectedly can block safe updates. Never commit the keystore or passwords, paste them into chat, store them in Gradle files, or place them in a cloud-synced workspace.

## One-time owner action

1. In Android Studio choose **Build > Generate Signed App Bundle or APK > Android App Bundle > Create new**.
2. Save the upload keystore in an encrypted, backed-up location outside this repository.
3. Use alias `apk-sentinel-upload`, a unique strong store password, a unique strong key password, validity of at least 25 years, and the real publisher identity intended for Play.
4. Make two encrypted backups in separate controlled locations. Record recovery ownership and rotation procedure.
5. Enrol in Play App Signing at first upload. Preserve both the upload-certificate and Play app-signing-certificate SHA-256 fingerprints in release evidence. Play’s current flow distinguishes the developer-held upload key from the Google-held app-signing key; use a distinct upload key and register the Play-held certificate with any API provider that validates the installed app. Source checked 13 August 2026: [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en).

Do not use the debug keystore, an automatically generated unknown password, or a key created only inside an ephemeral CI runner.

## Local release build

Set these variables only in the trusted release shell/process:

```powershell
$env:APK_SENTINEL_KEYSTORE_PATH = 'X:\secure\apk-sentinel-upload.jks'
$env:APK_SENTINEL_STORE_PASSWORD = '<secret>'
$env:APK_SENTINEL_KEY_ALIAS = 'apk-sentinel-upload'
$env:APK_SENTINEL_KEY_PASSWORD = '<secret>'
$env:APK_SENTINEL_THREAT_FEED_KEY_ID = 'publisher-2026-01'
$env:APK_SENTINEL_THREAT_FEED_PUBLIC_KEY_BASE64 = '<P-256 SubjectPublicKeyInfo Base64>'
$env:APK_SENTINEL_LEGAL_PUBLISHER_NAME = '<real Play publisher legal name>'
$env:APK_SENTINEL_SUPPORT_EMAIL = '<monitored support address>'
$env:APK_SENTINEL_PRIVACY_POLICY_URL = 'https://<public-host>/apk-sentinel/privacy'
$env:APK_SENTINEL_PRIVACY_POLICY_EFFECTIVE_DATE = '2026-08-11'
$env:APK_SENTINEL_TERMS_EFFECTIVE_DATE = '2026-08-11'
```

The threat-feed key is a separate publisher-controlled P-256 key. Only its
public X.509 SubjectPublicKeyInfo Base64 value is embedded in the app. Never
reuse the Play upload key for threat data and never place either private key in
this repository. Release tasks fail when the feed verification key is absent.
The offline helper in `tools/` can generate and use this separate key.

Then run the complete release gate and clear the password variables immediately afterwards:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-release.ps1 `
  -AndroidSdk 'C:\Users\Dell\AppData\Local\Android\Sdk' `
  -BundletoolJar 'X:\reviewed-tools\bundletool-all.jar'
Remove-Item Env:APK_SENTINEL_STORE_PASSWORD,Env:APK_SENTINEL_KEY_PASSWORD
```

The release helper renders a host-ready privacy-policy artifact, verifies that the configured public HTTPS page is reachable and contains the expected product title/support address, then runs unit tests, lint, both release artifacts, dependency reporting, bundletool validation, APK signature verification, source/artifact/toolchain hashes, and an evidence manifest. It parses application ID, version, minimum SDK, and target SDK from the signed APK, rejects a debuggable package, and requires the R8 mapping for the minified release. It fails if any privacy-policy placeholder survives. The build refuses `bundleRelease`/`assembleRelease` when any signing input is absent, the keystore path is invalid, the feed key is not exact P-256, or publisher/legal fields are missing or malformed. A custom domain is optional, but the privacy-policy URL must be public HTTPS. Signing inputs stay outside source control.

## Play delivery verification

For a new Play app, the production submission is the signed AAB, not the local APK. Google Play creates the optimized APKs delivered to devices. After the first upload, use Internal App Sharing or download device-specific generated APKs from App Bundle Explorer and test them with the exact reviewer flow. Record the generated APK source, hashes, certificate fingerprint, device configuration, install/upgrade result, permissions, foreground-service notification, declarations, and feature/default-state checks. See [Android App Bundles](https://developer.android.com/guide/app-bundle) and [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en), both checked 13 August 2026.

Do not treat a locally release-signed APK as evidence of Play signing, Play-generated splits, or Play policy approval. The complete dated policy and Console-evidence list is [Policy evidence snapshot — 13 August 2026](POLICY_EVIDENCE_2026-08-13.md).

## Artifact verification

For both AAB and APK record file size and SHA-256. Verify the APK certificate and schemes with current Android Build Tools `apksigner verify --verbose --print-certs`. Inspect the AAB with `bundletool validate` and generate/test Play-style device APKs. Attach mapping/native symbols, dependency lock/SBOM, source revision, JDK/Gradle/AGP versions, build time, and certificate fingerprints to the evidence bundle.
