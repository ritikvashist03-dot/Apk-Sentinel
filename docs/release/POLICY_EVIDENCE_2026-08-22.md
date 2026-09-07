# APK Sentinel policy evidence snapshot — 22 August 2026

Status: engineering policy research only. This is neither legal advice nor a Google Play approval. Recheck Play Console against the final signed AAB and actual production data flows immediately before submission.

## Source configuration checked

This snapshot inspected source only; it did not compile, install, inspect, or upload a signed artifact.

- `app/build.gradle.kts` declares application ID `app.apksentinel.mobile`, `minSdk = 26`, `targetSdk = 36`, and `compileSdk = 37`.
- Source manifests request broad package visibility and declare a local, non-exported `VpnService` plus an Android 14+ `specialUse` foreground service. A merged-release-manifest inspection is still required.
- The default product has no ads, account requirement, analytics transport, or remote VPN server. Every optional off-device route still needs final data-flow and Data Safety review.
- `app/build.gradle.kts` accepts optional `APK_SENTINEL_THREAT_FEED_UPDATE_ENDPOINT` and `APK_SENTINEL_OFFLINE_ATTRIBUTION_UPDATE_ENDPOINT` values. Blank values intentionally disable update transport; the app has no automatic update scheduler.
- When configured, only an explicit user-triggered HTTPS GET is permitted. The response is bounded and detached-signed; no cookies, credentials, APK inventory, capture data, or traffic are sent, and a failed candidate retains the current verified protection.

## Current official requirements and release consequence

| Area | Official evidence checked 22 August 2026 | Required release evidence |
|---|---|---|
| Target API | From 31 August 2026, new phone/tablet apps and updates must target Android 16 / API 36 or higher. [Android Developers — target API requirement](https://developer.android.com/google/play/requirements/target-sdk) (page updated 14 August 2026). | Inspect the signed AAB/APK and prove `targetSdk=36`; source alignment alone is not a release pass. |
| Broad app visibility | Google treats installed-app inventory as personal and sensitive. `QUERY_ALL_PACKAGES` is permitted only when broad visibility is core user-facing functionality and a narrower approach is insufficient; a Permissions Declaration Form is required. [Play Console Help — broad package visibility](https://support.google.com/googleplay/android-developer/answer/10158779?hl=en). | Submit a core-function and least-privilege justification, prominent disclosure evidence, reviewer instructions, and proof that inventory data is not sold or used for ads/analytics. |
| VPN service | Every `VpnService` app must complete the declaration. Device-security/firewall and network-tool use can be eligible only when genuine core functionality; use must be documented and sensitive-data access requires prominent disclosure and consent. Traffic may not be manipulated for monetization. [Play Console Help — VpnService](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en). | Provide the final listing wording, disclosure and accept/decline evidence, Android consent, active notification and Stop path, exact tunnel/encryption explanation, Data Safety alignment, and reviewer video. Play eligibility remains a Console decision. |
| Foreground service | Android 14+ requires the appropriate FGS type and normal permission. `specialUse` requires a manifest subtype and Play declaration and is reviewed. [Android Developers — foreground-service types](https://developer.android.com/about/versions/14/changes/fgs-types-required) and [Play Console Help — FGS declaration](https://support.google.com/googleplay/android-developer/answer/13392821?hl=en). | Inspect the merged manifest and demonstrate that monitoring is user-started, user-perceptible, immediately stoppable, and accurately described by the submitted subtype. |
| Data Safety and disclosure | Play requires accurate Data Safety answers and an accessible privacy policy. Unexpected access to personal or sensitive data needs an in-app disclosure before access plus distinct affirmative action; terms acceptance is not a substitute. [Play Console Help — Data Safety](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en), [User Data](https://support.google.com/googleplay/android-developer/answer/10144311), and [prominent disclosure](https://support.google.com/googleplay/android-developer/answer/11150561?hl=en). | Audit the final artifact and all outbound routes, then record clean-device accept, decline, re-entry, deletion, and retention evidence for package inventory, VPN, raw/payload/TLS/root capture, remote streaming, lookups, reports, and the optional user-triggered signed feed/bundle update request. |
| AAB and signing | New Play apps publish as Android App Bundles; Play App Signing uses an upload key separately from the Play-held app-signing key. [Android Developers — App Bundles](https://developer.android.com/guide/app-bundle) and [Play Console Help — Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en). | Produce and verify a release-signed AAB, preserve certificate fingerprints, validate the bundle, and test Play-generated APKs. A local APK alone is not Play-delivery proof. |
| Developer verification | Developer identity and package registration are owner/Console controls, separate from source implementation. [Android developer verification](https://developer.android.com/developer-verification). | Verify the developer account and register `app.apksentinel.mobile` with final signing evidence before the applicable deadline. |

## Required Play submission package

1. Final publisher identity, support contact, public HTTPS privacy-policy URL, effective dates, and accurate Data Safety answers.
2. `QUERY_ALL_PACKAGES`, `VpnService`, and foreground-service declarations tied to the final artifact and reviewer path.
3. A short clean-device video showing the full VPN disclosure, decline and re-entry, Android consent, active notification, Stop, and the core local outcome.
4. Content rating, target audience, app-access instructions, store screenshots, and policy wording captured from the signed candidate.
5. Release AAB, upload and Play-signing fingerprints, mapping/SBOM, source/build hashes, bundle inspection, device matrix, and Play-generated-APK evidence.

## Current blockers that source work cannot close

- No current signed artifact or merged-release-manifest inspection exists.
- Play Console declarations, Data Safety answers, developer verification, package registration, and policy decisions require the publisher account.
- The final public legal identity, support contact, privacy-policy URL, effective dates, upload keystore, and production threat-feed key are still owner-supplied release inputs.
- Clean-device, Android-version, OEM, accessibility, network-transition, and Play-generated-APK evidence still requires device/emulator and Console execution.
