# APK Sentinel Play release checklist

This checklist cannot grant policy approval. Recheck dated official Google Play and Android requirements at submission time and attach evidence to `COMPLETION_LEDGER.md`.

## Dated policy baseline (refreshed 18 August 2026)

The latest linked authoritative detail, source-manifest inventory, submission package, and unresolved risks are recorded in [Policy evidence snapshot — 13 August 2026](POLICY_EVIDENCE_2026-08-13.md). That snapshot is a dated starting reference and must be refreshed at submission. This checklist is source/release planning, not a Play approval; the current ledger remains **Not assessed / TBD**.

- New phone/tablet apps and updates submitted from 31 August 2026 must target Android 16 / API 36 or higher. The current source sets `targetSdk = 36`; the signed artifact still needs inspection. Source: [Android target API requirement](https://developer.android.com/google/play/requirements/target-sdk).
- All Play developers complete Data Safety and provide a privacy-policy link. Local-only processing, user-directed transfers, IP addresses, redirect checks, exports, and SDKs must be assessed by their actual data flow—not by a generic “local-first” label. Source: [Data Safety form guidance](https://support.google.com/googleplay/android-developer/answer/10787469?hl=en).
- The source uses `QUERY_ALL_PACKAGES`, `VpnService`, and an Android 14+ `specialUse` foreground service. Each has a distinct declaration/review path; source presence does not establish Play eligibility. Sources: [broad app visibility](https://support.google.com/googleplay/android-developer/answer/10158779?hl=en), [VpnService](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en-EN), and [foreground-service types](https://developer.android.com/about/versions/14/changes/fgs-types-required).
- Per-app English/Hindi configuration uses Android’s supported locale configuration path, but needs Android 26–37 device verification and human language review. Source: [per-app language preferences](https://developer.android.com/guide/topics/resources/app-languages).
- New Play apps publish with an AAB and should be tested from Play-generated APKs after configuring Play App Signing. Source: [Android App Bundles](https://developer.android.com/guide/app-bundle) and [Play App Signing](https://support.google.com/googleplay/android-developer/answer/9842756?hl=en).
- Play packages must be registered for Android developer verification by 30 September 2026. Source: [registering Play package names](https://support.google.com/googleplay/android-developer/answer/16984799?hl=en).

### Current-source boundary

- `.apks`/`.xapk` bounded inspection and base-plus-split export are source-integrated but not compiled or device-tested; exported base-plus-split material is not reinstall-guaranteed.
- Encrypted network history is selectable (session only, 1 day, 7 days, or 30 days), with 7 days as the app default. Installed-app continuity stores one encrypted prior snapshot, not a 30-day history.
- Protocol evidence is off by default, separately acknowledged, active-session only, and in memory. Likely-plaintext payload viewing is separately acknowledged, best-effort redacted, memory-only, and defaults to a five-minute maximum session.
- TLS is certificate setup only. Root capture is separately gated on an already-rooted device with no automatic rooting. Authenticated remote streaming is source-integrated as a default-off Sensitive Advanced literal-IP, pinned mutual-TLS session for bounded metadata and upstream-classified encrypted/raw records, but it is not device/network/security/release verified.
- Flow metadata export is redacted JSON/NDJSON to a user-selected SAF document. No reputation, update, analytics, or support transport exists in the current source.
- These are source-integrated/unavailable observations, not release evidence. No Gradle, device/OEM, signed artifact, or Play verification is claimed in this review.

These checks are a dated engineering baseline, not legal advice or Play approval. Recheck them on the actual submission date.

## Identity and artifacts

- [ ] Final application ID, product title, icon, version name/code, support contact, privacy-policy URL, and store listing are approved.
- [ ] Clean reproducible `bundleRelease` and `assembleRelease` pass with unit, lint, static, instrumentation, and dependency verification gates.
- [ ] Record AAB/APK SHA-256, upload/app-signing certificate SHA-256, source revision, build timestamp, dependency lock/SBOM, and mapping/native-symbol files.
- [ ] Test Play-generated APKs from the AAB, not only a locally assembled APK.

## Required declarations

- [ ] `QUERY_ALL_PACKAGES`: Permissions Declaration Form, final core-function/least-privilege justification, in-app visibility disclosure, truthful limited-coverage behavior, no inventory upload, and reviewer instructions/video.
- [ ] `VpnService`: declaration identifies the truthfully supported device-security/firewall purpose; listing documents it; separate pre-consent disclosure, one-VPN limitation, active notification, Data Safety alignment, and a <=90-second accept/decline reviewer video are attached.
- [ ] Foreground service: `specialUse` subtype/property, source service behavior, signed-artifact manifest, user-perceptible active notification, and Play Console foreground-service declaration match exactly. Do not assume `specialUse` is approved or switch to `systemExempted` without platform eligibility.
- [ ] Notification permission is requested contextually before a visible monitoring session, with a useful denial path.
- [ ] Data Safety has a build-specific outbound audit covering selected files, installed apps, network metadata, optional raw PCAPNG capture (including IP-address/plaintext-content risk), redacted flow-metadata SAF export, redirect resolution, exports/share recipients, every SDK, encryption, retention, deletion, and zero-account behavior. It records that no reputation, update, analytics, or support transport exists. It distinguishes local-only processing from any data actually collected/shared.
- [ ] Sensitive permissions/APIs and every SDK are declared; no SDK performs undeclared collection.

## Policy-sensitive features

- [ ] Optional raw PCAPNG capture is disabled by default, user-initiated only, bound to a user-selected document and explicit scope/time/size disclosure, independently reviewed, visibly active/stoppable, and accurately disclosed as potentially containing IP addresses or plaintext/content. It has no payload preview, TLS decryption, or APK Sentinel upload.
- [ ] Other PCAP/payload/TLS/root/streaming capabilities, if present, remain disabled by default, independently reviewed, and exposed only through their approved route. Current source exposure is not verification.
- [ ] TLS certificate setup/removal rehearsal passes and the listing/reviewer instructions accurately state that this build has no traffic-decryption data plane or selected-app traffic session.
- [ ] Root capture proves the app never roots a device and cannot start without an already-rooted environment plus explicit session authorization; the current route is fixed IPv4 TCP connection-control headers only.
- [ ] Live receiver protocol, client and receiver tools, visible state, exact destination binding, data-category limits, time/queue/byte bounds, automatic stops, clear/erase behavior, and no-background/no-discovery claims are independently reviewed and exercised on the final signed artifact before public exposure.
- [ ] Fraud reporting names the actual recipient/portal; no claim implies APK Sentinel or Google submitted a report when Android only opened another app/site.
- [ ] Developer-account identity verification and package registration for `app.apksentinel.mobile` are complete with the final signing certificate, before the 30 September 2026 requirement.

## Reviewer rehearsal

- [ ] Fresh install in English and Hindi; 200% font; dark/light; TalkBack; phone/tablet/foldable; gesture/three-button navigation.
- [ ] Decline package visibility context, notification, VPN, usage, optional lookup, raw capture, TLS, root, and streaming; useful unaffected paths remain.
- [ ] Start/pause/stop/revoke VPN on Wi-Fi/mobile, IPv4/IPv6, Private DNS, captive portal, another VPN, lockdown/always-on, reboot/update, low memory/storage, and OEM task killing.
- [ ] Inspect valid, split, `.apks`, `.xapk`, unsigned, corrupt, oversized, traversal, encrypted, and archive-bomb APK corpus without losing an earlier result; verify that base-plus-split export is not represented as reinstall-guaranteed.
- [ ] Exercise firewall breakage/undo/emergency release, raw PCAPNG capture scope/limits/active indication/Stop, saved-file persistence outside erase, retention expiry, category deletion, erase all, certificate cleanup, exported-file explanation, and uninstall cleanup.

## Listing and operations

- [ ] Screenshots and copy show real verified screens; no "complete protection," malware guarantee, fake scan, fear language, or unsupported reputation claim.
- [ ] Privacy policy, T&C, support/runbook, vulnerability disclosure, license notices/source obligations, threat-feed dispute process, incident response, staged rollout, rollback, and safe kill switch are live.
- [ ] Closed/internal testing reports meet crash/ANR, battery, startup, low-end performance, accessibility, comprehension, and alert-precision thresholds before production rollout.
