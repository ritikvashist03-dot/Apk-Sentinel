# APK Sentinel

Current-source review: 18 August 2026. The capabilities described below are
source-integrated observations unless a release-verification statement says
otherwise. No current Gradle build, device/OEM run, signed artifact, or Play
decision is implied by this README; the release ledger remains **Not assessed /
TBD**.

APK Sentinel is a privacy-first Android security utility for inspecting APK files, reviewing installed-app evidence, checking device protections and links, and running a user-started local VPN with bounded metadata, numeric firewall rules, and an optional bounded raw PCAPNG export.

The product reports observations, confidence and limitations. It does not label every unusual APK as malware or promise that a phone, app, link, or connection is safe.

## Current architecture

| Module | Responsibility |
|---|---|
| `app` | Compose navigation, disclosures, result presentation, exports, privacy controls and Android system handoffs |
| `core:model` | Shared evidence and report-domain models |
| `core:security` | Safe text/file normalization, grants and Android Keystore-backed encrypted storage |
| `core:reporting` | Bounded redacted JSON/CSV report rendering |
| `core:designsystem` | Theme, responsive layout and accessible reusable components |
| `feature:device-posture` | Local device-protection checks and Android Settings handoffs |
| `feature:app-inspector` | Installed-app inventory, evidence, statistics and user-initiated exports |
| `engine:apk-inspector` | Hostile-input-bounded APK/ZIP, `.apks`/`.xapk`, signing and readable-manifest inspection |
| `engine:url-inspector` | Non-opening local URL analysis and DNS-rebinding-safe optional redirect resolution |
| `engine:network-monitor` | VpnService lifecycle, limited on-device forwarding, metadata, encrypted bounded history, firewall policy, optional raw PCAPNG and separately gated in-memory payload inspection |
| `engine:threat-intel` | Strict P-256 signed offline feed verification, rollback/expiry handling and encrypted snapshots |
| `engine:tls-inspection` | Integrated certificate-setup safety path only; no traffic-decryption data plane or active inspection route |
| `engine:remote-stream` | User-consented literal-IP remote stream with pinned P-256 receiver identity, APS1/APSA attestation, ordered AES-GCM frames, bounded drop-newest queue and VPN-owned lifecycle |

Each engine has a `HANDOFF.md` describing its exact API, evidence boundary and remaining limitations.

## Build environment

- Android Studio / JBR 17
- Android SDK with API 37 compile platform and API 36 target support
- Gradle wrapper included in the project
- No Kotlin Android plugin: AGP 9.3 built-in Kotlin is used; Compose modules apply only the Compose compiler plugin

On Windows PowerShell, with `JAVA_HOME` set to Android Studio's JBR:

```powershell
.\gradlew.bat test lint assembleDebug
```

The latest source changes require a new full run before any release-readiness claim. Earlier build outputs do not validate later edits.

## Privacy and safety defaults

- no account, ad SDK, analytics transport or APK Sentinel remote server;
- Android's document picker for selected files and exports;
- bounded private APK copies, archive expansion and decoded-manifest output;
- link checks stay offline unless the user separately permits redirect resolution;
- local VPN requires an app disclosure, Android VPN consent, notification visibility and a reachable Stop action;
- encrypted network history is selectable (session only, 1 day, 7 days, or 30 days), with 7 days as the app default; saved firewall policy is local; retention and erase controls do not affect files the user has exported;
- installed-app continuity keeps one encrypted prior snapshot for change comparison; it is not a 30-day installed-app history;
- protocol evidence is off by default, requires a fresh active-session acknowledgement, and remains bounded in memory for that session only;
- ordinary monitoring does not persist packet payloads; an optional user-started raw PCAPNG capture writes to a user-selected document only, may include IP addresses or plaintext/content, never starts automatically, and has a visible active state and Stop action;
- optional Sensitive Advanced payload viewing is separately acknowledged, likely-plaintext only, bounded to memory for a default maximum of five minutes, best-effort redacted, never exportable from that surface, and zeroized on stop/hide/disposal;
- TLS has an integrated certificate-setup path only; there is no traffic decryption data plane, package picker, or decrypted-TLS history. Root capture is an already-rooted, explicitly gated fixed IPv4 TCP connection-control-header route with no automatic rooting. Remote streaming is an explicit advanced path only: it uses a user-entered literal IP, enrolled P-256 mTLS identities, APS1/APSA plus ordered authenticated frames, a bounded encrypted queue, and a user-selected local `RAW_ENCRYPTED_PACKET` sink on the desktop receiver;
- flow metadata export is a bounded redacted JSON/NDJSON SAF export; it omits endpoint addresses, DNS values, package/flow identifiers and payload content;
- there is no reputation transport, threat-feed update transport, analytics transport, APK Sentinel remote server, or support-diagnostic transport in the current source;
- saved exports, including PCAPNG files, are outside app storage and cannot be removed by in-app erase after saving;
- manual threat feeds must verify against the packaged exact P-256 key and are encrypted locally after acceptance;
- app-owned local data, grants, events/rules and the threat-feed key have an explicit erase path.

## Release

Read these before creating any signed artifact:

- `docs/release/COMPLETION_LEDGER.md`
- `docs/release/PLAY_STORE_CHECKLIST.md`
- `docs/release/SIGNING_RUNBOOK.md`
- `docs/release/STORE_LISTING_DRAFT.md`
- `docs/REFERENCE_APP_PARITY_MATRIX.md`

Release tasks deliberately fail until external signing inputs, the publisher threat-feed key, legal publisher name, monitored support email, public HTTPS privacy-policy URL and Terms effective date are provided. Secrets and private keys must remain outside the repository. The source-integrated `.apks`/`.xapk` bounded inspection, base-plus-split export, network history, protocol evidence, payload view, root setup, TLS setup, remote pairing setup, and flow export are not release-verified here.

The included privacy-policy HTML is a publishing template with explicit owner placeholders. A custom domain is optional, but Play publication still requires a public policy URL and complete declarations.

## Evidence rule

Source presence, a screenshot, or a debug build is not release evidence. APK Sentinel 1.0 is release-verified only after current unit/lint/instrumentation tests, hostile-input tests, device/OEM/network checks, English/Hindi and accessibility review, signed APK/AAB verification, current Play declarations and the completion ledger all pass for the same artifact tuple.
