# APK Sentinel threat model

Status: active design and release gate  
Last reviewed: 9 August 2026

## Assets and security objectives

Protect selected APKs, inspection results, installed-app inventory, network metadata/payloads, firewall rules, threat data, reports, consent history, encryption/signing keys, and the user's continued network connectivity. APK Sentinel must remain truthful: a limitation, requested block, or incomplete parse can never be rendered as verified protection.

## Trust boundaries

1. Untrusted external input: document providers, APK/ZIP entries, manifests, DEX/native strings, URLs, QR/share text, imported rules/reports, packet bytes, DNS names, update files, and receiver endpoints.
2. Android-owned authority: PackageManager, Settings, Keyguard, VPN consent, notification permission, credential store, system picker/share surfaces, Keystore, and app sandbox.
3. Privileged engines: APK parser/signature verifier, VpnService/forwarder, firewall, raw/payload/TLS/root/streaming sessions.
4. Local persistence: encrypted databases/preferences/cache and unencrypted user-chosen exported files.
5. Optional outbound boundary: signed generic updates, reputation provider, paired receiver, and user-confirmed report handoff.
6. Build/release boundary: dependency repositories, wrapper, CI, signing key, AAB/APK, Play Console declarations, and update continuity.

## Primary threats and required controls

| Threat | Required controls and evidence |
|---|---|
| Malformed/archive-bomb APK crashes or exhausts the app | Streaming input cap; entry/count/expanded-size/ratio limits; no archive extraction; cancellation; typed partial failures; corpus/fuzz tests; preserve previous report |
| ZIP path traversal or unsafe exported name | Never extract entries; normalize display/save names; system picker; bounded redaction preview; traversal corpus tests |
| Deceptive bidi/punycode/mixed-script app or hostname | Strip control/bidi overrides from labels; show Unicode plus ASCII host; avoid unsafe truncation; TalkBack reads full hostname; mixed-script tests |
| Parser or native compromise escapes into UI/storage | Separate modules/process boundary where feasible; least privilege; no parser network access; app-private temporary files; dependency review and fuzzing |
| False malware/protection claims | Observation, interpretation, confidence, limitation, and recommendation are distinct; requested/confirmed firewall decisions differ; no score-only guarantee |
| VPN black-holes traffic or loops through itself | Never establish routes without a proven forwarder; protect every upstream socket; dual-stack tests; immediate revoke/failure stop; emergency release; physical-device matrix |
| Silent interception or overbroad collection | Feature disclosure plus Android VPN consent; notification/active state; bounded default metadata; payload/TLS/root/streaming separately disabled and authorized |
| Sensitive payload visible on lock screen/log/crash | No payload by default; screenshot/recents protection on reveal screens; redacted logger; bounded encrypted storage; crash/analytics prohibited-field tests |
| Firewall blocks critical connectivity | Reversible rules; preview; temporary allow; rule hit/confirmation; captive-portal/system exclusions; visible undo and emergency release |
| Local SOCKS/receiver endpoint is abused | No unauthenticated listening socket; bind loopback/unix socket; random per-session authentication; destination pairing; socket protection; automatic stop |
| TLS certificate remains or captures credentials | Selected-app scope; financial/password/health exclusions; persistent indication; credential warning; verified removal; no credential logging/export; cleanup gate blocks release |
| Root tooling escalates or is hijacked | Detect only; never root; exact command allowlist; no shell string construction; separate session consent; bundled binary integrity; stop/delete and abuse review |
| Threat database is forged/replayed | Offline signing key separation; signature/version/expiry/rollback checks; atomic last-known-good activation; key rotation/revocation tests |
| Inventory/traffic is exfiltrated | Default-deny outbound allowlist; network-security config; no third-party ads/replay SDK; dynamic outbound audit; provider disclosure and minimization |
| Consent reused for a different purpose | Stable purpose IDs; disclosure version/hash; session-scoped grant, expiry and revocation; T&C never acts as feature consent; unit tests |
| Encryption key unavailable or backup leaks | Keystore AES-GCM with associated data; backup disabled; recovery reset; no hardware-backed claim; exported-file warning |
| Malicious deep link/intent starts sensitive action | No exported sensitive component; Android-owned consent still checked in service; explicit in-app disclosure; validate all intent extras and session IDs |
| Supply-chain or signing compromise | Pinned Gradle checksum; dependency verification/locks/SBOM/license scan; secret scan; offline release signing; certificate continuity and artifact hashes |

## Abuse cases

- Stalkerware/covert surveillance: no silent start, boot auto-start, hidden icon, remote traffic relay, or concealed active state. Receiver sessions require visible authenticated pairing and expire.
- Credential theft: payload/TLS tools are never enabled by general terms, diagnostic consent, or VPN consent. High-sensitivity apps are excluded by default.
- Fraud/scareware: no "clean/safe guaranteed" language, forced notification/usage/VPN access, countdown, or fear-based score.
- Unauthorized app extraction: exporting installed packages/icons occurs only after a deliberate user action and current Android/Play policy check; split completeness and reinstallability limitations are shown.

## Release-blocking invariants

- No route is established without a tested forwarder for every requested IP family.
- No block is reported as enforced until the forwarder confirms it.
- No sensitive session lacks a separate receipt, visible state, immediate stop, cap, and cleanup path.
- No parser failure crashes the shell, corrupts an earlier report, or leaves its temporary copy.
- No signed public artifact is produced from unpinned dependencies or an unrecorded signing identity.
