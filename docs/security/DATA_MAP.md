# APK Sentinel data map

Status: normative current-truth contract; source-integrated behavior is not
release verification  
Last reviewed: 22 August 2026

APK Sentinel is local-first and has no account, advertising SDK, mandatory cloud service, or silent traffic/history upload. "Local" does not mean harmless: APK contents, package inventory, domains, IP addresses, payloads, certificates, and reports can still be sensitive. Every implementation and test must use this map.

| Data class | Source and purpose | Current source storage/retention | Outbound behavior | Required user control |
|---|---|---|---|---|
| Selected APK/package file | Android system picker; static inspection only | Bounded private temporary copy; delete at the end, including partial/cancel paths | None | Cancel, revoke persisted URI grant, delete report |
| APK report | Local parser: hashes, manifest, signer, inventory, evidence | Current result remains in the active screen; there is no durable APK-report history. User-saved reports are outside app storage. | Only a user-selected save/share destination after preview | Cancel analysis, replace current result, redacted export |
| Installed-app inventory | PackageManager; app inspection and collection statistics | One encrypted prior inventory snapshot is retained for change comparison; this is continuity, not a 30-day inventory history | None | Refresh, clear snapshot through Erase, visibility disclosure |
| Device-posture signals | Android settings/build/keyguard and bounded local indicators | Bounded encrypted typed observations; no raw setting values or causal claims | None | Refresh, clear history through Erase, open authoritative Android setting |
| URL input/result | User paste; safe normalization and local list match | Current composition only; raw input is not saved-instance or durable history state | Redirect resolution only after a separate choice; no reputation provider is integrated | Clear/replace input, decline redirect resolution, choose official portal handoff |
| VPN connection metadata | User-started VpnService; app, time, destination, bytes, decision/evidence | Encrypted metadata history with selectable session-only, 1-day, 7-day, or 30-day retention; 7 days is the app default. The underlying engine event store is additionally bounded and process-local | None; never a remote VPN | Pause/stop, clear category, retention choice |
| DNS/HTTP/SNI/protocol metadata | Observable session traffic | DNS names are hashed per session by default. Narrow protocol evidence is off by default, separately acknowledged, active-session only, and in memory; it is not added to encrypted history | No reputation/update/analytics/support transport. Flow export is a user-selected SAF handoff of redacted metadata only | Visibility scope, stop, clear/export preview |
| Raw packets/PCAPNG | Explicit user-started bounded raw capture | Off by default; written directly to the Android document destination chosen by the user, not retained as app-private capture history | User-selected document destination only; no APK Sentinel upload, payload preview, TLS decryption, or paired receiver | Scope/time/size and sensitive-content warning, visible active state, immediate Stop, and exported-file persistence explanation |
| Likely-plaintext payload | Specific Sensitive Advanced session | Off by default; separately acknowledged, best-effort redacted bytes in memory only, default maximum session duration 5 minutes, with zeroization on hide/stop/disposal. No decrypted-TLS store exists. | No export, analytics, support collection, or remote transfer from the payload surface | Separate session and reveal acknowledgements, stop/hide cleanup, lock-screen privacy |
| Capture-document metadata catalog | Explicit user-selected SAF document open/create flow | Stable ID, URI grant, size, format, availability, and timestamps in bounded Android Keystore-encrypted metadata; capture bytes remain in the user-selected document provider | None; no scan/upload and no document deletion claim | Refresh, forget, release grant after successful metadata removal, erase metadata/keys while explaining user documents remain |
| TLS inspection certificate/key material | Advanced network screen; explicit user setup action only | The integrated surface can prepare per-install non-exportable Keystore material and launch Android's user-mediated certificate installer after disclosure and consent. No TLS traffic decryption data plane or decrypted-payload history is integrated. | None | The UI keeps the capability unavailable for traffic sessions, reports installation as unknown when Android cannot verify it, and provides removal guidance through Android settings |
| Root capture artifacts | Sensitive Advanced network screen; explicit capability check and capture action only | Source-integrated already-rooted route for fixed IPv4 TCP connection-control headers only; no automatic rooting. Bounded output is temporary app-private data until stopped export/erase. This is source-integrated but unverified. | User-selected document destination only after an explicit stopped-session export | Capability consent, fixed scope, visible active/Stop state, bounded session/output limits, immediate cleanup on export/erase, and never attempt rooting |
| Firewall rules | User decisions and threat-feed matches | Encrypted until deleted or expiry; temporary rules expire | None | Undo, temporary allow, emergency release, delete all |
| Threat/ASN data | Publisher-signed threat feed and country/ASN bundle; manual SAF import remains available | Verified bytes and rollback metadata are encrypted locally. A failed candidate or update request retains the active feed/bundle. Offline attribution remains unavailable unless a signed bundle/key is configured. | Only an explicit user-triggered HTTPS GET to an exact configured publisher endpoint, with a detached bounded signature header; the request sends no APK inventory, capture data, traffic, cookies, or credentials. Blank endpoints mean no update transport. | Optional update action, active/last version and publisher-signed disclosure, rollback rejection, erase/import replacement |
| Consent receipts/audit events | Feature-specific affirmative actions | Per-feature typed session consent plus a bounded encrypted deletion receipt; no complete append-only consent ledger exists | None by default | Withdraw/stop the active feature and erase local data |
| Authenticated live receiver stream | Explicit Sensitive Advanced session after encrypted pairing, exact destination/pin review, and fresh session consent while local VPN monitoring is active | Off by default; pairing is encrypted locally. One protected outbound pinned mutual-TLS connection can send only bounded `METADATA` and upstream-classified `RAW_ENCRYPTED_PACKET` APSR records; queue, record, byte, packet, and ten-minute default limits apply. No decrypted payload or credential category is authorized by the app route | User-paired literal-IP receiver only; no DNS discovery, cloud relay, analytics, or silent background destination | Exact destination/fingerprint, active state and Stop; automatic stop on VPN/service/process/background/network/authentication/clock/limit events; erase pairing and client identity |
| Diagnostics/analytics/support | User-created redacted reports; analytics/support transport absent | Temporary report bytes/cache are bounded and cleared on completion/cancel where implemented; no analytics or support diagnostic transport exists | Only a user-confirmed Android save/share/report handoff | Preview, cancel, delete app-private data; exported files remain user-controlled |

## Storage and key rules

- App-private databases/preferences containing sensitive records use Android Keystore-backed AES-GCM. The app must not claim hardware-backed keys unless a specific device attestation proves it.
- Backups are disabled in the manifest and data-extraction rules. Exported files are outside app deletion control; the UI explains this.
- Logical storage keys are authenticated as associated data. Key loss or invalidation produces a recoverable local-data reset path without logging plaintext.
- Size/time limits are enforced before writes and during streaming. Low-storage behavior stops capture safely before corrupting prior records.
- Erase all first stops services/schedules, deletes app-private databases/cache, revokes app-owned grants where possible, destroys app-owned keys, and explains remaining exported files (including raw PCAPNG documents), Android VPN consent, or installed certificates. A file already saved to a user-selected destination remains outside app deletion control.

## Outbound allowlist

The release network-security test must observe no outbound connection except a user-enabled, documented Android handoff below:

1. a user-selected raw PCAPNG document save through Android's storage provider (the provider receives the file, but APK Sentinel does not upload it);
2. a user-selected redacted flow-metadata document export through Android's storage provider;
3. a user-confirmed report/fraud-portal handoff through Android; or
4. an optional user-approved redirect-resolution request, only where the current
   URL-inspector route is deliberately enabled and its outbound fields are
   previewed; or
5. an explicit user-triggered signed threat-feed or country/ASN update request,
   only when an exact HTTPS endpoint is configured in the build. It sends only
   the update request and receives bounded publisher-signed bytes; it has no
   cookies, credentials, inventory, capture, traffic, analytics, or support
   fields. There is no automatic update scheduler in the app composition.

Any new outbound field or destination changes this document, the disclosure, Data Safety form, tests, and release evidence before activation.
