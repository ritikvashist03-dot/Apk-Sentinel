# APK Sentinel reference-app parity contract

Status: required product scope; current-source status is recorded separately
and is not release verification  
Baseline checked: 22 August 2026  
References: M-Kavach 2 current Google Play listing, PCAPdroid official repository/user guide, and APK Analyzer by Martin Styk current Google Play listing.

This is a capability-parity contract, not permission to copy another product's code, artwork, wording, private services, trademarks, or proprietary verification data. APK Sentinel must implement equivalent user outcomes with its own design, evidence model, security boundaries, and independently reviewed dependencies.

## Coverage meanings

- **Play Simple:** available in the default consumer experience using plain language.
- **Play Advanced:** included in the Play build but revealed only after Advanced mode is deliberately enabled.
- **Sensitive Advanced:** included in the same product/codebase and delivery cycle, disabled by default, device-capability gated, and protected by feature-specific consent, persistent indication, bounded storage, cleanup, and additional security review.
- **Equivalent:** delivers the user outcome without depending on a reference product's proprietary service.

No row may be silently dropped or deferred while waiting for store review. “Not technically possible” requires evidence from supported Android public APIs and a recorded alternative user path.

## Play-distribution evidence note — 18 August 2026

Parity scope does not establish a permissible Play distribution route. The latest linked official-source policy snapshot is [Policy evidence snapshot — 22 August 2026](release/POLICY_EVIDENCE_2026-08-22.md); it remains a dated starting reference and must be refreshed at submission. In particular, installed-app inventory requires a `QUERY_ALL_PACKAGES` necessity/declaration review, local-VPN monitoring requires `VpnService` declaration and prominent consent when sensitive data is accessed, and the Android 14+ `specialUse` foreground-service subtype is independently reviewable. PCAP, reports, redirect checks, payload/TLS/root/streaming routes need a signed-build data-flow audit and Data Safety assessment before their public exposure is claimed.

No parity row may be called policy-approved based on source code, a local APK, or this matrix. Its delivery state is governed by the release ledger and its signed-artifact/device/Console evidence cards.

## Current source status — 22 August 2026

Every row below remains a mandatory outcome. The labels in this section are
implementation observations only and do not change a row's required outcome or
the release ledger state. No row is Release verified in this source review.

| Mandatory row family | Current source status |
|---|---|
| M-Kavach device, app, link, fraud, and language outcomes | Source-integrated local flows are present, including device posture, installed-app evidence, local link analysis, optional redirect resolution, signed-feed import, optional user-triggered publisher-signed feed updates, a redacted fraud-report draft, and official fraud-portal handoff. Update endpoints are intentionally blank until publisher infrastructure is configured; no reputation, analytics, or support transport exists. The handoff reports opened/cancelled/unavailable and never uploads or submits from APK Sentinel. Build/device/accessibility/Play evidence is unavailable. |
| APK Analyzer selected/installed analysis | Source-integrated bounded APK analysis is present. `.apks`, `.xapk`, and `.aab` handling are integrated: AAB input is retained as bounded publishing-structure evidence and is never called directly installable. These paths are not compiled or device-tested in this source review. Installed-app continuity stores one encrypted prior snapshot only. Base-plus-split export is source-integrated and is not reinstall-guaranteed. |
| PCAP-01 through PCAP-04 monitoring and protocol evidence | Source-integrated local VPN, encrypted metadata history, firewall composition, and narrow protocol evidence are present but unverified. Encrypted history is selectable (session only, 1 day, 7 days, or 30 days), with 7 days as the app default. Protocol evidence is off by default, separately acknowledged, active-session only, and in memory. |
| PCAP-05 payload inspection | Source-integrated Sensitive Advanced likely-plaintext view, separately acknowledged and best-effort redacted, is memory-only with a default five-minute maximum session. It is not TLS decryption and is not release-verified. |
| PCAP-06 TLS inspection | A selected-app, bounded TLS inspection route is source-integrated with user-mediated CA setup, explicit per-session acknowledgement, TCP/443 interception, and selected-app QUIC rejection. It is not yet compiled or device/OEM verified; certificate pinning may prevent inspection. Plaintext persistence, decrypted history, HAR transaction wiring, SSLKEYLOGFILE, and decrypted PCAP export are unavailable. |
| PCAP-07/08 capture and export | Raw PCAPNG is source-integrated as an explicit bounded capture written directly to a user-selected SAF document; it is not compiled/device/release verified. Redacted flow metadata JSON/NDJSON SAF export is source-integrated; it omits endpoint/DNS/package/flow identifiers and payload content. Decrypted-session export is unavailable. |
| PCAP-09 remote stream | A deliberate Sensitive Advanced receiver session is source-integrated: encrypted pairing storage, literal-IP destination, pinned P-256 receiver identity, app-held client identity, protected outbound mutual TLS, APS1/APSA attestation, ordered AES-GCM records, bounded queues/limits, active destination state, VPN ownership, automatic stops, and a runnable JDK receiver. It is not freshly compiled, device/receiver-network tested, independently security reviewed, or release verified. |
| PCAP-11 country/ASN and update operations | Signed offline attribution/import and optional user-triggered exact-HTTPS publisher-signed update transport are source-integrated. Endpoints and production signing keys are intentionally unconfigured, so no live attribution update or reputation service is available by default. |
| PCAP-12 root capture | Source-integrated already-rooted route is fixed to IPv4 TCP connection-control headers; no automatic rooting. It is unverified and does not provide payload capture or general raw traffic coverage. |
| PCAP-13 firewall and PCAP-14 threat intelligence | Source-integrated encrypted local firewall policy and publisher-signed manual imports are present. Optional user-triggered exact-HTTPS signed updates are implemented when endpoints are configured; blank endpoints intentionally provide no live update. Current protection is retained on verification/storage/network failure. |

### Explicit current unavailable gaps

The following outcomes must stay visible as gaps until independently integrated
and verified: universal/complete protocol capture, device-verified TLS traffic
decryption, decrypted-session export, reputation lookups, a configured live
threat/ASN update service, analytics transport, support-diagnostic transport,
automatic rooting, payload capture beyond the bounded likely-plaintext memory
view, reinstallability of exported base-plus-split packages, and any
device/OEM/accessibility/Play or signed-artifact evidence. PCAPdroid 2.0-derived
source integrations now include an encrypted capture library with measured
sizes, hostile-input-bounded PCAP/PCAPNG inspection, metadata-only safe HAR
export, per-app capture selection, configurable connection-log capacity,
settings import/export, and port/domain rule management. Domain enforcement is
available only when authenticated packet-bound attribution is present; otherwise
the UI keeps domain rules visibly inactive. Target-37 `ACCESS_LOCAL_NETWORK`
release/device evidence remains open.

## M-Kavach 2 parity

| Reference capability | APK Sentinel commitment | Surface | User-friendly improvement |
|---|---|---|---|
| Holistic device security status | Separate protection coverage from current risk; show check time and limitations | Play Simple | No misleading single safety score; one clear next action |
| Security misconfiguration advice | Phone Checkup with public-API verification or honest guided review | Play Simple | Prepares the user for Android Settings and verifies on return when possible |
| Potentially risky/malicious-app detection | Evidence-based findings from signing, access, structure, local threat data, and observed network context | Play Simple | Distinguishes unusual, suspicious, and confirmed evidence |
| Hidden and sideloaded app detection | Installed-app filters with install-source and visibility limitations | Play Simple | Explains why sideloading is relevant without calling every sideloaded app dangerous |
| Stale-app/update-age statistics | Last-update views, filters, and change-aware recommendations | Play Simple | Filters such as not updated in 6/12/24 months; never assumes age alone means malware |
| Authentic-app verifier | Signature continuity, installer/source evidence, official-link handoff, and optional approved transparency/reputation evidence | Play Simple + Advanced | Equivalent outcome without claiming access to M-Kavach's proprietary blockchain ledger |
| Adware scanner | SDK/indicator evidence plus observed destination context where available | Play Simple | Presence of an ad SDK is not presented as proof of harmful behaviour |
| URL scanner | Safe, non-opening URL normalization, redirect resolution, local threat-list matching, and optional reputation lookup | Play Simple | Displays the real hostname safely and keeps shortened/unresolved links unreassured |
| Fraud reporting | Guided, privacy-previewed report and official portal handoff | Play Simple | Redacts private fields, confirms the official recipient, and states that APK Sentinel did not submit anything |
| English and Hindi | Complete localized UI/content system at launch | Play Simple | Meaning-equivalent severity terms, TalkBack, large text, and mixed-script support |

## APK Analyzer parity

| Reference capability | APK Sentinel commitment | Surface | User-friendly improvement |
|---|---|---|---|
| Analyze installed and selected APK files | Installed-app Inspector plus selected package-file analyzer | Play Simple | Same evidence grammar and navigation for installed and uninstalled apps |
| App identity, version, min/target SDK, install/update dates | Identity and lifecycle report | Play Simple + Advanced | Explains why old targets or recent updates matter without automatic alarm |
| Certificates, signing data, SHA-1/SHA-256 | Signing continuity, signer detail, and file/certificate hashes | Play Simple summary + Advanced raw values | Puts identity continuity before hexadecimal detail |
| Requested/granted permissions with descriptions and protection levels | Permission explorer with requested/granted/observed distinctions | Play Simple + Advanced | Explains access in ordinary language and avoids “permission equals misuse” |
| Activities and launch actions | Component inventory; safe launch only through exported, resolvable Android intents | Play Advanced | Labels exposure and consequence; never bypasses Android access controls |
| Services, receivers, and content providers | Component inventory with exported state and intent/filter detail | Play Advanced | Groups important exposure first and hides raw noise by default |
| Hardware features | Required/optional device-feature report | Play Advanced | Explains compatibility impact |
| Decoded AndroidManifest.xml with save | Readable manifest view and system save-picker export | Play Advanced | Safe text rendering, size limits, search, and redaction preview |
| Save/share installed APK and icon | User-initiated artifact/icon export when Android access and Play policy permit | Play Advanced, policy-gated | Verifies split-package completeness and never claims reinstallability |
| Permission-to-app exploration and prevalence statistics | Permission explorer plus on-device collection statistics | Play Simple + Advanced | Search by app and package name; filters by grant state and sensitivity |
| Android/signing/component collection statistics | Local Advanced Insights | Play Advanced | Keeps collection-level technical statistics away from Home |
| Full install-source chain | Typed initiating, installing, and originating package evidence plus Android's package-source classification when the current public API exposes it | Play Simple summary + Advanced detail | Missing visibility or unsupported platform evidence stays Unknown instead of being guessed |
| Packaging, native code, and storage evidence | Bounded base/split artifact sizes, split names, native-library names/ABIs, UID/shared-UID context, and public manifest security flags | Play Advanced | Separates package-file bytes from private app data and never treats a shared UID or native library as harmful by itself |
| Browse by app attribute | On-device indexes for permission, signer fingerprint, target SDK band, install origin, category, and shared UID | Play Advanced | Searchable bounded groups answer “which apps share this fact?” without a cloud inventory |
| Optional last-used and storage context | Usage Access-gated last-used and Android-provided storage evidence, with an honest Settings handoff and Unknown fallback | Play Advanced, optional Android access | Core inspection remains useful when access is declined; the app never implies background observation without access |
| On-device factual summary | A short local evidence summary, deterministic by default and optionally model-assisted only on a capable device with a reviewed on-device provider | Play Simple | Clearly labels evidence and limitations; no network model, malware verdict, or unavailable AI capability is implied |
| No-root operation | All consumer features operate without root | Play | Root is never requested by the consumer build |

## PCAPdroid parity

| Reference capability | APK Sentinel commitment | Surface | User-friendly improvement |
|---|---|---|---|
| No-root local-VPN monitoring | On-device VpnService engine with no remote VPN server | Play Simple | Explicit one-VPN explanation, coverage state, interruption recovery, and seven-day local default |
| App/system connection log | App-first connection history with time, destination, bytes, decision, and evidence source | Play Simple | Groups repeated traffic and avoids packet noise |
| SNI, DNS, HTTP URL, and remote IP extraction | Metadata extraction when technically observable, with source/confidence labels | Play Simple + Advanced | Never infers a hostname when encryption or attribution prevents it |
| HTTP request/reply decoding | Bounded plaintext-protocol summaries | Play Advanced | Sensitive content hidden until deliberate reveal; retention and sharing warnings |
| Full payload text/hexdump | Bounded session payload inspection | Sensitive Advanced | Separate consent, storage budget, auto-delete, redaction, and lock-screen privacy |
| HTTPS/TLS decryption and SSLKEYLOGFILE | User-certificate/TLS inspection flow | Sensitive Advanced | Names breakage/credential risk, excludes sensitive apps by default, and provides exact certificate cleanup |
| PCAP export/browser download | User-initiated bounded PCAP export through Android's system save/share surfaces; implementation is not conditional on review, while public exposure is | Play Advanced; public exposure policy-reviewed | Preview scope, size, time window, and privacy fields before generation |
| PCAPNG/decrypted-session export | PCAPNG export for selected capture types | Play Advanced or Sensitive Advanced according to payload risk | Uses explicit encrypted/decrypted labeling |
| Capture library with on-disk sizes | Bounded list of user-created or explicitly opened capture documents with current size, format, creation/open time, availability, and permission state | Play Advanced | Never scans shared storage; missing/revoked documents recover without losing other history |
| Open existing PCAP/PCAPNG and decrypt supported captures | User-selected, hostile-input-bounded capture import with format/encryption detection and explicit key/certificate requirements | Play Advanced or Sensitive Advanced according to decrypted content | Preview and limitations appear before any sensitive content; unsupported encryption is never guessed |
| HAR export including binary bodies | User-initiated HTTP Archive export with standards-safe binary encoding, redaction preview, and explicit completeness limits | Sensitive Advanced | Credentials are redacted by default and binary data is encoded instead of corrupted as text |
| Live remote Wireshark/UDP streaming | Deliberate, authenticated live receiver session | Sensitive Advanced | Pairing confirmation, visible active state, network warning, automatic stop, and no silent background stream |
| Per-app capture isolation and exceptions | User-selected include/exclude app scope with package/UID evidence, shared-UID and attribution limitations, and a future-session preview | Play Advanced | Starts from one chosen app, makes exceptions reversible, and never implies perfect attribution |
| Connection filters/anomaly rules | Search/filter plus saved technical views | Play Advanced | Simple mode uses task-oriented filters; raw rule expressions stay Advanced |
| Configurable connection-log capacity | Bounded session/history capacity with plain-language storage impact and deterministic oldest-first eviction | Play Advanced | Uses safe presets rather than an unbounded numeric field and shows what will be forgotten |
| Settings export/import | Versioned user-selected settings document that excludes secrets, keys, consents, active sessions, captures, and private evidence | Play Advanced | Preview, conflict handling, and per-section selection prevent a settings file from silently weakening protections |
| Port-mapping and destination exceptions | Narrow protocol/port/domain exceptions with validation, consequence preview, confirmed-hit evidence, and immediate undo | Play Advanced | Broad or ambiguous rules are rejected; domain matching never becomes a reputation verdict |
| Domain collector destinations | Bounded destination groups derived only from observed or user-entered domains, with source and freshness labels | Play Advanced | Lets users reason about related endpoints without claiming organizational ownership |
| Offline country/ASN lookup | Signed offline attribution database | Play Advanced, simple country context where useful | Labels provider/version/date and treats hosting location as context, not guilt |
| Android 17 local-network protection | Target-SDK-aware local receiver/stream permission handling and denial/revocation recovery | Play Advanced / Sensitive Advanced | Target 36 never requests an inapplicable permission; target 37+ requires an explicit LAN rationale and safe fallback |
| Root capture while another VPN runs | Root-only capture engine that activates only when the device is already rooted and the user explicitly authorises the session | Sensitive Advanced | APK Sentinel never roots a device; root state and expanded visibility are explicit |
| App/domain/IP firewall | Reversible allow/block rules with temporary allow and breakage recovery | Play Simple + Advanced | Previews consequences, keeps undo visible, and distinguishes monitoring from enforcement |
| Malicious-connection blacklists | Signed local threat feeds with evidence, versioning, rollback protection, and dispute path | Play Simple | No silent cloud upload and no blacklist-only claim of compromise |

## APK Sentinel capabilities beyond the references

- One calm status/findings system spanning apps, APKs, phone settings, links, and network events.
- Evidence, confidence, limitation, and recommendation shown separately.
- APK-to-installed-version comparison with signer continuity and meaningful access/component changes.
- Hostile-file isolation: malformed APKs cannot crash the product shell or corrupt previous results.
- Safe hostname rendering resistant to bidirectional-text and truncation confusion.
- Privacy-first reports for ordinary users plus technical exports for experts.
- Complete local data inventory, retention controls, backup exclusions, deletion receipts, and uninstall cleanup guidance.
- Reversible decisions, verification after Android system handoffs, and recovery when blocking breaks an app.
- English/Hindi launch quality, accessibility, large-text, TalkBack, Voice Access, reduced motion, and low-end-device budgets.
- No account, ads, sale of data, mandatory cloud upload, or fear-based engagement.

## Acceptance rule

Before a signed review candidate, every row must have one of these evidence states in the release ledger:

1. implemented and covered by automated plus device tests;
2. implemented and awaiting an explicitly named external review;
3. implemented in Sensitive Advanced with feature-specific consent, containment, cleanup, and device-capability tests;
4. blocked by a documented current Android/Play constraint with a tested alternative user outcome.

Missing, silently deferred, or marketing-only parity does not satisfy this contract. Public 1.0 requires Release verified evidence for every delivered outcome. A blocked original capability is acceptable only when its tested equivalent outcome is separately Release verified and the public limitation is explicit.

The current-source labels above are not evidence states: all corresponding
release-ledger rows remain **Not assessed** with evidence **TBD** until the
required artifact, automated, device, accessibility, security, legal/policy,
and owner evidence exists.
