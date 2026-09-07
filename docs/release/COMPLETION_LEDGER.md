# APK Sentinel 1.0 Completion and Release Ledger

Status: initialized; no implementation or release claim is made by this document  
Release target: complete APK Sentinel 1.0  
Ledger baseline: 18 August 2026  
Scope authority: [Complete Product Experience and Implementation Blueprint](../../../APK_SENTINEL_PRODUCT_BLUEPRINT.md) and [Reference-App Parity Contract](../REFERENCE_APP_PARITY_MATRIX.md)

## 1. Purpose and non-negotiable scope rule

This is the single release-control ledger for the complete APK Sentinel product. It converts the approved product blueprint and reference-app parity contract into verifiable delivery records.

Every named capability belongs to the same 1.0 delivery cycle. No reference capability may be silently removed, represented only by a screen or marketing statement, deferred because a store review is pending, or enabled remotely without a tested engine and disclosure route.

Store review does not block implementation. It is still a distribution gate: if a current Android or Play constraint prevents a public artifact from exposing a completed capability, record the exact constraint, its date, the artifact exposure decision, and the tested equivalent user outcome. Never hide the limitation or make an inaccurate declaration.

This ledger separates four facts which must never be conflated:

1. The capability is implemented.
2. The capability has passed internal product, security, accessibility, and device evidence.
3. The signed AAB/APK actually contains the capability and its intended default state.
4. The current public distribution route is policy-approved.

The initial value of every state and evidence field below is a placeholder. Replace it with an evidence record; do not replace it with a verbal assertion.

## 2. How to maintain this ledger

### 2.1 Required evidence card

Create one evidence card for each completed product-area, parity, gate, or deliverable ID. The evidence card may live in the release evidence bundle, CI artifact store, issue tracker, or an approved linked record, but it must contain all of the following:

| Field | Required value |
|---|---|
| Evidence ID | Stable ID, for example E-APP-01-001. |
| Ledger IDs covered | One or more IDs from this document. |
| Build tuple | Application ID, version name, version code, variant, source revision, build timestamp, AAB/APK SHA-256, and signing-certificate SHA-256. |
| Implementation reference | Module or source location, review/merge reference, and owner. |
| Test evidence | Automated result, device/OEM result, security/privacy result, accessibility/language result, and policy/reviewer result as applicable. |
| Expected and observed outcome | Exact expected behavior, observed result, environments, devices, and test data/corpus version. |
| Data and consent evidence | Data classes involved, disclosure version, affirmative-action proof where required, retention/cleanup result, and outbound audit result. |
| Exceptions | Linked defect or explicit risk acceptance, owner, expiry/review date, and user-facing limitation. |
| Reviewer and date | Named accountable reviewer and completion date. |

Evidence must be reproducible from the recorded build tuple. Screenshots alone, a happy-path demo, a merged pull request, or a passing emulator test alone are never release evidence.

### 2.2 Allowed implementation states

| State | Meaning | Allowed next state |
|---|---|---|
| Not assessed | No implementation or verification evidence has been entered. | Planned, In progress, Blocked by current constraint, Implemented |
| Planned | Scoped with an accountable owner and acceptance route. | In progress, Blocked by current constraint |
| In progress | Work is underway; no completion claim. | Implemented, Blocked by current constraint |
| Implemented | Code exists, but required evidence is incomplete. | Internally verified, Blocked by current constraint |
| Internally verified | Required internal gates pass for the named scope. | External review pending, Release verified |
| External review pending | Implementation and internal evidence pass; a specifically named external policy, legal, or store review remains. This is not public-release approval. | Release verified, Blocked by current constraint |
| Release verified | The signed artifact, all required evidence, and its approved exposure route are verified. | Superseded, Blocked by current constraint |
| Blocked by current constraint | A dated Android/Play/legal constraint is recorded with a tested equivalent user outcome and an owner for revalidation. | Planned, In progress, Release verified |
| Superseded | Replaced by a linked record; prior evidence is retained. | None |

Forbidden states: Deferred, later, mock only, marketing only, assumed approved, and works on my device.

### 2.3 Completion rule

A row is complete only when its implementation state is Release verified and its linked evidence card proves every required gate. A Sensitive Advanced row additionally needs a verified feature-specific consent, active-state indication, containment, stop path, retention/cleanup path, and device-capability test.

An externally pending row may be part of a signed candidate for review but cannot be described as an approved public release. If a public artifact differs from the tested complete product because of a current distribution constraint, that difference must be listed in the artifact manifest and user-facing disclosure.

## 3. Gate groups used by the product and parity ledgers

| Code | Gate group | Minimum evidence |
|---|---|---|
| AUT | Automated functional and regression evidence | Deterministic CI results for the behavior, error/recovery states, and regression suite. |
| DEV | Device, OEM, Android, and network evidence | Recorded physical-device/emulator matrix with observed result, not a single-device assertion. |
| SEC | Security, privacy, abuse, data-lifecycle, and supply-chain evidence | Threat-model/data-flow review plus relevant adversarial, outbound, cleanup, and independent-review evidence. |
| A11Y | Accessibility, localization, and comprehension evidence | Manual assistive-technology results, 200% scale result, English/Hindi review, and task comprehension evidence. |
| PLAY | Android, Play, legal, and distribution evidence | Current dated policy review, declaration/listing/data-safety alignment, and clean-device reviewer rehearsal. |
| ART | Signed artifact and release-operation evidence | Artifact manifest, hashes/signing provenance, release notes, support and incident readiness. |

Every product-area row inherits the global final gates in sections 8 and 9 even where a group is not repeated in its row.

## 4. Complete product-area ledger

State and evidence are intentionally initialized as placeholders. Use the evidence-card format above when updating them.

| ID | Complete product area and required outcome | Delivery surface | Required gates | State | Evidence card |
|---|---|---|---|---|---|
| FND-01 | Native Android foundation: no-account, local-first operation, secure launch, navigation, durable local state, universal loading/empty/partial/error/recovery states, and no unfinished or hidden product route. | Play Simple | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| UX-01 | Complete screen catalogue: every blueprint screen, Android-owned handoff, and acquisition/trust surface has its required purpose, action budget, hierarchy, responsive behavior, state design, and recovery path. | Simple, Advanced, Sensitive Advanced where tagged | AUT, DEV, A11Y, PLAY, ART | Not assessed | TBD |
| ONB-01 | Onboarding and access: language choice, privacy promise, first check, contextual access primers, useful denial path, interrupted-onboarding recovery, Privacy and access hub, and verified return from Android Settings. | Play Simple | AUT, DEV, SEC, A11Y, PLAY | Not assessed | TBD |
| HOME-01 | Home, status, findings, Activity, search, filters, and history: coverage remains separate from risk; observation, interpretation, confidence, limitation, and recommendation remain distinguishable; every action verifies its result. | Play Simple plus Advanced evidence disclosure | AUT, DEV, SEC, A11Y | Not assessed | TBD |
| APP-01 | Installed-app Inspector: visibility disclosure, indexing, search/filter, identity/lifecycle, requested/granted/observed access distinctions, signing/authenticity context, hidden/sideloaded/update-age/adware context, components, change detection, and safe handoffs. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY | Not assessed | TBD |
| APK-01 | APK/package-file analysis: selected-file intake, hostile-file isolation, bounded parser, package/bundle support, identity, signing, permissions, manifest/components/libraries, hashes, comparison, partial result, safe export, cancellation, and preservation of prior results. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY | Not assessed | TBD |
| LINK-01 | Link and fraud checking: non-opening normalization, safe visual/spoken hostname rendering, redirect and local-threat evidence, clear uncertainty, optional lookup consent, official report/handoff, outgoing-data preview, and fraud-report confirmation. | Play Simple and Advanced evidence export | AUT, DEV, SEC, A11Y, PLAY | Not assessed | TBD |
| CHECK-01 | Phone Checkup: public-API/OEM feasibility matrix, status categories, nuanced root/system/certificate/patch checks, guided Android Settings handoff, verified/unchanged/unverifiable outcomes, and no false automatic claim. | Play Simple with Advanced detail | AUT, DEV, SEC, A11Y, PLAY | Not assessed | TBD |
| NET-01 | Local network monitoring: VpnService lifecycle, per-app attribution including unknown/shared cases, DNS/SNI/IP/ASN evidence when observable, overview/live/history/detail views, one-VPN and lockdown recovery, bounded local retention, foreground indication, interruption/reboot recovery, and accurate monitoring/protection wording. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| FIRE-01 | Firewall and signed threat intelligence: app/domain/IP allow/block rules, active/saved/hit-state separation, engine-confirmed enforcement, temporary allow, undo, captive-portal and broken-app recovery, rule conflicts, precision controls, signed feed update/rollback, and false-positive route. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| RPT-01 | Reports, exports, and cooperative help: human-readable redacted reports, technical reports, scope choice, privacy preview, Android save/share, format/size limits, export persistence explanation, and support-safe diagnostics. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| ADV-01 | Advanced mode: deliberate entry/exit, global and per-item disclosure, raw app/APK/network evidence, tables/search/filter, comparison, custom rules/import/export, technical diagnostics, and active Advanced behavior visible and controllable from Simple mode. | Play Advanced | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| SADV-01 | Sensitive Advanced tools: bounded PCAP/PCAPNG, payload text/hexdump, TLS/user-certificate inspection, root-device capture, and authenticated remote streaming. Each is off by default, capability-gated, separately consented, persistently indicated, bounded, stoppable, redacted, and cleaned up. | Sensitive Advanced | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| TRUST-01 | Trust, privacy, and local data control: Trust Center, data inventory, local encryption, retention/size controls, backup exclusion, clear-category/erase-all receipt, export/diagnostic control, no-account model, no ads/sale, optional lookup, and analytics off by default. | Play Simple | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| HELP-01 | Settings, Help, diagnostics, outage/offline behavior, support routes, uninstall/exit guidance, certificate-removal guidance, and recovery without guilt, dead ends, or data-loss claims. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |
| NTF-01 | Notifications and retention: monitoring/protection status, important alerts, interruptions, reminders, weekly summary, quiet hours/frequency limits, lock-screen privacy, and no fear-based engagement. | Play Simple and Advanced | AUT, DEV, SEC, A11Y, PLAY | Not assessed | TBD |
| DESIGN-01 | Premium design system: measured light/dark contrast, 48 dp targets, typography, spacing, components, status/finding/permission/advanced patterns, reduced motion, haptic/sound preferences, calm visual language, and specified performance budgets. | All surfaces | AUT, DEV, A11Y, ART | Not assessed | TBD |
| LANG-01 | English/Hindi launch quality and India-focused inclusion: complete localized UI/content, human linguistic and plain-language review, controlled glossary, mixed-script handling, 30-40% expansion, UPI/banking neutrality, low-end conditions, and large-screen/ChromeOS behavior. | All surfaces | AUT, DEV, A11Y, PLAY, ART | Not assessed | TBD |
| OPS-01 | Release operations: methodology/limitations, support knowledge base, vulnerability disclosure, security response, threat-data operations, incident playbooks/game days, staged rollout and rollback/kill-switch behavior that preserves user data/control. | Release operation | AUT, DEV, SEC, A11Y, PLAY, ART | Not assessed | TBD |

### 4.1 Source-review observation — 18 August 2026

The following is a source-only implementation observation, not an evidence card and not a state transition. No current Gradle build, lint, unit/instrumented test, emulator/device, accessibility, signing, or Play-policy result was reviewed for this observation. Therefore every row above remains **Not assessed** until its required evidence card exists. All evidence-card placeholders remain **TBD**, and owner/legal/signing/feed placeholders remain unfilled.

| Observed source area | What exists in the reviewed source | Ledger impact that is deliberately **not** claimed |
|---|---|---|
| ONB-01 / FND-01 | `SentinelShell` routes an incomplete first launch to `OnboardingScreen` and persists completion/skip. | No interrupted-flow, localization, accessibility, device, or release verification. |
| DESIGN-01 / A11Y-02 | `MainActivity` persists high-contrast and reduced-motion choices, provides them through the design system, and `PrivacyScreen` exposes the controls. `ScreenColumn` uses `SentinelResponsiveColumn`. | No measured contrast, full motion coverage, 200% scale, large-screen, TalkBack, or screenshot evidence. |
| NET-01 / NTF-01 | The shell reads current monitor status, renders a banner while the service is starting/active/stopping, and exposes a global Stop action. The network surface shows consent, runtime state, and capabilities. | No proof that monitoring/forwarding works on a device, that the active notification works, or that stop/cleanup/recovery is reliable. |
| PC-03 / PC-04 / PC-05 / NET-01 | Source contains separately acknowledged, off-by-default protocol evidence that is active-session/in-memory only, plus a separately acknowledged likely-plaintext payload view that is memory-only, best-effort redacted, and defaults to a five-minute maximum session. | No Gradle/test result, device/runtime evidence, or release verification; TLS decryption and durable payload history remain unavailable. |
| PC-07 / PC-08 / ACC-08 | Source contains a bounded raw PCAPNG writer and forwarding hooks, with deliberate user start, direct user-selected SAF document output, visible active state/counters, Stop, no automatic start, no payload preview, TLS decryption, or upload. Source also contains redacted JSON/NDJSON flow-metadata SAF export that omits endpoint/DNS/package/flow identifiers and payload content. A saved raw capture can contain IP addresses and plaintext/content and is outside app erase once written. | No Gradle/test result, end-to-end UI/Android document handoff, real forwarding/capture, limit/stop/drain result, output correctness, deletion behavior, localization/accessibility, device, policy, or signed-artifact verification. |
| CHECK-01 / MK-01 | Device posture shows coverage, observed time, limitations, per-check status, and refreshes on return to the app; it does not render a single safety score. | No public-API/OEM matrix, accessibility, language, or device-evidence claim. |
| APP-01 / APK-01 / LINK-01 / RPT-01 | Source contains installed-app and selected/installed APK inspection, bounded `.apks`/`.xapk` inspection, base-plus-split export, bounded report export, local link checks, consented redirect resolution, and an official fraud-report handoff. Installed-app continuity stores one encrypted prior snapshot; base-plus-split export is not reinstall-guaranteed. | No parser-fuzz, hostile-input, export, privacy, device, or signed-artifact claim. `.apks`/`.xapk` and split export are source-integrated but unverified. |
| FIRE-01 / PC-14 | Source contains a signed local threat-feed verifier, encrypted local persistence, expiry/rollback logic, and a manual import surface; there is no reputation/update/analytics/support transport. | No feed-publisher operation, key custody, live update, engine enforcement, false-positive route, or release verification. |

The known unimplemented or unverified parity outcomes remain mandatory. The
source-integrated but unverified outcomes are bounded `.apks`/`.xapk`
inspection, base-plus-split export, local VPN/history, protocol evidence,
likely-plaintext payload view, raw PCAPNG and redacted flow-metadata export,
certificate setup, already-rooted header capture, and pairing setup. Current
unavailable gaps are TLS traffic decryption, decrypted-session export,
reputation/update/analytics/
support transport, automatic rooting, and any release/device/Play evidence.

### 4.2 External policy research observation — 18 August 2026

[Policy evidence snapshot — 22 August 2026](POLICY_EVIDENCE_2026-08-22.md) records a current official-source review of target API, `QUERY_ALL_PACKAGES`, `VpnService`, Android 14+ foreground-service types, Data Safety, prominent disclosure, AAB/Play App Signing, and developer verification. It inspected current source configuration but did not build, install, upload, submit a declaration, or obtain a policy decision.

This is therefore **not** an evidence card or a state transition. In particular, the source’s `specialUse` foreground-service subtype, local-only VPN design, `QUERY_ALL_PACKAGES` necessity, Data Safety answers, user-directed PCAP/report transfer treatment, Play developer verification, package registration, and all reviewer assets remain **Not assessed** until the relevant signed-artifact, device, Console, and owner evidence exists.

## 5. Reference-app parity ledger

The parity rows below are mandatory capability outcomes, not permission to copy reference code, branding, wording, private services, or proprietary data. Each row must point to both its product-area evidence and a dedicated parity evidence card before it is Release verified.

### 5.1 M-Kavach 2 equivalent outcomes

| ID | Required APK Sentinel outcome | Surface | Product evidence route | State | Evidence card |
|---|---|---|---|---|---|
| MK-01 | Holistic device status with separate protection coverage, current risk, check time, limitation, and one clear next action; never a misleading safety score. | Play Simple | HOME-01 | Not assessed | TBD |
| MK-02 | Security-misconfiguration guidance through Phone Checkup, public-API verification where possible, and honest guided review where not. | Play Simple | CHECK-01 | Not assessed | TBD |
| MK-03 | Evidence-based risky/malicious-app findings using signing, access, structure, local threat data, and observed network context; distinguish unusual, suspicious, and confirmed evidence. | Play Simple | APP-01, HOME-01, FIRE-01 | Not assessed | TBD |
| MK-04 | Hidden and sideloaded-app views with install-source and visibility limitations explained neutrally. | Play Simple | APP-01 | Not assessed | TBD |
| MK-05 | Stale-app/update-age filters and change-aware recommendations without treating age alone as malware proof. | Play Simple | APP-01 | Not assessed | TBD |
| MK-06 | Authentic-app verification through signer continuity, installer/source evidence, official handoff, and approved optional transparency/reputation evidence without claiming a proprietary ledger. | Play Simple and Advanced | APP-01, APK-01, LINK-01 | Not assessed | TBD |
| MK-07 | Adware scanner with SDK/indicator evidence and observed-destination context when available; SDK presence is not proof of harm. | Play Simple | APP-01, NET-01 | Not assessed | TBD |
| MK-08 | URL scanner with safe non-opening normalization, redirects, local list matching, optional reputation lookup, and unreassured unresolved links. | Play Simple | LINK-01 | Not assessed | TBD |
| MK-09 | Guided fraud report with private-data preview/redaction, confirmed recipient, and official portal/local handoff. | Play Simple | LINK-01, RPT-01 | Not assessed | TBD |
| MK-10 | Complete English and Hindi UI/content experience, including severity, TalkBack, large text, and mixed-script behavior. | Play Simple | LANG-01, DESIGN-01 | Not assessed | TBD |

### 5.2 APK Analyzer equivalent outcomes

| ID | Required APK Sentinel outcome | Surface | Product evidence route | State | Evidence card |
|---|---|---|---|---|---|
| AA-01 | Analyze installed apps and selected package files through one coherent Inspector/analyzer evidence model. | Play Simple | APP-01, APK-01 | Not assessed | TBD |
| AA-02 | Identity and lifecycle report: package identity, version, min/target SDK, install/update dates, with plain-language context. | Play Simple and Advanced | APP-01, APK-01 | Not assessed | TBD |
| AA-03 | Signing continuity, signer detail, file/certificate hashes, with Simple summary and selectable Advanced raw values. | Play Simple and Advanced | APP-01, APK-01, ADV-01 | Not assessed | TBD |
| AA-04 | Permission explorer showing requested/granted/observed distinctions, descriptions, protection levels, sensitivity, and non-alarmist explanation. | Play Simple and Advanced | APP-01, HOME-01 | Not assessed | TBD |
| AA-05 | Activity and launch-action inventory; launch only through exported, resolvable Android intents without bypassing access controls. | Play Advanced | APP-01, APK-01, ADV-01 | Not assessed | TBD |
| AA-06 | Service, receiver, and content-provider inventory with exported state, intent/filter detail, and meaningful exposure grouping. | Play Advanced | APP-01, APK-01, ADV-01 | Not assessed | TBD |
| AA-07 | Required/optional hardware-feature report with compatibility explanation. | Play Advanced | APK-01, ADV-01 | Not assessed | TBD |
| AA-08 | Readable decoded AndroidManifest view with safe rendering, search, size limits, redaction preview, and system save-picker export. | Play Advanced | APK-01, ADV-01, RPT-01 | Not assessed | TBD |
| AA-09 | User-initiated APK/icon export only where Android access and current policy permit; verify split-package completeness and never claim reinstallability. | Play Advanced, policy-gated | APP-01, APK-01, RPT-01 | Not assessed | TBD |
| AA-10 | Permission-to-app exploration and on-device prevalence/collection statistics with search, package filtering, grant-state, and sensitivity filters. | Play Simple and Advanced | APP-01, ADV-01 | Not assessed | TBD |
| AA-11 | Local Advanced Insights for Android/signing/component collection statistics, kept out of ordinary Home. | Play Advanced | APP-01, ADV-01 | Not assessed | TBD |
| AA-12 | Consumer inspection works without root; no consumer feature asks to root the device. | Play Simple and Advanced | FND-01, APP-01, APK-01 | Not assessed | TBD |
| AA-13 | Full typed install-source chain: initiating, installing, and originating package plus Android package-source classification when exposed; unavailable evidence remains Unknown. | Play Simple and Advanced | APP-01, ADV-01 | Not assessed | TBD |
| AA-14 | Bounded packaging evidence: base/split artifact bytes, native libraries/ABIs, UID/shared-UID context, and public manifest security flags, explicitly distinct from private app-data size and harmfulness. | Play Advanced | APP-01, APK-01, ADV-01 | Not assessed | TBD |
| AA-15 | Bounded searchable browse-by-attribute indexes for permission, signer fingerprint, target SDK band, install origin, category, and shared UID. | Play Advanced | APP-01, ADV-01 | Not assessed | TBD |
| AA-16 | Optional Usage Access-gated last-used/storage context with Android Settings handoff, verified return where possible, denial recovery, and Unknown fallback without reducing core inspection. | Play Advanced, optional Android access | APP-01, ONB-01, ADV-01 | Not assessed | TBD |
| AA-17 | Short on-device factual summary whose statements map to collected evidence and limitations; deterministic local behavior is the baseline and no cloud/AI/malware claim is implied. | Play Simple | APP-01, HOME-01 | Not assessed | TBD |

### 5.3 PCAPdroid equivalent outcomes

| ID | Required APK Sentinel outcome | Surface | Product evidence route | State | Evidence card |
|---|---|---|---|---|---|
| PC-01 | No-root local-VPN monitoring with no remote VPN server, one-VPN explanation, coverage state, interruption recovery, and seven-day local default retention. | Play Simple | NET-01, TRUST-01 | Not assessed | TBD |
| PC-02 | App/system connection history with app, time, destination, bytes, decision, evidence source, grouping, and understandable noise reduction. | Play Simple | NET-01, HOME-01 | Not assessed | TBD |
| PC-03 | DNS, SNI, HTTP URL, remote IP, and ASN extraction only when observable, with source/confidence labels and no invented hostname. | Play Simple and Advanced | NET-01, ADV-01 | Not assessed | TBD |
| PC-04 | Bounded plaintext-protocol request/reply summaries with deliberate sensitive-content reveal and retention/share warnings. | Play Advanced | NET-01, ADV-01, SADV-01 | Not assessed | TBD |
| PC-05 | Bounded full payload text/hexdump inspection with separate consent, storage budget, auto-delete, redaction, and lock-screen privacy. | Sensitive Advanced | SADV-01, TRUST-01 | Not assessed | TBD |
| PC-06 | TLS/user-certificate inspection including selected-app scope, high-sensitivity-app exclusion by default, credential/breakage warning, persistent indication, and verified certificate cleanup. | Sensitive Advanced | SADV-01, TRUST-01, HELP-01 | Not assessed | TBD |
| PC-07 | User-initiated bounded PCAP export using Android save/share, with scope, time, size, and privacy preview before generation. Implementation is not conditional on review; public exposure is. | Play Advanced; public exposure policy-reviewed | SADV-01, RPT-01 | Not assessed | TBD |
| PC-08 | PCAPNG export for selected capture types, explicitly labelled encrypted/decrypted according to payload risk. | Play Advanced or Sensitive Advanced by capture type | SADV-01, RPT-01 | Not assessed | TBD |
| PC-09 | Deliberate authenticated remote Wireshark/UDP receiver session with pairing confirmation, visible destination/active state, network warning, automatic stop, and no silent background stream. | Sensitive Advanced | SADV-01, NET-01 | Not assessed | TBD |
| PC-10 | Connection filters, anomaly rules, and saved technical views; raw expressions remain Advanced while Simple uses task-oriented filters. | Play Advanced | NET-01, FIRE-01, ADV-01 | Not assessed | TBD |
| PC-11 | Signed offline country/ASN attribution database with provider/version/date labels and no implication that hosting location proves harm. | Play Advanced with simple country context where useful | NET-01, TRUST-01 | Not assessed | TBD |
| PC-12 | Root-only capture engine that can activate only on an already-rooted device after explicit authorization; APK Sentinel never roots a device. | Sensitive Advanced | SADV-01 | Not assessed | TBD |
| PC-13 | Reversible app/domain/IP firewall with temporary allow, visible undo, breakage recovery, and a clear distinction between monitoring and enforcement. | Play Simple and Advanced | FIRE-01, NET-01 | Not assessed | TBD |
| PC-14 | Malicious-connection matching from signed local threat feeds with evidence, versioning, rollback protection, and dispute path; no silent cloud upload or blacklist-only compromise claim. | Play Simple | FIRE-01, TRUST-01 | Not assessed | TBD |

## 6. Feature-specific access, consent, and active-state ledger

General Terms and Conditions may explain authorized use, but they never substitute for a feature-specific disclosure and affirmative action where a capability exposes sensitive data or changes network behavior.

| ID | Capability/data | Trigger and authorization required | Required proof before Release verified | Decline, withdrawal, or stop route | State | Evidence card |
|---|---|---|---|---|---|---|
| ACC-01 | Broad installed-app visibility | User starts an installed-app check; in-app prominent disclosure, not a fake runtime prompt. | Exact inventory scope/purpose, local processing, controls to stop use/delete inventory, listing/declaration alignment, no inventory outbound. | APK/file/checkup paths remain useful; coverage shows Limited; in-app stop/delete control. | Not assessed | TBD |
| ACC-02 | Selected file access | User chooses Check APK, save, or open report through Android picker. | Only user-selected scope is read; cancellation preserves previous state; expiry/change-while-read path is safe. | Return to prior screen with no-file-selected state. | Not assessed | TBD |
| ACC-03 | VpnService monitoring/protection | User taps Start monitoring or protection after a separate prominent local-VPN disclosure, then accepts Android's authoritative consent surface. | Recorded disclosure version/time, app/destination/time/bytes scope, local processing/seven-day default, one-VPN statement, no traffic/history upload, foreground indication, reviewer rehearsal. | Not now leaves internet unchanged; Stop/pause works; another-VPN path explains conflict and preserves current VPN. | Not assessed | TBD |
| ACC-04 | Notifications | After monitoring value is clear or immediately before important alerts, never at first launch. | Exact channel purpose, lock-screen minimization, denial path, frequency/quiet-hour controls, and no feature coercion. | In-app findings remain; neutral status/settings route. | Not assessed | TBD |
| ACC-05 | Usage access | User explicitly enables recent-use context. | Exact scope/value, Android handoff, last-use purpose, and no dependence for core inspection. | Hide usage context; all core checks continue. | Not assessed | TBD |
| ACC-06 | Battery optimization exception | Only after observed monitoring interruption or an explicit user reliability request. | OEM/Android route, measured reliability/battery tradeoff, and alternative help route. | Continue with a reliability note and OEM help. | Not assessed | TBD |
| ACC-07 | Optional online reputation lookup | First user-initiated lookup or explicit Privacy settings enablement. | Exact domain/hash indicator, provider/purpose, data-minimization and contract review, disclosure, affirmative consent, outbound audit, and withdrawal test. | Local result remains and says online reputation was not checked. | Not assessed | TBD |
| ACC-08 | User-initiated capture/export | User starts a bounded PCAP/PCAPNG/raw capture or export. | Scope/time/size/privacy preview, persistent active state, storage cap, auto-delete, redaction, save/share proof, and policy exposure decision. | Cancel before capture/export; Stop immediately; delete capture with receipt. | Not assessed | TBD |
| ACC-09 | Plaintext payload reveal | User deliberately enables a specific Sensitive Advanced payload session or reveal. | Content sensitivity warning, selected scope, separate affirmative action, persistent indication, bounded retention, lock-screen privacy, redaction, and cleanup. | Metadata monitoring continues; immediate stop/delete remains visible. | Not assessed | TBD |
| ACC-10 | TLS/user certificate inspection | User enables selected Sensitive Advanced inspection and follows certificate setup. | Certificate scope, compatibility/credential warning, high-sensitivity default exclusions, active indication, removal verification, uninstall cleanup guidance, and no credential-capture claim. | Metadata monitoring continues; disable/remove certificate with verified result. | Not assessed | TBD |
| ACC-11 | Root-device capture | Already-rooted environment is detected and user explicitly authorizes a bounded session. | Technical proof that no root attempt occurs, root boundary/isolation, session indication, stop/delete, and abuse review. | Remain no-root; all ordinary consumer features continue. | Not assessed | TBD |
| ACC-12 | Remote live streaming | User pairs an authenticated destination and confirms the visible receiver/session scope. | Destination binding, authentication, visible session state, network warning, automatic-stop/interruption behavior, no silent background continuation, and privacy review. | Cancel pairing; immediate stop; no remote stream starts. | Not assessed | TBD |
| ACC-13 | Fraud report/diagnostic/report sharing | User explicitly chooses a recipient/save/share action. | Field-level privacy preview/redaction, recipient confirmation, successful/cancelled handoff result, and exported-file persistence explanation. | Cancel preserves local draft; nothing leaves device. | Not assessed | TBD |
| ACC-14 | Optional product analytics | Explicit, separate, off-by-default consent. | Published event dictionary, prohibited sensitive fields, outbound audit, bounded aggregate, withdrawal/deletion proof, and no third-party replay/ads SDK. | Keep off without repeat prompting; turning off deletes unsent aggregates. | Not assessed | TBD |
| ACC-15 | Erase all local data | User confirms a destructive local-data erase. | Stop monitoring/schedules first, destroy keys/data, deletion receipt, remaining exported/certificate/system-record explanation, and reset proof. | Cancel leaves data unchanged; per-category deletion available where supported. | Not assessed | TBD |

## 7. Data retention and cleanup verification ledger

These are product defaults to verify in the signed artifact, not claims that data is safe merely because it is local.

| Data class | Default handling and retention | Release proof required |
|---|---|---|
| Installed-app inventory and current findings | Encrypted local app storage; current snapshot and up to 30-day change history unless shortened. | Outbound audit, storage-size accuracy, retention expiry, inventory-delete control, backup exclusion, erase/uninstall result. |
| Connection metadata | Encrypted local storage; seven days by default. | VPN disclosure alignment, no traffic/history outbound, retention/size cap, clear-category, backup exclusion, and stopped-service cleanup. |
| Aggregate app/network totals | Local; 30 days by default. | Retention and aggregate accuracy test; no hidden export/upload. |
| Raw packet capture | Off; explicit bounded Advanced session; 24 hours unless deliberately saved. | Scope/size/time caps, active indication, auto-delete, save/share privacy preview, exported-file explanation, backup exclusion. |
| Decrypted/plaintext payload | Off; separately scoped Sensitive Advanced session; session or 24-hour maximum unless deliberately saved. | Consent, active indication, lock-screen privacy, redaction, auto-delete, delete receipt, and no accidental analytics/support capture. |
| Firewall rules and accepted findings | Local until deleted or expired. | Rule persistence/recovery, clear/erase, app-broke recovery, and no cloud synchronization. |
| Signed threat intelligence | Generic signed database replaced after verified update. | Signature/version/freshness checks, atomic activation, rollback protection, last-known-good, key rotation/revocation, and deletion behavior. |
| Optional reputation request | Minimal disclosed indicator only; no server history by default. | Provider/data contract, consent versioning, observed outbound field audit, withdrawal, and local-only fallback. |
| Reports | Locally generated; drafts for 24 hours and saved files under user control. | Scope/redaction preview, draft expiry, save/share confirmation, export persistence notice, and erase behavior. |
| Diagnostics | Generated on request; previewed/redacted; deleted after cancelled/completed handoff. | Redaction, recipient confirmation, outbound audit, cancellation cleanup, and support-log leakage test. |
| Product analytics | Off by default; short, aggregated retention only when separately enabled. | Event-dictionary review, forbidden-field tests, outbound audit, withdrawal/deletion, and no functionality loss when off. |

## 8. Release-gate ledger

Each gate must have an evidence card and a named decision owner. A failure blocks the affected capability from activation and blocks public 1.0 when it meets a no-public-release condition in section 10.

### 8.1 Automated and build gates

| ID | Gate | Minimum evidence and pass condition | State | Evidence card |
|---|---|---|---|---|
| AUT-01 | Reproducible release build | Clean, repeatable release build produces the recorded variant and artifact hashes; compile, lint/static checks, unit, integration, and instrumented suites pass. | Not assessed | TBD |
| AUT-02 | Product-state regression | Automated coverage proves primary actions plus uninitialized, loading, background, success, empty, partial, offline, stale, denied, error, process-death, and recovery states without duplicate action. | Not assessed | TBD |
| AUT-03 | App/APK/link hostile-input regression | Mutation/coverage-guided fuzzing and corpus tests cover malformed archives, zip bombs, split/encrypted packages, signatures, manifests/resources, hostile URLs, QR payloads, bidi/punycode, redirects, and cancellation. No parser result may crash the shell or corrupt prior data. | Not assessed | TBD |
| AUT-04 | Network/firewall engine regression | Deterministic tests cover start/pause/stop/reboot, attribution confidence, DNS/SNI/IP limits, rule save/active/hit state, enforcement confirmation, conflicts, undo, emergency release, and no monitoring/protection wording mismatch. | Not assessed | TBD |
| AUT-05 | Threat-data supply-chain regression | Tests reject expired, future-dated, corrupt, partial, replayed, rolled-back, or invalidly signed feeds; prove atomic activation, key rotation/revocation, and last-known-good behavior. | Not assessed | TBD |
| AUT-06 | Data lifecycle and consent regression | Tests prove retention expiry, category clear, erase-all, backup exclusion, restore behavior, consent versioning/withdrawal, redacted share previews, and no sensitive data in analytics by default. | Not assessed | TBD |
| AUT-07 | Sensitive Advanced regression | Tests prove disabled defaults, selected scope, active indication, time/size caps, stop/auto-delete, certificate cleanup route, root precondition/no-root attempt, stream pairing/authentication/destination binding/automatic stop, and technical export labels. | Not assessed | TBD |
| AUT-08 | Performance and stability regression | Recorded budgets cover cold/warm launch, first content/result, indexing, live-list stability, retention/database growth, capture caps, crash/ANR thresholds, and graceful low-memory/storage degradation. | Not assessed | TBD |
| AUT-09 | Build/dependency security | Dependency policy, SBOM generation, vulnerability/static analysis, secret scan, license review, reproducible dependency lock, and release-signing/provenance checks pass or have explicit dated risk acceptance. | Not assessed | TBD |

### 8.2 Device, OEM, Android, and network gates

| ID | Gate | Minimum evidence and pass condition | State | Evidence card |
|---|---|---|---|---|
| DEV-01 | Android/OEM matrix | Supported minimum through latest public Android plus current preview compatibility is tested on representative Samsung, Xiaomi/Redmi/Poco, Vivo/iQOO, Oppo/Realme, OnePlus, Motorola, and Pixel devices, based on the current supported-market baseline. | Not assessed | TBD |
| DEV-02 | Device-condition resilience | Physical-device evidence covers 2/3 GB RAM and current devices, low/exhausted storage, small/large phone, tablet/foldable/ChromeOS, managed/work profile, multiple users where available, permission revocation, process kill, reboot, update/migration, clock/timezone/language/theme change, battery/Data Saver, and background restriction. | Not assessed | TBD |
| DEV-03 | Network matrix | Evidence covers Wi-Fi, mobile, dual SIM, roaming/handoff, airplane/intermittent/metered networks, IPv4/IPv6, DNS/Private DNS, QUIC/HTTP3, TLS, captive portal, another/always-on/lockdown/work VPN, high throughput, shared UID, app update during monitoring, and foreground-service/OEM interruption. | Not assessed | TBD |
| DEV-04 | Firewall recovery matrix | Banking, UPI, authentication, messaging, Play/update, captive portal, common CDN, rule conflicts, changing DNS/IP, existing connections, engine stop with rules active, and emergency unblock are tested. Users must recover a legitimate blocked app within two minutes at the approved success threshold. | Not assessed | TBD |
| DEV-05 | Long-running reliability | 24-72-hour soak demonstrates acceptable battery, memory, storage, heat, connection coverage, interruption recovery, and notification behavior on the target matrix. | Not assessed | TBD |
| DEV-06 | Sensitive capability environments | PCAP/PCAPNG, payload, TLS/certificate, root-capable already-rooted device, and authenticated receiver scenarios are exercised on physical devices; each unsupported device condition is accurately surfaced and safely unavailable. | Not assessed | TBD |

### 8.3 Security, privacy, abuse, and operational-security gates

| ID | Gate | Minimum evidence and pass condition | State | Evidence card |
|---|---|---|---|---|
| SEC-01 | Current threat model and data-flow diff | Every capability has a current threat model and data-flow diagram covering parsers, VPN engine, firewall, feeds, reports, diagnostics, updates, Advanced tools, and external destinations. Material changes have a reviewed diff. | Not assessed | TBD |
| SEC-02 | Independent security assessment | Independent penetration test and mobile application security assessment cover local storage/keys, parser/proxy/decoder, VPN/firewall bypass/loops, intents/deep links/exported components, FileProvider/share, dependencies, build/update supply chain, and remediation. | Not assessed | TBD |
| SEC-03 | Privacy outbound and leakage audit | Observed outbound domains/fields are compared with Trust Center, Data Safety, disclosures, and optional-feature states. Logs, crash reports, notifications, screenshots/recents, diagnostics, analytics, and support flows contain no prohibited sensitive data. | Not assessed | TBD |
| SEC-04 | Data deletion, certificate, and uninstall proof | Clear-category, erase-all, backup/restore, exported-file scope, certificate installation/removal, certificate cleanup, stopped services, and uninstall guidance have device evidence and receipt accuracy. | Not assessed | TBD |
| SEC-05 | Advanced abuse containment | Review proves no stealth capture, unauthorized third-party interception, credential capture, remote stream without pairing, root escalation, or surveillance-oriented configuration path. Persistent indicators, scope, stop, and cleanup controls are verified. | Not assessed | TBD |
| SEC-06 | Finding and alert integrity | Severity/confidence/limitation rules, false-positive route, critical/interruptive precision threshold, evidence freshness, rule-engine confirmation, and no absolute-safety claim are verified. | Not assessed | TBD |
| SEC-07 | Incident readiness | Vulnerability disclosure, patch-response, compromised-feed, false-positive rollback, security incident, and emergency-unblock game-day outcomes are documented and acceptable. | Not assessed | TBD |

### 8.4 Accessibility, language, product comprehension, and visual-quality gates

| ID | Gate | Minimum evidence and pass condition | State | Evidence card |
|---|---|---|---|---|
| A11Y-01 | Manual assistive-technology core flow | All critical journeys pass TalkBack with screen off/no sight, Voice Access, Switch Access, keyboard/ChromeOS, magnification, and stable live-activity focus without a blocker. Automated scanner output is triage only. | Not assessed | TBD |
| A11Y-02 | Scale, contrast, motion, and non-color state | At least 200% font/display retains all actions/evidence; light/dark/high-contrast/monochrome and color-vision checks pass; reduced motion and haptic/sound-off preferences work; no gesture-only critical action remains. | Not assessed | TBD |
| A11Y-03 | Advanced technical accessibility | Tables, technical strings, manifests, packet/payload views, chart alternatives, selection/copy, focus order, large screen, and ChromeOS keyboard use work without hiding information from assistive technologies. | Not assessed | TBD |
| A11Y-04 | English/Hindi quality | A security-aware reviewer and a plain-language reviewer approve English and Hindi content; high-impact copy is back-translated; severity, permissions, destructive actions, dates, units, pluralization, mixed scripts, and long pseudo-localized strings remain correct. | Not assessed | TBD |
| A11Y-05 | Comprehension and usability | Novices and enthusiasts complete the critical task set: explain status/coverage, check an app/APK/link, understand VPN consent, recover a broken rule, verify Settings handoff, create a redacted report, erase data, and enter/leave Advanced. Record success, mental model, help, time, confidence, and emotional change. | Not assessed | TBD |
| A11Y-06 | Calm, coherent visual system | Design QA proves contrast/touch-target rules, risk/coverage separation, no fear-based copy/animation, coherent simple-to-Advanced progression, and the blueprint performance targets on the reference device. | Not assessed | TBD |

### 8.5 Android, Play, legal, and reviewer gates

| ID | Gate | Minimum evidence and pass condition | State | Evidence card |
|---|---|---|---|---|
| PLAY-01 | Current policy/API revalidation | At architecture freeze and before every submission, record dated official reviews of target/compile API; exact signed manifest permissions/services; Android/Play foreground-service type and declaration; VpnService eligibility, disclosure, consent, tunnel-boundary/encryption evidence and reviewer video; broad package visibility necessity/declaration; sensitive APIs; capture/rule-update treatment; Data Safety data-flow mapping; developer verification/package registration; and applicable Indian privacy obligations. The 22 August 2026 research snapshot is a starting reference only, not pass evidence. | Not assessed | TBD |
| PLAY-02 | Artifact-to-declaration alignment | Inspect the signed AAB/APK manifest and runtime behavior against every declared permission/API. Listing, Play Console declarations, Data Safety, privacy policy, Trust Center, and feature disclosures are mutually consistent. | Not assessed | TBD |
| PLAY-03 | Prominent disclosure and affirmative consent | Clean-device proof confirms separate VpnService disclosure/affirmative action, feature-specific Sensitive Advanced consent, optional lookup/analytics consent, clear decline paths, consent-version renewal, and no substitution of Terms acceptance for sensitive authorization. | Not assessed | TBD |
| PLAY-04 | Reviewer rehearsal | On a clean device, rehearse install/first launch, app visibility purpose, VPN accept/decline/local behavior, foreground notification, data deletion/retention, Advanced capture indicator/stop, every declared permission/API, and absence of hidden/remote behavior. Maintain current reviewer instructions and a behavior-accurate VPN/disclosure video when required. | Not assessed | TBD |
| PLAY-05 | Claims, audience, identity, and branding | Verify adult 18+ positioning, non-child-directed marketing, supported security claims, developer identity, final application ID, name/trademark/domain/package/store clearance, and no copied reference branding/content. | Not assessed | TBD |
| PLAY-06 | Distribution exposure decision | For every Sensitive Advanced and policy-gated feature, record whether it is in the signed public artifact, its default state, device requirements, consent route, reviewer instructions, and any documented current constraint with tested alternative. | Not assessed | TBD |

## 9. Final AAB/APK and release-package deliverables

The production AAB and signed test APK are separate deliverables. The test APK cannot be used to conceal a capability absent from the submitted AAB. Any intentional difference in application ID, signing, feature split, default state, or capability exposure must be named and approved in the artifact manifest.

| ID | Deliverable | Required content or proof | State | Evidence card |
|---|---|---|---|---|
| ART-01 | Immutable production AAB | Release-signed AAB with final application ID, version name/code, target/min API, capability inventory, permission/API inventory, disclosure versions, default-state inventory, SHA-256, signing/provenance record, and reproducible-build result. | Not assessed | TBD |
| ART-02 | Signed device-test APK | Installable release-equivalent APK for device/reviewer testing with SHA-256, signing/provenance record, capability/default-state manifest, and explicit delta from production AAB if any. | Not assessed | TBD |
| ART-03 | Device-installed artifact proof | Evidence that the relevant outputs actually install and execute on the device/OEM matrix, including clean install, upgrade, restore/migration, permission denial, uninstall, and no stale test configuration. | Not assessed | TBD |
| ART-04 | Symbol, mapping, and debug-recovery package | Retain mapping files, native symbols where applicable, dependency lock/SBOM, build logs, crash-symbolication route, and signing-key custody/runbook in the approved secure release store. | Not assessed | TBD |
| ART-05 | Product capability and parity manifest | Build-specific matrix mapping every FND through OPS, MK, AA, and PC capability ID to artifact presence, surface, default state, consent route, device requirements, retention, and evidence card. | Not assessed | TBD |
| ART-06 | Test and quality evidence bundle | Immutable CI summaries, device/OEM/network matrix, fuzz/corpus versions, performance/soak results, privacy-outbound audit, accessibility/language records, usability study, defects, exceptions, and final sign-offs. | Not assessed | TBD |
| ART-07 | Security and privacy release package | Current threat model/data-flow, pen-test and remediation record, SBOM/dependency review, data-retention/deletion evidence, certificate cleanup proof, vulnerability-disclosure process, and incident playbooks. | Not assessed | TBD |
| ART-08 | Play/reviewer submission package | Store listing, screenshots/video, Data Safety, privacy policy, permissions and VpnService declarations, broad-visibility justification, foreground-service information, reviewer instructions/credentials if needed, clean-device rehearsal result, and dated policy memo. | Not assessed | TBD |
| ART-09 | User-facing trust and support package | Trust Center content, methodology/limitations, release notes, English/Hindi Help and support articles, diagnostics rules, uninstall/exit guidance, known limitations, and support escalation paths. | Not assessed | TBD |
| ART-10 | Rollout, rollback, and response plan | Internal/closed/open/public rollout criteria, monitoring without sensitive telemetry, halt/rollback decision owners, policy capability-control decision, emergency feed/rule response, and user-data/control preservation proof. | Not assessed | TBD |

## 10. Final release decision

### 10.1 No-public-1.0 blockers

Do not mark the public 1.0 release as ready while any of the following is true:

- A critical or high security issue remains unresolved.
- A critical accessibility issue remains unresolved.
- The artifact makes an absolute-safety, unsupported malware, or otherwise misleading claim.
- Sensitive outbound data is not accurately disclosed and affirmatively consented where required.
- Firewall/rule UI claims enforcement without engine confirmation.
- Capture, storage, battery, or live-stream behavior is unbounded or cannot be stopped.
- A parser/decoder crash can escape containment or corrupt prior data.
- App-private data cannot be erased through the documented control.
- A VPN conflict, monitoring gap, or protection interruption is unexplained.
- Play declaration, listing, Data Safety, policy, or runtime behavior does not match the signed artifact.
- Critical/interruptive alert precision is below the approved threshold.
- A user certificate remains after TLS inspection or cannot be removed/verified.
- Root capture can attempt to root a device or start without an already-rooted environment and explicit authorization.
- Remote streaming can begin without authenticated destination pairing and a visible active session.
- A mandatory parity row lacks an allowed evidence state and tested outcome.

### 10.2 Final sign-off record

Complete a signed review-candidate record only after every required row is Release verified or has a dated Blocked by current constraint entry with a tested equivalent outcome and truthful exposure decision. Public 1.0 sign-off additionally requires each blocked original outcome to map to a separately tested, truthful equivalent outcome whose row is Release verified; a blocked entry alone is never product completion.

| Decision field | Required entry |
|---|---|
| Release candidate | Version name/code, source revision, AAB SHA-256, APK SHA-256, signing certificate SHA-256. |
| Capability completeness | Link to ART-05 showing every product-area and mandatory parity row. |
| Internal gate result | Links to AUT, DEV, SEC, A11Y, PLAY, and ART evidence cards. |
| External review state | Named authority/process, submission/reference, decision date, and any condition. |
| Known limitations | User-visible wording, affected devices/surfaces, workaround, owner, and review date. |
| Risk acceptance | Only explicit, dated, named acceptance with mitigation and expiry; never Terms-and-Conditions-only mitigation. |
| Go/no-go decision | Go, submit for external review, hold, or block; accountable product, security, privacy/policy, accessibility, and release owners. |
| Post-release watch | Rollout cohort, halt thresholds, support/on-call owners, vulnerability/feed response, and revalidation date. |

## 11. Source traceability

This ledger is derived from the product source of truth, especially the complete-product delivery decision, feature contracts, privacy/access model, Advanced and Sensitive Advanced requirements, release scope, implementation roadmap, testing strategy, risk register, acceptance checklist, and release gates in the [Blueprint](../../../APK_SENTINEL_PRODUCT_BLUEPRINT.md).

Current external-policy research is linked separately in [Policy evidence snapshot — 13 August 2026](POLICY_EVIDENCE_2026-08-13.md). Its official links must be refreshed again on the real submission date.

The mandatory MK, AA, and PC rows map one-to-one to the [Reference-App Parity Contract](../REFERENCE_APP_PARITY_MATRIX.md). When either source changes, update the affected ledger IDs and evidence requirements in the same change; do not leave a source capability untracked.
