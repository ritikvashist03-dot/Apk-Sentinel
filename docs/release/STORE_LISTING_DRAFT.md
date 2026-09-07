# APK Sentinel Play listing draft

Status: source-aligned draft, not approved marketing copy. Current-source
review: 18 August 2026. Reconcile every sentence with the final signed
artifact, device evidence, and Play declarations before submission. No current
Gradle/device/signed-artifact/Play verification is claimed; the release ledger
remains **Not assessed / TBD**.

## Search-visible identity

- **Play title (26/30):** `APK Sentinel: App Security`
- **Short description:** `Inspect APKs, installed apps, device settings and local network evidence privately.`
- **Suggested category:** Tools
- **Primary discovery terms used naturally:** APK analyzer, APK signature, Android manifest, app permissions, installed apps, link check, local VPN, firewall rules, device security.

The brand remains **APK Sentinel** inside the app. The extended Play title explains the product to someone who has never heard the brand while keeping “APK” first.

## Full description

APK Sentinel helps you understand Android apps and APK files using evidence that is processed on your phone.

Inspect an APK before you install it:

- review package identity, SDK requirements and file hashes;
- verify APK signing schemes and certificate fingerprints;
- explore permissions, activities, services, receivers and providers;
- search and save a bounded readable AndroidManifest.xml view;
- review DEX, native-library, asset, tracker-namespace and endpoint indicators;
- compare a selected APK with an installed version where Android allows it.

Review apps already on your phone:

- search the app inventory Android makes visible;
- inspect installer, update age, permissions, components and signing evidence;
- export an app icon, base APK or available base-and-split set through Android's save picker;
- inspect bounded `.apks` and `.xapk` containers as evidence, without claiming installability;
- treat a base-plus-split export as a user-selected artifact that is not reinstall-guaranteed;
- treat sideloading, age and SDK presence as context, never automatic proof of malware.

Check more than files:

- review screen-lock, patch, debugging, storage-protection and limited root signals;
- inspect a link locally without opening it;
- optionally resolve redirects after a separate disclosure;
- open India's official cybercrime reporting portal without silently transmitting your inspection;
- start a local Android VPN session to view bounded destination metadata and apply numeric IP/CIDR rules within the built-in proxy's documented protocol limits;
- choose encrypted metadata-history retention (session only, 1 day, 7 days, or 30 days; 7 days by default), and compare installed apps against one encrypted prior snapshot rather than a 30-day inventory history.

Private by design:

- no account, ads, analytics transport, reputation transport, update transport, support-diagnostic transport or APK Sentinel cloud server;
- APK and installed-app inspection runs locally;
- no remote VPN endpoint;
- ordinary monitoring does not persist packet payloads or decrypt TLS;
- narrow protocol evidence is off by default, separately acknowledged, active-session only and in memory;
- the optional Sensitive Advanced content view is likely-plaintext only, separately acknowledged, best-effort redacted, memory-only and defaults to a five-minute maximum session;
- an optional, user-started, bounded raw PCAPNG capture writes only to a document destination the user chooses. It never starts automatically, remains visibly active with Stop available, is not previewed/decrypted/uploaded by APK Sentinel, and may contain IP addresses or plaintext/content from authorized traffic;
- a separate redacted flow-metadata JSON/NDJSON export writes only to a user-selected SAF document and omits endpoint addresses, DNS values, package/flow identifiers and payload content;
- TLS is certificate setup only; root capture is separately gated on an already-rooted device with no automatic rooting; authenticated remote streaming is a default-off Sensitive Advanced route limited to a user-paired literal-IP receiver, metadata and upstream-classified encrypted/raw records, strict limits, a visible active state, and automatic stops;
- signed threat data is imported manually, verified locally and encrypted at rest;
- exports are created only when you choose a destination;
- app-owned local data, retained document grants, network events/rules and the threat-feed key can be erased from Privacy.

APK Sentinel reports observations, limitations and recommendations. It cannot guarantee that an app, APK, link, network or device is safe, genuine, private or free from malware.

## Screenshot story

Use only screenshots captured from the final signed candidate:

1. Home — current coverage and the recommended first check.
2. APK result — identity, signature and partial-result disclosure.
3. Installed apps — search/filter and evidence detail.
4. Device protection — Good/Review/Unknown checks with observation time.
5. Link check — non-opening local result and optional redirect disclosure.
6. Network — active-state banner, limited capability report and Stop.
7. Firewall — numeric rule, enforcement wording and one-tap remove.
8. Privacy — no analytics transport, accessibility controls and erase scope.

Capture English and Hindi phone screenshots; add a tablet/large-screen set only after that layout is device-verified.

Include optional raw PCAPNG capture, redacted flow-metadata export, and authenticated receiver disclosures, active indication/counters, and Stop only when the final signed candidate has been device-verified for those flows. Do not make a public live-receiver, TLS-decryption, or reputation/update claim until the corresponding route is independently reviewed and release verified.

## Prepared graphic asset

- Play feature graphic: `docs/release/assets/play-feature-graphic-1024x500.png` (exact 1024 x 500 PNG)
- Editable/high-resolution generation source: `docs/release/assets/play-feature-graphic-source.png`

The graphic uses the selected APK Sentinel name and the product's shield/document motif. Revalidate it against the final icon, listing copy, and Play asset rules immediately before upload.

## Play reviewer notes draft

- Core purpose: device/app security analysis. Broad app visibility powers the user-facing installed-app inventory and comparison flow; inventory is processed locally and is not sold, shared for ads or sent for analytics.
- `VpnService` purpose: user-started on-device security/network tool with a local forwarding proxy and optional local numeric firewall rules. It has no remote VPN server. A separate in-app disclosure is shown immediately before Android's VPN consent. A foreground notification and global in-app Stop remain visible while active. The final review package must precisely document the tunnel boundary and encryption implementation; “local” is not itself proof of the VpnService encryption requirement.
- Optional raw PCAPNG capture: source-integrated but not release-verified. A user must deliberately start a bounded capture and choose the output document. It can contain IP addresses and plaintext/content from authorized traffic. APK Sentinel does not preview payloads, decrypt TLS, upload the capture, or start capture automatically. The active state and Stop action remain visible. The saved file is outside app storage, so Privacy erase cannot delete it.
- Flow metadata export: source-integrated but not release-verified. It is a bounded, redacted JSON/NDJSON SAF document handoff with no endpoint addresses, DNS values, package/flow identifiers or payload content.
- Notification permission is requested only in the network-session setup. Declining keeps monitoring off; APK, installed-app, link and device checks remain usable.
- Test path: finish/skip onboarding, open **Network**, accept the feature disclosure, allow notifications, then accept Android's VPN dialog. The capability report names limited and unavailable coverage. Use **Stop** in the global banner or notification.
- Capture test path: while a local VPN session is active, start the optional raw PCAPNG flow, review its scope/time/size and sensitive-content disclosure, choose a document destination, verify the active indication/counters, use **Stop**, and verify that the saved file persists outside Privacy erase. Separately verify redacted flow-metadata JSON/NDJSON export and its omitted fields.
- No login or test account is required.
- Record a <=90-second reviewer video showing app launch, the full separate VpnService disclosure, accept → Android VPN consent → active notification/Stop, decline → unaffected paths, and re-entry. Include the final `specialUse` foreground-service subtype in the App content declaration and ensure the video matches the signed build.

## Final owner inputs

- [ ] Legal publisher name and monitored support/privacy email.
- [ ] Public HTTPS privacy-policy URL; a custom domain is optional.
- [ ] Effective date, legal review, governing-law/consumer terms if applicable.
- [ ] Final content rating, target audience, countries and pricing.
- [ ] Play declarations for `QUERY_ALL_PACKAGES`, `VpnService`, foreground-service `specialUse`, Data Safety and app access, backed by the final signed artifact and reviewer video.
- [ ] Developer identity verification and `app.apksentinel.mobile` package registration with the final signing certificate.
- [ ] Final screenshots, feature graphic, support route and vulnerability-disclosure route.

See [Policy evidence snapshot — 13 August 2026](POLICY_EVIDENCE_2026-08-13.md) for the official-source baseline and unresolved policy risks. This listing draft does not establish approval.
