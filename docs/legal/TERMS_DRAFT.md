# APK Sentinel Terms of Use - release draft

Effective date: `[publisher to complete]`  
Publisher/legal entity: `[publisher to complete]`  
Support contact: `[publisher to complete]`

This is a product-complete draft for legal review, not legal approval. Replace every bracketed field and obtain jurisdiction-specific review before publishing.

## 1. Product purpose

APK Sentinel is an Android security and privacy utility that can inspect user-selected APK/package files, review installed-app and device-security signals, inspect links, monitor and filter local network activity through Android's VPN interface, generate reports/technical exports, and provide separately gated advanced diagnostic tools. It is intended for devices, apps, files, accounts, networks, and traffic that the user owns or is explicitly authorized to test.

APK Sentinel provides evidence and guidance, not a guarantee that any app, link, device, or connection is safe, malicious, authentic, private, or legally compliant. A warning can be incomplete or wrong, and no warning can result from visibility, encryption, platform, data-freshness, or technical limits.

## 2. Included capabilities

Depending on Android/device capability, build exposure, and the user's choices, the product may include:

- device posture and settings guidance;
- installed-app inventory, installer/update/signing/permission/component evidence and local collection statistics;
- static analysis of selected APK/ZIP files, including hashes, manifest, signing certificates, SDKs, permissions, components, DEX/native/assets, embedded indicator heuristics, comparison, and reports;
- safe non-opening URL normalization, local threat matching, optional disclosed reputation lookup, and fraud-report handoff;
- user-started no-root local-VPN connection metadata, DNS/SNI/HTTP evidence when observable, filtering, firewall rules, local threat-feed matching, retention, reports, and country/ASN context;
- an optional, user-initiated bounded raw PCAPNG capture that writes only to a document destination selected by the user. It is not automatic, remains visibly active and stoppable, can contain IP addresses or plaintext/content, and APK Sentinel does not preview captured payloads, decrypt TLS, or upload the capture;
- separately gated plaintext/payload, TLS/user-certificate inspection, already-rooted-device capture, and authenticated live receiver tools when available; and
- local export/share, diagnostics, deletion, privacy, language, accessibility, and recovery controls.

Feature presence in these Terms does not enable it, grant Android authority, prove device support, or replace an in-product disclosure. Sensitive capability code remains disabled until its exact preconditions and approvals are satisfied.

## 3. User authorization and prohibited use

The user must have authority for every inspected file/app/device/network/packet and every destination or receiver. The user must not use APK Sentinel to covertly monitor another person, steal credentials or private data, bypass access controls, distribute malware, disrupt a network, violate intellectual-property rights, or perform unlawful surveillance/testing.

APK Sentinel does not root a device, bypass Android access control, silently install a certificate, silently start a VPN, or guarantee access to hidden/system/work-profile data. Root capture can operate only on an already-rooted device after a specific bounded authorization.

## 4. Consent and Android controls

Accepting these Terms is not consent to collect traffic, reveal payload, inspect TLS, use root, stream remotely, contact a reputation provider, send diagnostics, or enable analytics. Each capability that exposes sensitive data or changes network behavior requires its own prominent purpose/scope/retention disclosure and affirmative action. Android-owned consent/permission surfaces remain authoritative and can be declined or revoked.

An active sensitive session must remain visible and stoppable. The user is responsible for reviewing destination, app scope, duration, size, exclusions, retention, and export fields before starting or sharing.

## 5. Local VPN and connectivity

APK Sentinel's no-root monitor uses Android `VpnService` locally and is not a remote anonymity VPN. Android normally allows one active VPN per user/profile, so starting it can replace or conflict with another VPN or lockdown configuration. Monitoring, filtering, Private DNS, captive portals, calls, and some apps can break. APK Sentinel must expose actual starting/active/failed state and an immediate stop/emergency-release route; a requested block is not claimed as enforced until the engine confirms it.

## 6. Sensitive Advanced tools

Raw packets and decrypted/plaintext payloads can contain credentials, messages, health/financial information, identifiers, or other people's data. A raw PCAPNG capture is written only after the user chooses a destination; after it is saved outside app storage, in-app erase cannot delete it. TLS inspection can weaken expected certificate trust, break apps, and expose secrets. Root capture expands device access. Live streaming sends selected capture data to a paired receiver. These tools are disabled by default, scoped, time/size bounded, separately disclosed, visibly active, and subject to cleanup. High-sensitivity apps are excluded by default where technically enforceable.

The user must remove/verify any inspection certificate, stop receiver/root sessions, and securely manage saved/exported files. APK Sentinel must provide the cleanup route but cannot delete copies outside app-controlled storage.

## 7. Threat data, reputation, and reports

Threat-feed, tracker, ad-SDK, hosting-country, ASN, age, permission, signer, or heuristic evidence is context—not proof of wrongdoing. Generic databases can be stale, disputed, or unavailable. Optional reputation providers receive only the indicator shown in the outgoing-data preview after consent. Reports are drafts until the confirmed Android handoff completes; opening an official portal is not a claim that a report was submitted.

## 8. Data and privacy

The Privacy Policy and in-product data inventory describe local storage, retention, optional outbound processing, deletion, encryption, backups, and exported-file limits. There is no account, ad SDK, sale of data, mandatory upload, or traffic/history upload by default. Optional analytics is separate and off by default.

## 9. Updates, availability, and policy constraints

Android, OEM behavior, root state, Play policy, certificates, dependencies, threat data, and external providers can change. A feature may truthfully show unavailable/limited status or use a tested equivalent route. Security-critical updates, database signature failures, or policy changes may disable unsafe activation without deleting the user's existing local data or hiding the reason.

## 10. Intellectual property and open-source notices

APK Sentinel's branding and original code/content are owned or licensed by `[publisher]`. Third-party open-source components remain under their listed licenses. The final distribution license, source-offer obligations, notices, and modification disclosures must match the dependency/architecture choice and published source materials.

## 11. Disclaimers and liability

To the maximum extent allowed by applicable law, the product is provided without a guarantee of uninterrupted connectivity, complete detection, compatibility, or fitness for a particular investigation. Nothing excludes rights or liabilities that cannot legally be excluded. Final warranty, liability cap, indemnity, dispute, governing-law, termination, and consumer-rights language must be supplied by qualified counsel for the publisher's jurisdictions.

## 12. Contact, changes, and acceptance

Security reports: `[security contact/URL]`  
Privacy requests: `[privacy contact/URL]`  
Terms/support: `[support contact/URL]`

Material changes require a new version/date and a clear summary. Reacceptance of general Terms does not renew or broaden a prior feature-specific consent.
