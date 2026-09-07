# APK Sentinel Privacy Policy - release draft

Effective date: `[publisher to complete]`  
Controller/publisher and address: `[publisher to complete]`  
Privacy contact: `[publisher to complete]`

This draft mirrors the 18 August 2026 source-truth review and
`docs/security/DATA_MAP.md`. It requires legal, runtime, SDK, network, Data
Safety, device, signed-artifact, and owner verification before publication.

## Privacy summary

APK Sentinel is designed to work without an account. APK files, installed-app inventory, device checks, and network history are processed on the Android device by default. APK Sentinel has no advertising SDK, does not sell personal data, and does not silently upload APK contents, installed-app inventory, traffic, or history.

The current source has no reputation, generic feed-update, analytics, or
support-diagnostic transport. The separately enabled live receiver route is limited to a user-paired literal-IP destination, pinned mutual authentication, metadata and upstream-classified encrypted/raw records, and strict session limits; it is never an automatic cloud upload
route. Data leaves the app only through an Android handoff or an explicitly
user-approved redirect-resolution request described below. Each available route
is disclosed and controllable.

## Data processed

- user-selected APK/package files and local analysis results;
- visible installed-app identity, version, installer, update, permission, component, and signing evidence;
- device-security settings/signals exposed by Android;
- links/hostnames a user chooses to inspect;
- during a user-started local VPN session, selected app attribution, destination address/port, time, byte counts, firewall decisions, and DNS/SNI/HTTP metadata only when technically observable;
- narrow protocol evidence only after a separate acknowledgement, active-session only and in memory; it is off by default and not written to history;
- only in separately authorized Sensitive Advanced sessions, bounded raw packets or likely-plaintext payload; the payload view is best-effort redacted, memory-only, and defaults to a five-minute maximum session. It does not decrypt TLS or persist decrypted content;
- certificate-setup material for a user-mediated Android installer, and fixed-scope already-rooted IPv4 TCP connection-control-header capture artifacts; no automatic rooting;
- validated remote pairing material encrypted locally; if the user separately starts a receiver session while monitoring is active, bounded metadata and upstream-classified encrypted/raw records can be transferred to that exact literal-IP receiver over pinned mutual TLS and application-layer authenticated encryption;
- settings, firewall decisions, consent receipts, audit events, reports, and deletion receipts; and
- user-selected redacted reports and flow-metadata exports; no support diagnostics or analytics transport.

## Purposes and legal basis

Data is used to perform the security/privacy task the user requests, remember local choices, protect connectivity, generate/export reports, apply rules, manually import generic signed security data, and satisfy security/legal obligations. The publisher must insert jurisdiction-specific legal bases and age/guardian terms after counsel review. Feature-specific consent is used where a capability is optional/sensitive; it can be withdrawn for future processing without making unrelated local tools unusable.

## Local storage, security, and retention

Sensitive app-owned records use bounded app-private encrypted storage with Android Keystore-backed keys; hardware backing is not guaranteed. Android backup is disabled. Installed-app continuity retains one encrypted prior snapshot, not a 30-day inventory history. Encrypted network metadata history is selectable as session only, one day, seven days, or 30 days, with seven days as the app default. Protocol evidence is active-session memory only. Likely-plaintext payload viewing is memory-only with a default five-minute maximum session. Raw PCAPNG is written directly to a user-selected document, not retained as app-private capture history. A bounded encrypted catalog may retain only document metadata and app-owned SAF grant state; erase does not delete user documents. Exact categories and controls appear in the in-product data inventory.

Temporary selected-file copies are deleted after analysis, including cancellation/partial-result paths. Exports are stored by the Android provider/location the user selects and can remain after app data is erased or the app is uninstalled.

## Outbound processing and recipients

No outbound route is enabled merely by accepting Terms. When chosen, recipients
can include:

- a redirect destination selected through the optional URL-resolution route;
- the Android storage provider or app selected for a report, APK, icon, manifest,
  package-set, raw PCAPNG, or redacted flow-metadata save/share handoff; or
- the official fraud-report portal opened by the user. APK Sentinel does not
  prefill or transmit the inspected report through that handoff.

The final policy must name processors, countries/transfers, safeguards,
retention, contracts, and request routes for any Android handoff or redirect
recipient. No third-party recipient may use APK contents, package inventory, or
traffic for advertising or unrelated profiling. No reputation/update,
analytics, or support processor is present in the current source.

## Permissions and access

Broad package visibility supports the core security inventory and is subject to
Android/Play review. `VpnService` is used only after the prominent local-monitor
disclosure plus Android consent. Notifications keep active-session status/stop
visible. Document access uses Android's picker. Certificate setup, already-rooted
capture, payload view, protocol evidence, pairing setup, and exports remain
separately gated and useful to decline; no traffic-decryption,
reputation, update, analytics, or support route is available in this source.

## User choices and deletion

Users can inspect without an account, decline optional access, stop sessions,
revoke document access, change network-history retention, clear categories,
delete reports/captures/rules, withdraw optional redirect resolution, and erase
app-owned local data. Erase all stops active services first and explains
anything APK Sentinel cannot remove itself: exported copies, Android's VPN
authorization record, system logs, a user-installed certificate, or remote
copies the user deliberately sent.

Applicable privacy rights and identity-verification/appeal timelines must be added for the publisher's jurisdictions. The app cannot identify an account holder because no account exists; requests about exported/remote data need the information required to locate it.

## Children, security, incidents, and changes

The publisher must define the intended age audience and required child protections. Security reports go to `[security contact]`. A verified incident follows the published response/notification process. Material policy or processing changes receive a new date/version and in-product notice; general acceptance never silently broadens a sensitive-session grant.

## Contact

Privacy: `[email/address/URL]`  
Support: `[email/URL]`  
Data-protection representative/authority details: `[where legally required]`
