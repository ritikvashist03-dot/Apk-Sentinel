# Reference-product parity source snapshot — refreshed 22 August 2026

Status: product-scope research only. This file records the current public
reference outcomes used to audit APK Sentinel. It is not evidence that APK
Sentinel implements, compiles, passes device tests, or is approved for Google
Play.

## Primary sources

- [M-Kavach 2 — Google Play](https://play.google.com/store/apps/details?id=org.cdac.updatemkavach)
  - Listing observed 22 August 2026; listing says updated 23 July 2026.
  - Public outcomes: holistic device security status, security configuration
    advice, risky-app review, hidden/sideloaded-app discovery, stale-app
    statistics, authentic-app verification, adware review, URL scanning, fraud
    reporting, and English/Hindi.
- [APK Analyzer — Google Play](https://play.google.com/store/apps/details?id=sk.styk.martin.apkanalyzer)
  - Listing observed 21 August 2026; listing says updated 6 June 2024.
  - Public outcomes: installed and selected-APK reports; identity, Android
    versions, lifecycle, signing, permissions, components, hardware features,
    readable manifest save, installed-artifact/icon export, permission-to-app
    exploration, and collection statistics.
- [APK Analyzer — official source repository](https://github.com/MartinStyk/AndroidApkAnalyzer)
  - Repository README observed 22 August 2026. Its current outcome catalogue
    additionally includes the full install-source chain; base/split packaging,
    native ABI, shared-UID, manifest-security, and storage evidence; browsing
    by permission/signer/target/origin/category/shared UID; optional Usage
    Access-backed last-used/storage context; and a local factual summary.
    Repository behavior may be newer
    than the Google Play artifact, so source-only features must not be described
    as Play-version parity without artifact evidence.
- [PCAPdroid — official repository](https://github.com/emanuele-f/PCAPdroid)
  and [v2.0.0 release](https://github.com/emanuele-f/PCAPdroid/releases/tag/v2.0.0)
  - v2.0.0 was released 20 August 2026. It is the current product-scope
    baseline even when a store rollout temporarily trails the GitHub release.
  - Existing public outcomes include local no-root VPN monitoring, app/system
    connection logs, DNS/SNI/HTTP/IP evidence, HTTP and payload inspection,
    TLS decryption, PCAP/PCAPNG, remote Wireshark streaming, filters, offline
    country/ASN context, rooted capture, firewall rules, and threat feeds.
  - v2.0.0 adds a capture list with on-disk sizes, per-app isolation, settings
    import/export, Android 17 local-network handling, port-mapping exemptions,
    configurable connection-log size, domain collector destinations, updated
    MITM/Wireshark handling, simpler PCAP/PCAPNG open/decrypt, Hindi and other
    translations, corrected HAR binary bodies, and RTL fixes.
- [PCAPdroid changelog](https://github.com/emanuele-f/PCAPdroid/blob/master/CHANGELOG.md)
  - Used to distinguish v2.0.0 additions from older capabilities.
- [Android local network permission](https://developer.android.com/privacy-and-security/local-network-permission)
  - Official guidance observed 21 August 2026. `ACCESS_LOCAL_NETWORK` is a
    runtime permission only for apps targeting Android 17 / SDK 37 or higher.
    Apps targeting SDK 36 or lower must not declare or request it; their local
    network access remains implicit through `INTERNET` during this transition.
    APK Sentinel's current SDK 36 build therefore needs denial/revocation
    migration tests before a future target-37 release, not a premature prompt.

## APK Sentinel acceptance interpretation

Parity means the user outcome, not copied code, artwork, wording, trademarks,
private data, proprietary ledgers, or paid-service internals. APK Sentinel may
provide a more private or more conservative equivalent, but it may not silently
replace a required outcome with a setup screen, a future hook, documentation,
or an unsupported marketing claim.

For every row, evidence must separately establish:

1. current source implementation;
2. automated behavior and hostile-input coverage;
3. compilation, resource merging, lint, and release minification;
4. device behavior across relevant Android versions and capability states;
5. English/Hindi, large-text, TalkBack, keyboard/switch, and responsive UI;
6. privacy, security, retention, stop/cleanup, and outbound-data behavior;
7. signed AAB/APK contents and default states; and
8. current Google Play declarations and owner-provided release identity.

Android 17 local-network parity is target-sensitive. A current target-36
artifact must prove that local receiver/stream routes continue to behave on an
Android 17 device without requesting a permission that does not apply. A future
target-37 artifact must separately declare, request, explain, and recover from
denial or revocation of `ACCESS_LOCAL_NETWORK` before it is release-verified.

When Android public APIs cannot deliver a reference behavior universally, the
UI must state the exact boundary and provide a tested alternative path. A
limitation is acceptable only when it is visible and the alternative outcome is
independently verified; a limitation label alone is not parity.

## Known source/artifact distinction

- M-Kavach's authentic-app ledger is proprietary. APK Sentinel must use signer
  continuity, installer/source evidence, official handoff, and an explicitly
  approved transparency or reputation source; it must never claim access to
  M-Kavach's ledger.
- APK Analyzer's current repository can differ from its 2024 Play artifact.
  The Play listing is authoritative for Play-version claims; repository-only
  behavior is additional inspiration, not proof of reference parity.
- PCAPdroid v2.0.0 was newer than its observed Play listing. Product scope uses
  the official v2.0.0 release, while Play-policy comparison must separately use
  the artifact actually distributed by each channel.
