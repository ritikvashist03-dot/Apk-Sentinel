# Rooted capture foundation handoff

Current-source review: 22 August 2026. This module is included in the app and
the Network Advanced surface composes its explicit capability-check, capture,
stop, and SAF-export route. It is source-integrated but not compiled, device-
tested, or release-verified; the release ledger remains **Not assessed / TBD**.
The app exposes the existing headers-only route and a separately consented,
already-rooted full-packet route described below.

## What this module is

`engine/root-capture` is an Android library foundation for a bounded
PCAPdroid-style rooted-capture option, included by the app. It has no Android
permissions, service, root request on startup, automatic restart, VPN, network
client, TLS interception, CA installation, upload, or remote streaming code.
The app route is available only as an explicit Advanced action and refuses to
start unless the environment is already rooted and `tcpdump` is available; APK
Sentinel never attempts to root the device.

Two deliberately separate scopes are supported:

* `IPV4_TCP_CONNECTION_CONTROL_HEADERS_ONLY` is the existing safe route. Its
  fixed BPF admits only IPv4 TCP SYN/FIN/RST packets with no payload, including
  no TCP Fast Open data on a SYN.
* `FULL_PACKET_CAPTURE` is the full parity route for an already-rooted device
  with an available `tcpdump`. It captures PCAP packet bytes up to the explicit
  bounded snap length (at least 256 bytes for full scope). The allowlisted `ALL_TRAFFIC` filter covers IPv4 and
  IPv6, while `IPV4_IPV6_TCP_UDP` provides the narrower fixed alternative. No
  address, protocol, or arbitrary BPF text is accepted.

Full scope is not enabled by default, cannot root/install/download a tool, and
does not decrypt TLS, install a CA, or claim credentials are safe. A snap
length can truncate a large packet; the UI must disclose that limitation.

## Containment rules implemented

- Feature state defaults to off in `RootCaptureDefaults` and
  `RootCaptureStartRequest`.
- Both a capability check and a capture start require explicit typed
  `RootCaptureConsent` actions. Start actions are scope-specific
  (`START_HEADERS_ONLY_CAPTURE` versus `START_FULL_PACKET_CAPTURE`), consent
  is nonce-bound and single-use per controller, and it is valid for at most 60
  seconds. A capability-check acknowledgement cannot start a capture.
- `checkCapability` can distinguish unsupported Android, no `su`, root denial,
  root-probe failure, missing `tcpdump`, and a tool-probe failure. It can invoke
  a root manager only after the host has collected capability-check consent.
- The module assumes no bundled `su` or `tcpdump` binary. The Android adapter
  invokes only the device's `su` and only fixed `tcpdump` commands.
- Interface selection is an enum (`ALL_DEVICE`, `WIFI`, `MOBILE`) resolved from
  a validated integration-owned map; no text interface or BPF-filter input is
  accepted. The command factory has fixed header-only, all-traffic, and
  IPv4/IPv6 TCP-or-UDP filters, a bounded snap length, typed packet count, and
  fixed executable/flags.
- Common Android root managers require `su -c`. Every fixed command token is
  individually POSIX-quoted by `RootCaptureSafeShellSerializer`; no raw user
  string is joined into a shell command.
- `tcpdump -w -` emits libpcap bytes to a process pipe.
  `RootCaptureBoundedOutputPump` copies only complete bounded PCAP records into
  an app-private cache file, enforcing both the byte cap and packet cap
  independently of the tool's `-c` argument. It rejects malformed or truncated
  records, supports classic and nanosecond little/big-endian PCAP headers,
  allocates only the selected hard-bounded snap-length buffer, zeroizes that
  buffer after use, and reports accepted byte/packet counters from streamed
  records rather than guessing. Duration is capped by a scheduler.
- A byte cap is a typed `ByteCap` result and finalizes only the valid PCAP
  prefix already written at a complete-record boundary. The terminal snapshot
  exposes `TRUNCATED_AT_BYTE_CAP` (packet caps similarly expose
  `TRUNCATED_AT_PACKET_CAP`), so a caller cannot silently label a partial
  capture complete. Malformed/partial output is typed
  `PARTIAL_OUTPUT_REJECTED`, erased, and never offered for export.
- The Android file store uses the app cache directory only. It accepts no
  filesystem export path. `exportToUserChosenDestination` receives an already
  opened stream, so the product must use the Android Storage Access Framework
  and the user chooses the destination. Successful export erases the temporary
  file immediately; privacy erase best-effort zeroizes the private file before
  deletion and does not claim forensic disk erasure.
- `stop`, duration/byte/packet limits, process death, output failure, and the
  `eraseAll` privacy hook terminate work and clean private output as required.
  Stop requests expose a temporary finalizing snapshot; the controller does
  not publish a completed/exportable record until the pump has ended and the
  private output stream is closed.
  The owning app must call `eraseAll` from local-data deletion and once at
  startup to clear orphaned cache files after an app/process death.
- All user-facing outcome types are enums or typed results; neither exceptions
  nor root-manager/tool output is exposed through the public contract.

## App integration evidence and remaining requirements

The current app composition evidence is in `app/src/main/java/app/apksentinel/mobile/RootCaptureCard.kt`,
`RootCaptureComposition.kt`, and `RootCaptureUiPolicy.kt`: the Sensitive Advanced
surface defaults off, requires a scope-bound capability check and fresh start
acknowledgement, exposes only the fixed interface category and two fixed full
filters, offers bounded presets, shows scope/counters/time/output completeness
while active, keeps an immediate Stop action, gates export on valid completed
output through SAF, and provides an explicit erase receipt. This is source
evidence only; no compiled or device behavior claim follows from it.

Only after the owner completes product, privacy, security, legal/policy, and
device review may it:

1. verify `include(":engine:root-capture")` and the explicit app dependency
   remain present in the source composition;
2. retain plain-language disclosures before `CAPABILITY_CHECK` and again before
   the selected start action, explaining root-manager prompts, the exact
   packet scope/filter, snap length, duration/byte/packet caps, and whether
   payload bytes are included;
3. wire `AndroidProcessBuilderRootRunner` only to explicit user buttons,
   never onboarding, app launch, background jobs, retries, or silent probes;
4. construct `AndroidPrivateRootCaptureOutputStore(applicationContext)`, a
   lifecycle-owned `ExecutorRootCaptureRuntime`, and call `shutdown` when its
   owner ends; show a prominent active indicator and immediate Stop control
   while `RootCaptureSessionSnapshot.active` is true;
5. launch a SAF create-document flow only after
   `prepareExport(UserMediatedDestinationRequired)`, open the returned URI
   itself, and pass its stream to `exportToUserChosenDestination`; never add
   broad storage access;
6. call `eraseAll` from the existing privacy erase transaction and app startup;
   disclose that cached capture is temporary until export/erase; and
7. keep the capability and current limitations truthful. A usable probe proves
   only that the root manager and that `tcpdump` command responded on this
   device; it does not prove an interface name, OEM behavior, PCAP
   compatibility, or traffic completeness.

Android API compatibility is lower-bounded at API 26; there is no artificial
upper bound. Unknown future API levels still go through the same explicit
capability probe and are never treated as proof of root or tcpdump support.

`RootCaptureTrustedInterfaceMap` defaults (`any`, `wlan0`, `rmnet_data0`) are
safe identifiers, not device guarantees. The app must expose only verified
categories and return typed tool/device failure when the selected interface is
unavailable. Do not turn this into a free-text interface/filter field.

## Residual device and release verification

No Gradle command was run because the project build gate remains active.
Before release, the owning app must run unit tests, lint, a signed build, and
physical Android 26+/OEM validation for: root-manager prompt deny/cancel and
timeout flows; no-`su`; absent/incompatible `tcpdump`; actual interface mapping
and packet filter semantics; byte/duration/packet limits under sustained load;
process kill, reboot, force-stop, and orphan cleanup; SAF cancel/failure/export
without storage permission; app-private file modes; TalkBack and large-text
disclosure/active/Stop flows; VPN coexistence; battery/thermal behavior; and
privacy/policy review of every product claim.

Do not claim decrypted HTTPS, credentials are safe, unrestricted full-device
coverage, interface portability, or root availability. Full scope captures
packet bytes only up to its explicit snap length and is not a TLS-decryption
feature. The current app integration is source evidence only; the fixed IPv4
TCP control-header route, separately consented full packet route,
already-rooted precondition, SAF export, stop/erase cleanup, and device
behavior remain unverified until the required Gradle/device/security/
accessibility/release checks are recorded.
