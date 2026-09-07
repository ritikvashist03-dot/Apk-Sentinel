# Network monitor module handoff

Current-source review: 18 August 2026. `engine/network-monitor` is included
and composed by the app. The statements below separate source-integrated
behavior from release evidence: no current Gradle, device/OEM/network, signed
artifact, or Play verification is claimed, and the release ledger remains
**Not assessed / TBD**.

## What is implemented now

`engine/network-monitor` contains a user-started, on-device local-VPN engine.
Its default `PureKotlinForwardingDataPlaneFactory` is original Kotlin/Java code;
it does not bundle PCAPdroid code or a native forwarding library.

The built-in data plane:

- creates a local full-route `VpnService` only after Android consent and a
  capability/MTU check;
- forwards **unfragmented IPv4 and IPv6 TCP and UDP** through protected upstream
  `SocketChannel`/`DatagramChannel` sockets;
- calls `VpnService.protect(...)` through `TunnelSocketProtector` before every
  upstream socket is connected, preventing an upstream connection from looping
  back into the local VPN;
- performs a bounded synthetic TCP handshake and local TCP-to-socket proxy;
- retains only bounded, in-flight write queues (256 flows and 256 KiB per flow
  by default), applies TCP/UDP idle timeouts, and exposes payload-free metrics;
- delivers packet metadata in both directions, so existing bounded cleartext
  port-53 DNS observation can see query and response metadata. DNS names remain
  per-session hashes by default;
- attributes an observed TCP/UDP tuple to one installed package only when
  Android API 29+ returns an owner for this **active** VPN and exactly one
  package owns that UID. Lookups use literal packet addresses, keep a bounded
  in-memory per-flow cache, and preserve missing/platform/shared-UID outcomes
  as explicit `Unknown` values; and
- enforces matching outbound firewall blocks before an upstream socket is used;
  a blocked TCP packet receives a synthetic RST and other valid IP packets
  receive a local ICMP administrative-prohibition error; and
- closes duplicate TUN descriptors, sockets, and the selector on user Stop,
  revocation, TUN I/O failure, or worker failure. Unexpected worker failure is
  reported through `onDataPlaneStopped` rather than silently leaving a route.

### Opt-in protocol-evidence foundation (PC-03 / PC-04)

`ProtocolEvidenceConfiguration` is part of `TunnelConfiguration` and is
**disabled by default**. The current app exposes a separately acknowledged
Advanced control and can enable it for one active session. The built-in TCP
forwarder makes an in-memory `protocolEvidenceSnapshot()` available only while
that session is active. It never writes these observations to
`NetworkEventStore`, encrypted history, flow-metadata exports, raw-PCAPNG
exports, or disk; it is rendered only in the active Network screen.

`ProtocolEvidenceSnapshot.sessionLimitations` gives a stable capability state:
the default snapshot contains `DISABLED_BY_SESSION`; an explicitly enabled
session has no session limitation but each parse still records any applicable
typed limitation.

The collector is bounded to 64 flow keys, 128 observations, and two
observations per flow/direction by default. It does not retain TCP bytes or
reassemble them: it parses only the one already-present TCP payload before the
forwarder releases it. It is invoked only on packets that passed the existing
forwarding decision, and it does not open a socket, change forwarding, or add
traffic. Session stop clears its in-memory observations.

The exact supported evidence surface is deliberately narrow:

- TLS: one complete TLS handshake record containing one complete ClientHello
  can yield a safe ASCII DNS SNI value. TLS is not decrypted. Fragmented,
  oversized, malformed, Unicode/unsafe, absent-SNI, and opaque records yield a
  typed limited outcome rather than a hostname.
- HTTP: only when `inspectCleartextHttp` is explicitly enabled, one complete
  bounded HTTP/1.0 or HTTP/1.1 request/reply header can yield method +
  version, or response status + version. No request target, Host header, other
  headers, body, query value, fragment, absolute authority,
  Authorization, Cookie, Set-Cookie, proxy credential, or API-key value is
  represented. Credential-bearing headers are only reported by the stable
  `SENSITIVE_HEADERS_OMITTED` limitation.

The capability is source-integrated in the app but remains off by default and
is unverified without a current build/device run. Its default product state is
`DISABLED_BY_SESSION`. If a session explicitly opts in, it remains `LIMITED`:
there is no TCP stream reassembly, TLS record or
handshake fragmentation support, HTTP chunk/body parsing, HTTP/2 or HTTP/3,
QUIC inspection, encrypted-DNS interpretation, payload UI, persistence,
decryption, MITM, hostname inference, or full-PCAPdroid protocol parity.

The service deliberately configures its TUN descriptor in blocking mode because
the data plane owns a dedicated reader and closes its duplicate descriptor to
cancel it safely. Android documents that reads from the VPN descriptor supply
outgoing IP packets and writes inject incoming packets; this is the model used
by this module. The upstream protection behavior follows Android's documented
`VpnService.protect(...)` contract.

### Sensitive Advanced likely-plaintext payload view (source-integrated, unverified)

The app also composes `PayloadInspectionConfiguration` behind a separate
Sensitive Advanced acknowledgement. It accepts only bounded bytes already
held by the local forwarder, makes a best-effort redacted text/hex view, and
keeps the retained content in memory only. The default maximum session
duration is **five minutes** (with byte, record, flow, queue, and per-record
caps); it does not decrypt TLS, reassemble TCP/UDP, write to disk, export,
upload, or feed raw content to ordinary history. A second reveal acknowledgement
is required before rendering selected content, and stop/hide/session teardown
zeroizes the in-memory material. This route is source-integrated but has not
been compiled or device-tested in the current review.

### Redacted flow-metadata SAF export (source-integrated, unverified)

The app can choose a local Android Storage Access Framework document and write
bounded JSON or NDJSON flow metadata. The export is explicitly marked redacted
and contains no payload, endpoint address, DNS value, package name, flow ID, or
session ID; it retains only bounded protocol/direction/timestamps/counts,
attribution state, and safe DNS-name state. It is a user-selected document
handoff, not packet capture or a remote upload. The output stream is owned by
the app handoff and is closed after the export. End-to-end document-picker and
device verification remain outstanding.

## Safe failure behavior

The service calls `ForwardingDataPlaneCapabilities.supports(configuration)`
**before** `Builder.establish()`. The built-in forwarder requires an MTU of at
least 1280 bytes and the requested IP family capabilities. If it cannot support
the request, the service publishes `CAPABILITY_UNAVAILABLE` and does not create
a traffic-owning route.

Once a valid route exists, a packet is never silently treated as forwarded:

- unsupported but valid IPv4/IPv6 packets get a local ICMP error where that is
  safe to construct;
- refused/failed TCP connections get a synthetic TCP reset;
- queue/capacity pressure is bounded and reported with an error response;
- an explicit firewall block gets an enforcement result plus a terminal local
  response; and
- malformed packets cannot safely be answered, but the synchronous listener
  records the parser failure and the packet is not routed.

`NoForwardingDataPlaneFactory` remains available for a host that wants the old
safe-disabled behavior. It reports no forwarding capability, so no TUN route is
created.

## Exact limits — do not market these as covered

This is a functional local TCP/UDP monitor/protector, **not yet a complete
PCAPdroid-equivalent capture stack**. Do not claim any of the following:

- complete app/UID attribution: the active-VPN Android API is attempted only
  for TCP/UDP on API 29 or later. It can be unavailable or return no owner,
  and any shared UID or multiple package result is deliberately `Unknown`; it
  never guesses from a five-tuple. The cache is bounded, process-local, and
  discarded with the forwarding runtime;
- IPv4 fragment reassembly, IPv6 extension headers/fragments, ICMP or IPsec
  proxying, QUIC-specific inspection/control, multicast/broadcast-specific
  behavior, or captive-portal edge cases. QUIC is opaque UDP only when it fits
  the normal UDP forwarding path;
- full TCP parity: TCP options, SACK, window scaling, retransmission storage,
  transparent half-close completion, and high-throughput tuning are not full
  implementations. Remote-to-app outstanding data is capped at 64 KiB;
- TLS decryption, certificate installation, MITM, root
  capture, remote traffic relay, payload UI, or full PCAPdroid-level capture.
  The one narrow exception is the separately user-started, bounded local
  raw-IP PCAPNG evidence export documented below; it is not continuous capture
  and must never be marketed as full PCAPdroid parity;
- interpretation of encrypted DNS, DNS-over-HTTPS, DNS-over-TLS, QUIC, or
  opaque encrypted payloads; or
- full durable-history parity in the engine. The engine's default event store
    is bounded and process-local, while the app composes a separate encrypted
    metadata history with selectable session-only/1-day/7-day/30-day retention
    (7 days by default).

Valid but unsupported packet types are visible as limitations/errors, not a
promise of coverage. This distinction must remain in product copy and the Play
Store disclosure.

## Host flow and API contract

1. Show a dedicated local-VPN disclosure before Android's consent surface. It
   must explain app identity, destination/IP/time/byte metadata, local
   processing, retention, no traffic/history upload, the one-active-VPN limit,
   protocol limitations, and how Stop works.
2. Record `VpnDisclosureAcknowledgement` only after that disclosure is accepted.
3. Launch `NetworkMonitorController.vpnConsentIntent(context)` when non-null.
4. After Android returns success, call
   `NetworkMonitorController.startAfterUserConsent(context, request)`.
5. Render actual state from `NetworkMonitorRuntime.currentStatus()` and render
   a capability/limitation, not an "active" claim, until state is `ACTIVE`.
   `ACTIVE` still does not mean universal protocol coverage: the built-in data
   plane reports `TRAFFIC_FORWARDING` as `LIMITED`, and that report must remain
   visible in the Network UI.

`ForwardingDataPlane.start` now receives the requested `TunnelConfiguration`:

```kotlin
fun start(
    tunnel: ParcelFileDescriptor,
    configuration: TunnelConfiguration,
    socketProtector: TunnelSocketProtector,
    listener: ForwardingDataPlaneListener,
): ForwardingStartResult
```

The configuration is required so a data plane can reject an unsupported MTU
before routes are changed. Custom forwarders must update to this signature and
must report their own real capabilities; they must not simply copy the built-in
capability object.

`ForwardingDataPlane.metrics()` returns only safe aggregate counters—active
flows, packet/byte counts, opened/closed flows, block/error counts, and queue
pressure. It never returns packet payloads, addresses, or DNS names.

## Runtime API for the Network UI

`NetworkMonitorRuntime` is the payload-free, thread-safe read/control surface
for the host UI. Its default dependencies use a bounded process-local event
store and a reversible `InMemoryFirewallRuleProvider`:

```kotlin
val status = NetworkMonitorRuntime.currentStatus()
val events = NetworkMonitorRuntime.recentEvents(limit = 100) // oldest to newest; bounded
val clearedEventCount = NetworkMonitorRuntime.clearRecentEvents()
val metrics = NetworkMonitorRuntime.forwardingMetrics()

val rules = requireNotNull(NetworkMonitorRuntime.inMemoryFirewallRules())
rules.upsert(blockRule)          // add or replace by rule ID
rules.remove("block-example")   // returns false when the ID was absent
rules.replace(listOf(ruleA, ruleB))
rules.clear()                    // returns the removed count
```

`NetworkEvent` and `ForwardingMetrics` contain no raw packet or payload bytes.
Events can still contain the metadata that the current session was configured
to observe (for example endpoint metadata and a safe DNS-name representation),
so the UI must not log or upload them without its own approved policy. Clearing
events does not stop the VPN or change rules. Rule changes are synchronized and
take effect for the next parsed outbound packet; they are not persisted. If a
host installs another `FirewallRuleProvider`, `inMemoryFirewallRules()` returns
`null` deliberately rather than mutating an unknown backing store.

The default event store is capacity-evicted and process-local: it has **no
seven-day or other age-based retention window**, and process death clears it.
The app separately composes `EncryptedNetworkHistoryController` for encrypted
metadata history with selectable session-only/1-day/7-day/30-day retention;
the app default is 7 days. The Network UI must distinguish these two surfaces
and must not describe the engine event store as durable time-based history.

The runtime pins these reads to the currently active session's dependency
snapshot. Calling `NetworkMonitorRuntime.install(...)` while monitoring is
active therefore only changes a later session, rather than making the UI read
from a different store or rule provider halfway through one session.

`NetworkMonitorDependencies.appAttributionProviderFactory` is created once per
user-started service session. The default uses
`ConnectivityManager.getConnectionOwnerUid(...)` only from the built-in active
VPN TCP/UDP path (API 29+), with literal `InetSocketAddress(InetAddress, port)`
endpoints—never host-name construction or DNS. A custom provider must preserve
the same conservative contract: exactly one `PackageManager` package for the
returned UID may be `Known`; no owner, platform/security failure, and shared or
multi-package UIDs must remain `Unknown`. Attribution cache entries are
bounded, process-local, and are not written to an event or export.

## Explicit bounded raw-PCAPNG evidence export

This path is source-integrated in the app but is not release-verified. It
writes directly to the local user-selected Android document stream; it is not
an app-private capture history and it has no remote receiver or upload path.

The built-in Kotlin forwarder can offer raw IPv4/IPv6 datagrams to an explicit,
user-started `RawPcapngCaptureRuntime` session. The runtime writes original
PCAPNG blocks, not a synthetic metadata file: a section header block, one
`DLT_RAW` (101) interface description block, and enhanced-packet blocks with
microsecond timestamps, captured/original lengths, and required padding. The
module never closes the caller-provided output stream.

The host must first show an additional prominent disclosure because this export
contains packet bytes. It must then obtain a **local user-selected document
stream**, start capture, and render actual status/drop counters. There is one
process-wide active capture only:

```kotlin
val output: OutputStream = /* user-selected local document stream */
when (RawPcapngCaptureRuntime.start(
    output = output,
    limits = RawPcapngCaptureLimits(
        maximumDurationMillis = 60_000,
        maximumPackets = 5_000,
        maximumCapturedBytes = 20L * 1024L * 1024L,
        perPacketSnaplen = 65_535,
        queueCapacity = 128,
    ),
)) {
    is RawPcapngCaptureStartResult.Started -> Unit
    is RawPcapngCaptureStartResult.Rejected -> /* render the stable reason code */ Unit
}

val status = RawPcapngCaptureRuntime.status()
RawPcapngCaptureRuntime.stop() // requests queue drain + flush; does not close output
RawPcapngCaptureRuntime.awaitStopped(timeoutMillis = 2_000)
```

The forwarding path calls only a non-blocking queue offer. A saturated queue,
duration/count/serialized-file-byte limit, invalid/non-IP packet, or output failure is reported
in `RawPcapngCaptureStatus`; `failureReason` and rejected-start reasons are
stable enums and never contain a provider/exception message. None stalls
forwarding. A capture stops when the
local VPN session ends, or on its own duration/count/byte bounds. No payload is
parsed, displayed, decrypted, remotely streamed, or retained once the session
ends. The serialized-file byte limit includes the 48-byte SHB/IDB prefix and
every EPB header, payload padding, and trailer; queued packet copies are
zeroized on write, rejection, stop backlog, and failure. Custom forwarders report raw PCAPNG as unavailable unless they explicitly
set `canOfferBoundedRawPcapngCapture = true` and call the same hook.

Capture begins only with a non-negative epoch clock. Negative packet timestamps
are dropped and counted; a broken/negative clock during capture ends it with a
typed failure. Duration deadlines and PCAPNG millisecond-to-microsecond values
use saturating arithmetic, so extreme valid epoch values cannot wrap into a
negative timestamp.

The public result types are intentionally code-only:
`RawPcapngCaptureStartResult.Rejected.reason` is a
`RawPcapngCaptureStartRejection`, and terminal status uses
`RawPcapngCaptureFailureReason?`. If worker creation/start fails, start clears
the active slot before returning `WRITER_START_FAILED`, allowing a later retry.

`PCAPNG_RAW_PACKET_EXPORT` is therefore `LIMITED`, while
`METADATA_CAPTURE_EXPORT` remains a separate, safer export surface. Neither is
full-PCAPdroid capture parity.

## Bounded metadata-capture export (not PCAPNG)

The available alternative is a deterministic, streaming JSON Lines export of
safe event metadata only:

```kotlin
val output: OutputStream = /* user-selected local document stream */
val result = SafeMetadataCaptureExporter.writeJsonLines(
    events = NetworkMonitorRuntime.recentEvents(limit = 512),
    output = output,
    limits = MetadataCaptureExportLimits(
        maximumEventsExamined = 512,
        maximumRecords = 512,
        maximumBytes = 512 * 1024,
        maximumRecordBytes = 2 * 1024,
    ),
)
```

The exporter writes a fixed metadata-source descriptor (`id=0`,
`android-local-vpn-metadata-v1`) followed by one record at a time, preserving
the supplied order and each event's exact epoch-millisecond timestamp. It does
not materialize the supplied event sequence, open sockets, choose a
destination, or close the supplied stream. The caller controls both sources:
to preserve the local-only promise, it must provide a bounded local event
snapshot and a user-selected local document stream, and handle I/O errors.

Exported records exclude raw packet bytes, payloads, endpoint addresses, ports,
DNS names, session/flow IDs, rule IDs, and free-form event details. They retain
only safe enums/counts/timestamps such as direction, IP/transport family,
packet size, parser-note codes, firewall outcome state, lifecycle state, and
limitation code. `METADATA_CAPTURE_EXPORT` is therefore `LIMITED` and must be
described as metadata export, never packet capture.

## Build and verification boundary

The owning build already includes the module and app dependency:

```kotlin
// settings.gradle.kts
include(":engine:network-monitor")

// app/build.gradle.kts
dependencies {
    implementation(project(":engine:network-monitor"))
}
```

The module deliberately applies only `com.android.library` because AGP 9.3
uses built-in Kotlin. Its direct AGP version is `9.3.0`; do not add
`org.jetbrains.kotlin.android` to this module.

Its manifest merges `INTERNET`, foreground-service permissions, and a
non-exported `NetworkMonitorService` with `BIND_VPN_SERVICE`. The service opts
out of always-on VPN. Before Play submission, policy/legal owners must review
the current VPN and foreground-service declarations and the user disclosure.

## Tests included and still required

Unit source now covers:

- IPv4/IPv6 TCP/UDP codec round trips and checksums;
- explicit IPv4-fragment rejection and synthetic TCP reset construction;
- bounded forwarding flow admission/release;
- existing packet metadata/DNS parsing, firewall priority/enforcement state,
  event eviction, and export redaction; and
- TCP/UDP owner-attribution endpoint orientation, bounded exact-flow caching,
  single-package mapping, and explicit shared/no-owner/platform-unavailable
  fallbacks; and
- limited-capability reporting plus the runtime event/rule/metrics API; and
- deterministic bounded metadata-capture streaming/export redaction.
- PCAPNG SHB/IDB/EPB binary structure for raw IPv4/IPv6, snap-length/original
  length handling, strict duration/count/byte bounds, bounded queue drops, and
  output-failure/no-stream-close behavior.
- protocol-evidence default-off behavior; complete TLS ClientHello SNI; split,
  oversized, malformed, and Unicode SNI rejection; cleartext HTTP
  request/reply summary bounds; query/header/body/credential omission; and
  per-flow/global metadata bounds.

Run the full module and app test suite for release evidence. Source-level
changes and the app compositions described in this handoff have **not** been
claimed as Gradle-compiled; the latest audit intentionally did not run Gradle.

Physical-device validation remains mandatory before release:

- Wi-Fi and mobile data; IPv4 and IPv6; TCP and UDP DNS; Private DNS;
- common TCP applications, UDP applications, QUIC behavior, and apps with
  large transfers; captive portals; network handoff; background/Doze;
- firewall allow/block rules, user Stop, Android revoke, another VPN,
  lockdown/always-on state, app selection, and OEM foreground-service kills;
- malformed/fragmented/ext-header traffic, flow/queue limit behavior, and
  memory/CPU/battery soak tests; and
- accessibility and plain-language disclosure review.

## Remaining integration contract for full product parity

To close the gap toward PCAPdroid-level functionality without changing the
privacy model, add a separately reviewed data-plane layer with all of the
following before making parity claims:

1. production-grade TCP state/retransmission/options/window control and a
   complete UDP/ICMP/fragment/IPv6 extension strategy;
2. keep the app-composed encrypted network history metadata-only and selectable
   by retention policy; the current raw PCAPNG export is caller-owned,
   short-lived, bounded, and does not claim encryption, retention, deletion
   scheduling, or broad capture parity;
3. optional SNI/HTTP/TLS metadata only where lawful and without MITM unless a
   separately approved product/privacy/security design explicitly changes that
   boundary;
4. any future country/ASN or threat-feed update transport would require signed
   data, expiry/rollback protection, and offline behavior; no update transport
   exists in the current source; and
5. independent network/security review plus the device matrix above.

Until then, keep the app's plain-language network screen scoped to **local
TCP/UDP monitoring and firewall enforcement with explicit limitations**.

## Durable firewall-policy foundation (PCAPdroid parity track)

`FirewallPolicyController` is an opt-in durable policy source in the engine.
It is intentionally **not** installed by `NetworkMonitorRuntime` by default,
so existing process-local `InMemoryFirewallRuleProvider` behavior remains
unchanged. Its policy rules are translated into the existing `FirewallRule`
engine only when a host explicitly supplies the controller (or composes it
after an existing provider):

```kotlin
val policy = FirewallPolicyController(keystoreBackedStore)
val provider = CompositeFirewallRuleProvider(existingRules, policy)
// Supply `provider` in a future NetworkMonitorDependencies installation.
```

The pure-engine `FirewallPolicySecureStore` contract receives plaintext only
after a host decrypts it and must write it with authenticated Android
Keystore-backed encryption. `InMemoryFirewallPolicySecureStore` is exclusively
for tests/previews; do not use it for durable user rules. The versioned codec
is bounded and strict UTF-8 validated. It has no network, remote configuration,
or plaintext preferences behavior.

Rule state is deliberately split:

- `enabled` is the user’s saved switch;
- `saved` reports secure-store success separately from activation;
- `active` means the rule was converted for the forwarder at this instant;
- `confirmedHitCount` changes only through `recordConfirmedOutcome` with the
  original matching decision and matching forwarder result.

Supported active scopes are exact app UID, package name, numeric IP/CIDR,
explicit-domain signal, transport protocol, and destination port. UID support
now evaluates only `AppAttribution.Known.uid`; an unknown/ambiguous owner never
matches a UID rule. Domain rules retain the existing strict contract: they need
an explicit separately-reviewed domain signal and never use hashed default DNS
metadata.

Unsupported scopes (country, ASN, URL path, TLS SNI, process, Wi-Fi, unknown)
are retained only so the UI can disclose them; they are inactive and never
converted. Broad block rules are also inactive until a future data-plane layer
can classify captive-portal and system-critical flows. Rules targeting a UID
below Android’s normal application range are visible but inactive pending the
same host classification. These are typed `FirewallPolicyLimitation` states,
not silent bypasses.

Temporary allows fail closed when wall-clock time is unavailable or rolled back;
temporary blocks remain active in that condition. This conservative behavior is
visible in `FirewallPolicyActivity`. `emergencyRelease()` persists an immediate
global release without deleting rules; `disableAll()` instead turns their saved
switches off. Both operations return a single-revision undo token. Do not claim
a rule was enforced merely because it is saved, active, selected by a decision,
or was requested; only an accepted forwarder confirmation is a hit.

Future app wiring must provide:

### Selected-app HTTP-over-TLS route (source-integrated, unverified)

The host installs a process-local `TlsInspectionRoute` in
`NetworkMonitorRuntime`. The service intent carries only selected package
names, a fresh one-shot session-consent nonce/timestamp (two-minute maximum
age, consumed before route opening), and byte/duration caps; CA private-key
handles and the normal system-trust context never cross the intent boundary.
The route opens only after exact public CA presence is verified. Shared-UID,
sensitive-category, and uncertain packages are excluded. Interception occurs
only for one known active-VPN package on TCP/443; unknown and unselected
attribution uses ordinary forwarding. Selected UDP/443 is rejected because
QUIC is not TLS-inspected.

The forwarder drives both bounded SSLEngine legs: client ciphertext enters the
local server engine, upstream handshake bytes go to the protected socket, and
upstream ciphertext is re-wrapped to the app. The callback re-wraps only the
ephemeral plaintext segment and zeroizes it before return. TLS 1.2/1.3 are
selected only when offered and provider-supported; SNI, HTTPS endpoint
identification, and normal system trust remain mandatory. Fragmented records,
underflow/overflow, delegated tasks, close-notify, queue caps, and idle/session
timeouts are handled. No-SNI, malformed/oversize, unsupported provider,
non-HTTP, trust, user-CA, pinning, or backpressure failure closes only the
selected flow with a terminal reset; it does not tear down the VPN.

Host driving algorithm: collect separate CA-setup and one-shot session consents;
the session nonce is invalidated when the start request is issued or rejected
and must be freshly acknowledged for the next VPN start; verify
the exact public CA while disclosing that this does not prove app trust or
remove pinning; obtain Android VPN consent; on each SYN choose intercept,
bypass, or reject; after TCP establishment feed client fragments and drain
`toUpstream` to the protected socket and `toClient` to bounded synthetic TCP
packets; feed upstream reads in the same way; on Stop, timeout, FIN, reset,
revoke, or erase, drain close-notify where possible and clear route memory.
Java SSLEngine does not provide truthful SSLKEYLOGFILE/decrypted-PCAPNG
parity. Plaintext bodies/credentials are not persisted or sent to the
authenticated remote stream; sanitized HTTP/HAR adapter and device/OEM
verification remain follow-up evidence.

1. a reviewed Keystore AES-GCM `FirewallPolicySecureStore`, with tamper/key
   failures mapped to `Corrupt`/`Unavailable` rather than replacing rules;
2. an explicit disclosure and separate confirmation for broad/system-critical
   policy limitations, plus a real captive-portal/system-flow classifier before
   enabling such blocks;
3. a forwarding-session result bridge which calls
   `policy.recordConfirmedOutcome(decision, result)` for the exact directive;
   the current data plane only reports block confirmations, so do not surface
   “allowed hit” totals as delivery claims; and
4. UI states for saved/active/limited/hit separately, undo expiry, emergency
   release, secure-store recovery, and unsupported imported rules.
