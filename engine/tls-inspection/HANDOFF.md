# TLS inspection foundation handoff

Current-source review: 22 August 2026. The module is included in the app and
the Network Advanced surface exposes certificate setup guidance. The app now
source-integrates a bounded selected-app route through network-monitor; this
is still source evidence only, not device/network verification. The engine
contains the forwarding-ready SSLEngine duplex core and the app host retains
only a non-exportable Keystore key handle in the process-local route.
No current Gradle, device/OEM, signed artifact, or Play verification is
claimed; the release ledger remains **Not assessed / TBD**.

## Status and boundary

`engine/tls-inspection` is a fail-closed Android library included by the app.
It generates a per-install Keystore key, signs a real X.509v3 CA certificate
(critical CA/pathLen0 and keyCertSign+cRLSign), and persists only the public DER
certificate entry. API 26-29 use the user-mediated KeyChain installer; API
30-36 offer a SAF public-certificate export plus Android Settings guidance.
Export is never treated as installation. The engine also supplies a bounded
fragmented ClientHello/SNI parser, SAN leaf builder, and TLS 1.2/TLS 1.3
SSLEngine bridge core (provider capability decides whether TLS 1.3 can be
selected) with normal upstream HTTPS endpoint validation and zeroized
plaintext callbacks. network-monitor drives both protected socket legs only
for selected known-attribution TCP/443 flows; unknown/unselected flows bypass,
selected UDP/443 is rejected as QUIC, and selected bridge failures close only
that flow. `reviewedDataPlaneAvailable` is true only for this bounded route,
not universal HTTPS parity.

Do not describe this module as universal HTTPS decryption. It does not bypass
certificate pinning, does not support non-HTTP TLS or QUIC, and has no
unbounded application selection. TLS 1.3 is attempted only when it is offered
by the ClientHello and enabled by both SSLEngine providers; a TLS 1.3-only
ClientHello is rejected with typed `UNSUPPORTED_PROTOCOL` only when the
selected provider cannot serve TLS 1.3. The app route remains subject to exact
CA-store presence, separate user consent, normal system trust, and
device/OEM verification; no pinning bypass or decrypted PCAPNG/SSLKEYLOGFILE
parity is claimed.

## Containment rules implemented

- `TlsInspectionConfiguration()` is strictly disabled by default.
- Certificate-setup consent (`CertificateSetupConsent`) and per-session
  inspection consent (`TlsInspectionSessionConsent`) are distinct types. One
  cannot stand in for the other.
- `TlsInspectionPackageScope` has a maximum of 25 explicitly selected packages.
  Banking, payment, authentication, password-manager, health, unknown, and
  shared/shared-UID categories are mandatory exclusions. The session rejects any package outside
  the validated scope on every segment.
- `AndroidTlsInspectionCapabilityMatrix` has typed rows for every Android API
  26 through 36. User-added CA trust is marked app/device-dependent; pinning,
  non-HTTP TLS, QUIC, and universal decryption are marked unsupported. The
  matrix's TLS-1.3 row remains unsupported for the current app data-plane
  attestation even though the isolated bridge can negotiate TLS 1.3 when both
  providers support it.
- `AndroidKeyStoreCaCredentialProvider` uses Android Keystore to generate a
  per-install RSA CA key and signs a validated X.509v3 CA certificate with
  Bouncy Castle 1.85. Only public DER is persisted; its public contract returns
  certificate metadata only. It has no private-key export method, encoded-key
  field, or key handle exposure.
- `AndroidUserMediatedCertificateInstallIntentFactory` creates an API 26-29
  KeyChain installer action or an API 30-36 SAF public-certificate export. It
  never starts either action; export is not installation and no private key is
  present.
- `AndroidCaStoreCertificateInstallationVerifier` reports typed
  `CA_STORE_PRESENT`, `CA_STORE_NOT_PRESENT`, or `CA_STORE_UNKNOWN` for exact
  public-certificate presence. CA-store presence is explicitly not target-app
  trust; `UNKNOWN` fails session start closed.
- `AndroidCertificateRemovalGuidance` supplies clear manual-removal steps and
  retains the verifier's typed `INSTALLED`/`NOT_INSTALLED`/`UNKNOWN` state. It
  does not silently remove a certificate.
- An active `TlsInspectionSession` accepts only a future reviewed HTTP-over-
  TLS-1.2 bridge. A copied plaintext segment is capped, supplied to one
  in-memory consumer as a read-only buffer, and zeroized in `finally`. The
  module stores only bounded safe metadata: app package, time, TLS/HTTP enum,
  and byte count. It has no body, credential, header, host, URL, endpoint,
  packet, logging, disk, export, or remote interface.
- `TlsInspectionBridge.kt` supplies a bounded fragmented ClientHello/SNI
  parser, TLS 1.2/1.3 provider-bounded SSLEngine duplex core, short-lived SAN
  leaf construction, normal HTTPS endpoint/SNI validation, QUIC/non-HTTP/
  no-SNI/malformed rejection, typed provider/trust/pinning failures, and a
  zeroized direction-labelled plaintext callback. A callback may synchronously
  call `wrapForClient(segment)` or `wrapForUpstream(segment)`; it must not
  re-enter `unwrap*` or `close` until the callback returns.
- Snapshots expose `mustShowProminentActiveIndicator` and
  `mustShowStopControl`; host UI must display both while active and call
  `stop()` immediately on the Stop action. Session duration, session bytes,
  and metadata records are bounded. Clock rollback/unavailability and local
  consumer failure stop the session closed.

## Files

- `TlsInspectionContracts.kt`: capability matrix, separate consents, host
  credential and verification contracts, user-mediated setup/removal contract.
- `TlsInspectionPolicy.kt`: default-off configuration, data-plane gate, and
  mandatory sensitive-package exclusions.
- `TlsInspectionSession.kt`: fail-closed start gate, prominent lifecycle,
  bounded in-memory metadata/segment interface and zeroization; this is a
  future traffic-integration boundary, not a current decryption data plane.
- `android/AndroidKeyStoreCaCredentialProvider.kt`: Android Keystore adapter,
  Bouncy Castle CA construction/validation, API-specific installer/export
  routes, AndroidCAStore presence verifier, and removal guidance.
- `TlsInspectionBridge.kt`: bounded ClientHello/SNI parser, SAN leaf builder,
  TLS 1.2/1.3 SSLEngine bridge core, HTTPS endpoint validation, direction-aware
  callback, typed failures, and zeroization boundary.
- `src/test/...`: pure unit tests for the matrix, exclusions, separate
  consent setup, default-off/start gates, CA DER/fingerprint/extensions,
  AndroidCAStore typed state, API installer routing, fragmented ClientHello,
  TLS 1.3-only/QUIC/no-SNI/malformed rejection, zeroization, lifecycle state,
  package gate, byte cap, and clock rollback.

## Host driving algorithm (bounded duplex)

The host owns both non-blocking sockets and never gives this module a socket,
file, logger, or persistent buffer. For one explicitly selected, consented
package:

1. Feed each bounded raw client fragment to `offerClientHello(fragment)` until
   `Accepted(hello)` or a typed rejection. Keep the same fragments in the host
   socket read buffer; parser acceptance is a preflight and does not feed an
   SSLEngine.
2. After acceptance, call `createServerEngine()`, then create the upstream
   engine with the normal system-trust `SSLContext` using
   `createUpstreamEngine(context, 443)`. The bridge sets `HTTPS` endpoint
   identification and mandatory SNI itself. Do not pass a trust-all context.
   `TLSv1.3` is enabled before `TLSv1.2` when both are offered and supported;
   a TLS-1.3-only ClientHello is not downgraded. A provider with no compatible
   version returns `UNSUPPORTED_PROTOCOL`, `NO_UPSTREAM_PROTOCOL`, or
   `TLS_PROVIDER_UNAVAILABLE`.
3. Feed the retained ClientHello bytes to `unwrapFromClient`; drain every
   `outbound` byte array from `wrapForClient(ByteArray(0))` to the client
   socket. Begin the upstream leg by draining
   `wrapForUpstream(ByteArray(0))` to the upstream socket. Continue polling
   both sockets and pass each fragment to the matching `unwrapFrom*` method.
   `NEED_MORE_INPUT` means read more, `NEED_TASK` means the provider task was
   bounded and must be retried, and `PROGRESSED` means drain outbound before
   polling again. Empty wraps are intentional handshake/close-notify drains.
4. Do not forward application plaintext until both
   `clientTlsProtocol()` and `upstreamTlsProtocol()` are non-null and the
   bridge state is `ESTABLISHED`. Once established, the callback receives an
   ephemeral segment labelled `CLIENT_TO_UPSTREAM` or `UPSTREAM_TO_CLIENT`.
   During that callback only, call the corresponding `wrapForUpstream(segment)`
   or `wrapForClient(segment)` and immediately write the returned ciphertext.
   The callback may not call `unwrap*` or `close`; copied/retained segment data
   is invalid after callback return and is zeroized in all paths.
5. Treat `CLOSED` as a close-notify/EOF boundary and stop both legs. To send
   close-notify before teardown, call `closeForClient()` and
   `closeForUpstream()` while the bridge is live, drain each result, then call
   `close()`. On
   `FAILED`, including overflow, queue-cap, non-HTTP, trust, user-CA, pinning,
   malformed, or provider failures, close both sockets and discard all pending
   bytes. Call `close()` on user Stop, socket failure, timeout, or policy
   failure. Never persist, log, export, or special-case credentials.

The bridge is synchronized and callback-safe only for the two synchronous wrap
methods above. A host that needs asynchronous forwarding must copy ciphertext
outbound bytes before callback return; it must never retain the ephemeral
plaintext segment.

## Required future traffic integration (do not do implicitly)

Before expanding the current certificate-setup route into a traffic surface,
obtain separate product,
privacy, security, legal/policy, and Android device/OEM review. Only then may
an owner decide whether to:

1. retain the deliberate app dependency and add no traffic route implicitly;
2. design plain-language setup/session disclosures, a selected-package picker,
   active indicator, Stop control, and removal/status screen;
3. collect certificate setup consent before calling
   `TlsCertificateSetupCoordinator.prepareUserMediatedInstall`, create the
   Android install intent only from that result, and let the user complete the
   system flow themselves;
4. integrate a real, independently reviewed data plane limited to HTTP over
   TLS 1.2, without pinning bypass, TLS 1.3, QUIC, non-HTTP, credentials, or
   body persistence; and
5. supply a legitimate installation verifier only where a public or managed
   capability can prove the actual result. Otherwise retain `UNKNOWN` and keep
   sessions off.

`TlsInspectionDataPlaneReadiness.REVIEWED_HTTP_TLS12_ONLY` is an integration
attestation, not evidence of a traffic implementation. Never surface it as a
claim that HTTPS traffic is being decrypted. The current app does not provide
that attestation or a traffic bridge.

## Validation performed

On 21 August 2026, `powershell.exe -NoProfile -ExecutionPolicy Bypass -File
tools/verify-static.ps1` passed: 260 source files, 5 localized resource sets,
and 15 included modules. A focused offline Gradle attempt using the locally
available Gradle 9.5 distribution (`:engine:tls-inspection:testDebugUnitTest`)
could not start because the shared project cache's
`.gradle/9.5.0/fileHashes/fileHashes.lock` returned `Access is denied`. A
separate project-cache path was also unable to create its configuration-cache
directory. Therefore focused unit tests and compilation remain unverified;
this is an environment/cache blocker, not test evidence. No full lint or
release build was run. Static checks confirm this library remains a
contract/setup boundary and contains no `VpnService`, `startActivity`,
private-key encoding, socket, file-output, HTTP client, export, or logging
implementation. The app's system-installer handoff is intentionally outside
this library and is user-mediated.

Physical-device validation is required before any release: Android 26-36/OEM
certificate UX, user-CA trust differences, cancel/remove flows, unknown
verification, clock changes, keystore invalidation, pinning/TLS 1.3/QUIC
rejection, accessibility of the active/Stop lifecycle, memory/battery caps,
and privacy review of every future local consumer.

### 22 August 2026 duplex-core update checks

- Source review covered the TLS module only. The parser now accepts fragmented
  TLS-1.3-only ClientHello and records the offered versions; both server and
  upstream engines enable only the offered/provider-supported set, preferring
  TLS 1.3 when both are available. No trust-all manager, socket, disk, export,
  logging, credential special case, or pinning bypass was added.
- Added adversarial/positive unit coverage for TLS-1.3-only acceptance,
  TLS-1.2 fallback bounds, malformed/no-SNI/oversize inputs, SNI and HTTPS
  endpoint parameters, direction labels, ephemeral zeroization, and typed
  trust/pinning mapping. The tests are present but not executed here.
- `:engine:tls-inspection:testDebugUnitTest --offline` could not start because
  this environment has no `JAVA_HOME` and no `java` executable. A subsequent
  `tools/verify-static.ps1` run was also blocked by the unrelated concurrent
  app resource error `network_app_selection_unknown_selected`; no static pass
  is claimed for this update. No network integration, device, signed artifact,
  or release verification is claimed.
