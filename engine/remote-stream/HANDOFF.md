# Authenticated remote-stream foundation handoff

Current-source review: 21 August 2026. The module is included in the app and
the Network Advanced surface exposes an explicit, consent-gated receiver
session. Pairing material is encrypted locally; the active path uses a pinned
P-256 mTLS identity, APS1/APSA attestation, ordered AES-GCM APSR frames, and a
VPN-owned attachment. No current signed artifact, device/OEM, or Play
verification is claimed; the release ledger remains **Not assessed / TBD**.

## Current boundary

`engine/remote-stream` is an Android library included by the app. The app
validates a user-entered literal IP/port and pinned receiver identity, stores
pairing material in Keystore-backed encrypted local storage, creates an
app-owned non-exportable client identity after a user action, and opens one
outbound TLS socket only while the active VPN service has installed its socket
protector. The desktop receiver is the separate `tools:remote-receiver` JDK
module. There is no discovery, cloud, relay, DNS, telemetry, or analytics path.

It is a containment-first user-paired **one receiver** advanced feature. Keep
the source-integrated and device/release verification boundaries separate: this
is not a claim of Wireshark compatibility, broad packet-capture parity, or
release readiness.

## Controls implemented

- `RemoteStreamConfiguration()` is disabled by default. Even though the app
  exposes pairing setup, nothing can open until
  the caller explicitly enables it, supplies two fresh consents, and the host
  creates one outbound transport.
- Receiver destinations must be a user-entered IPv4 or IPv6 literal plus port.
  Host names, DNS, zone identifiers, loopback, unspecified, multicast, and
  broadcast endpoints are refused. The module never resolves a name, so it
  cannot be silently redirected through DNS rebinding.
- `RemoteReceiverIdentity` validates a user-paired P-256 X.509 public key and
  SHA-256 pin using standard JCA. The receiver key id and fingerprint, and the
  exact literal destination, are available in every active snapshot for host
  UI to display.
- Pairing consent and per-session consent are separate, expire within fifteen
  minutes, and bind the disclosure version, exact destination, receiver
  fingerprint, network use, data categories, packet/byte/duration/queue caps.
  Any clock failure, rollback, expiry, or mismatch fails closed.
- The host boundary (`RemoteStreamSecureHost`) owns Android Keystore local
  keys/certificates and the actual connection. It must attest TLS 1.2+,
  mutual authentication, the exact destination, receiver pin, and a fresh
  challenge nonce. Cleartext, UDP, unauthenticated transport, discovery, and
  server/listener modes are not representable by the contract.
- Session keys are a one-use `RemoteStreamEphemeralSessionKey` capability from
  the secure host. This library copies it only for immediate AES-256-GCM use,
  then wipes its copy and destroys the host capability. It has no key
  persistence API or plaintext key store.
- Versioned `APSR` frames use AES-GCM with authenticated version/category/
  sequence/time/length headers. The reference receiver verifier rejects
  malformed, tampered, replayed, and out-of-order frames and zeroizes callback
  plaintext immediately after consumption.
- `tools:remote-receiver` accepts `APS1` client attestation, responds with
  `APSA`, derives the same ephemeral AES-256 key, requires the exact enrolled
  Android client SPKI through mTLS, and exposes only a bounded local
  `RAW_ENCRYPTED_PACKET` sink.
- Default categories are only `METADATA` and upstream-classified
  `RAW_ENCRYPTED_PACKET`, both encrypted again in the bounded in-memory queue.
  `DECRYPTED_PAYLOAD` and `CREDENTIAL` additionally require a fresh separate
  `RemoteStreamSensitivePayloadAuthorization`; they are never implicitly
  enabled.
- Queue records, queue bytes, record bytes, packets, bytes, and duration are
  bounded. Backpressure drops new input without dropping/reordering queued
  frames. A single head is retried at a time. Snapshot counters distinguish
  accepted, transmitted, queued, dropped, and backpressure events.
- The session has `mustShowProminentActiveIndicator` and `mustShowStopControl`.
  It wipes the encrypted queue, frame key, and closes the host transport on
  user stop, duration/limit, network change, background, process-owner stop,
  clock problem, consent expiry, authentication loss, or transport failure.
  No raw exception text appears in statuses.

## Files

- `RemoteStreamContracts.kt`: literal pairing, receiver pin, fresh consent,
  limits, secure-host and pinned-mutual-TLS contracts.
- `RemoteStreamFrameProtocol.kt`: versioned AES-GCM framing, pure reference
  replay/order verifier, ephemeral receiver callback bytes.
- `RemoteStreamSession.kt`: start gates, status, bounded encrypted queue,
  backpressure, lifecycle and zeroization.
- `src/test/.../RemoteStreamSessionTest.kt`: malicious destination/port,
  P-256 identity mismatch, default-off/expiry, sensitive consent, replay and
  order, callback zeroization, queue backpressure/cancellation wipe,
  receiver-auth loss, clock rollback, and limit stop sources.

## Operational composition now present

The app composition supplies the reviewed seams described by the contracts:

1. `RemoteStreamCard` keeps the feature in Network Advanced, requires separate
   pairing and session review toggles, shows the literal destination,
   fingerprint, limits, active status, counters, and immediate Stop action;
2. `RemoteStreamComposition` creates the Android Keystore client identity,
   shares only its public certificate, stores pairing ciphertext, opens pinned
   TLS 1.2/1.3 over a protected socket, performs APS1/APSA ECDH, and attaches
   the session to the running VPN service;
3. `RemoteStreamAttachmentRegistry` is process-local and service-owned. VPN
   revoke, service destruction, network changes, app background, and user Stop
   terminate the session and wipe queued frames/session keys; and
4. `tools:remote-receiver` runs as a JDK application, accepts only the exact
   enrolled client certificate, preserves sequence order, and writes only the
   operator-selected bounded raw-encrypted sink.

Only metadata and upstream-classified `RAW_ENCRYPTED_PACKET` records are
connected today. No decrypted payload or credential source is composed.

## Remaining device and security validation

Before any release, complete independent security review and real-device tests
on Android 26-36 and representative OEMs: Android Keystore invalidation and
biometric/lock changes; TLS 1.2/1.3 pin and mutual-auth proof; wrong key,
wrong literal/port, certificate rotation and expiry; captive portal, IPv4/6,
Wi-Fi/mobile/VPN transition and DNS non-use; offline/reconnect/backpressure;
foreground/background/process death; clock changes; queue/memory/battery
limits; frame fuzzing/tamper/replay/order; receiver one-copy and zeroization
behaviour; consent expiry/revocation; TalkBack/large text/EN-HI disclosure;
and Play policy, Data Safety, legal/privacy and threat-model approval.

Focused direct JDK/Kotlin compilation and protocol/session tests are useful
source checks but are not current Gradle, Android-device, signed-artifact, or
release evidence. Before release, run the repository Gradle suite and the
device/OEM/security matrix above against the same source and artifact tuple.
