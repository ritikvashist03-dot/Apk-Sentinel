# Threat intelligence handoff

## What this module does

`engine:threat-intel` is an offline verifier, encrypted local snapshot adapter,
and scheduling planner. It has **no HTTP client, endpoint, cloud account,
analytics, DNS lookup, or WorkManager dependency**. A caller supplies a signed
feed only after an explicit user action, or after the user has separately
enabled background refresh in settings.

## Exact signed feed contract

The ECDSA signature is standard padded Base64 and covers the exact UTF-8 byte
sequence. The payload must use LF line endings, have one final LF, no BOM, no
blank lines, and exactly this header order:

```text
APK_SENTINEL_FEED_V1
version=<positive decimal long>
issuedAtMillis=<positive decimal long>
expiresAtMillis=<positive decimal long>
keyId=<1-64 ASCII letters/digits/dot/dash/underscore>
entries:
<TYPE>|<canonical-value>|<category>|<LOW|MEDIUM|HIGH>|<evidence-id>
```

`TYPE` is one of `HOST`, `IP`, or `APK_SHA256`.

- `HOST` must be lower-case ASCII/Punycode, have at least two labels, and has
  no wildcard support. Incoming Unicode hosts are normalized for lookup only.
- `IP` must be canonical dotted IPv4 or canonical hexadecimal IPv6. No scoped,
  bracketed, host-name, or IPv4-mapped IPv6 spelling is accepted.
- `APK_SHA256` must be exactly 64 lower-case hexadecimal characters.
- `category` and `evidence-id` use bounded safe identifier grammars.

The verifier accepts only P-256 X.509 EC public keys. It bounds feed payloads
to 1,000,000 bytes, indicators to 25,000, signatures to 1,024 decoded bytes,
and feed lifetime to 31 days by default. Use smaller limits only if the
publisher and stored-feed cap are updated together.

## Compose it in the app layer

1. Package a reviewed immutable `List<ThreatFeedKey>` with the app. Mark a
   replacement key `ACTIVE`; mark an old key `RETIRED`; mark a compromised key
   `REVOKED` in an app update.
2. Create `AndroidKeystoreEncryptedStorage` with a dedicated Android Keystore
   alias and app-private `SharedPreferences`, then wrap it in
   `EncryptedThreatFeedSnapshotStore`.
3. Compose `ThreatFeedRepository(ThreatFeedVerifier(keys), store)` on an IO
   dispatcher. Call `install(payload, signature, now)` only after the bytes
   have arrived through a user-authorized path.
4. Call `loadActive(now)` before matching. Treat `Unavailable` and `Missing`
   as no local intelligence available, not as a clean result. Never display a
   raw parser/crypto exception.
5. Use `feed.matchHost`, `matchIp`, and `matchApkSha256` with a value already
   observed locally. A returned indicator is evidence for user review, not a
   malware verdict or automatic block.
6. On the Privacy "erase app data" action, call `repository.erase()` and show
   success only when it returns `DELETED`.

`install` reads the highest accepted encrypted version first, verifies the
candidate, and writes one complete snapshot only after acceptance. A malformed,
expired, downgraded, unknown-key, retired-key, or bad-signature candidate never
overwrites a working snapshot.

## Background refresh contract

`ThreatFeedUpdatePlanner` is a pure planner. Its default policy is
`MANUAL_ONLY`, which returns no plan. If the user explicitly enables background
refresh, pass `USER_ENABLED_BACKGROUND` and adapt `ThreatFeedUpdatePlan` into
unique replaceable work through `ThreatFeedUpdateScheduler`.

The adapter must:

- persist the user's opt-in independently from the plan;
- require the plan's unmetered constraint by default;
- cancel unique work immediately when the opt-in is revoked;
- record only a timestamp/outcome code for retry throttling, never URLs,
  indicators, app identities, or traffic history;
- call `install` on returned bytes and surface a safe rejection code.

No transport is supplied here. A future transport needs its own security
review, endpoint pinning/update strategy, user disclosure, and Play-policy
review before it is enabled.

## Retention and limitations

- `pruneExpired` removes the encrypted, app-owned snapshot after 14 days by
  default; choose zero for immediate expiry deletion. `erase` removes it now.
- The encrypted storage adapter has a 900 KB persisted payload cap because the
  shared secure-storage primitive has a 1 MB plaintext limit. A verified feed
  larger than that is deliberately not persisted.
- Android Keystore encryption protects the stored record at rest and binds it
  to its logical key. It is not an anti-replay service against a rooted device,
  device restore, or a rollback of all local app data; package a monotonic
  keyring/version strategy in app updates for that threat model.
- Key revocation takes effect only when an updated app keyring ships. Retired
  keys can validate already stored feeds until those feeds expire, but cannot
  install a new feed.
- This module does not fetch intelligence, inspect network traffic, determine
  a URL's final redirect, or guarantee a host/IP/APK is malicious or safe.

## Test surface

The unit tests cover canonical bytes, signatures, expiry, rollback, duplicate
keys, key status/validity, P-256 enforcement, host/IP/APK lookup boundaries,
snapshot copying/codec corruption, retention, and manual-vs-opted-in scheduling.
Build execution remains owned by the root release verification pass.
