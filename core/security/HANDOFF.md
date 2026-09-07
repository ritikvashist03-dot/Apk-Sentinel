# Core model and security handoff

## Required Gradle wiring

Add these project includes in the root settings.gradle.kts:

    include(":core:model")
    include(":core:security")

Use the libraries from an Android module that needs their contracts:

    implementation(project(":core:model"))
    implementation(project(":core:security"))

core:security already declares api(project(":core:model")), so its public types
resolve for consumers. Both modules use Android library plugin version 9.3.0
and the project built-in Kotlin support. Do not apply org.jetbrains.kotlin.android
to these modules.

No third-party runtime dependency is required. Both modules target compile SDK
37, min SDK 26, and Java 17 to match the app.

## Model contracts

app.apksentinel.core.model contains stable capability IDs and states; evidence
with source, confidence, context, and limitations; risk findings that keep
observations distinct from interpretations; purpose-specific consent receipts;
privacy/export/redaction policies; and bounded audit event contracts.

Do not change existing ID enum values after shipping: they can be persisted in
receipts, reports, and audit records.

## Consent and sensitive features

Before enabling a sensitive feature:

1. Display the current disclosure and collect a decision for the exact
   ConsentPurpose.
2. Record a ConsentReceipt in a ConsentLedger.
3. Request a short-lived SensitiveFeatureGrantManager grant for the current
   SensitiveSessionId, explicit scopes, and expiry.
4. Check isActive immediately before the sensitive operation.
5. Revoke all grants for a session on sign-out, app lock, or explicit user
   cancellation.

The in-memory ledger is intentionally a foundation. A future persisted ledger
must preserve append-only receipt history, unique receipt IDs, and monotonically
increasing decision timestamps per purpose. It must never treat a receipt for
one purpose as consent for a different purpose.

## Files, exports, redaction, and logs

Use SafeTextNormalizer for names received from users, packages, or files before
showing them or creating output files. It removes controls, bidi overrides,
path separators, unsafe filename characters, and Windows device names.

Apply RedactionHelpers with an explicit RedactionPolicy before creating exports,
audit metadata, or log metadata. RedactingSafeLogger is the security module
logger; do not send raw exceptions, tokens, session IDs, paths, contact details,
or transport data to Android Log.

## Encrypted storage

Compose storage using AndroidKeystoreEncryptedStorage with an
application-private SharedPreferences instance, a stable application-owned
Keystore alias, and a stable namespace. The implementation uses AES-GCM and
binds each ciphertext to its logical storage key as associated data.

The adapter uses Android Keystore, but it does not detect, request, or claim
hardware-backed key storage. Device key residency and invalidation behavior are
device-specific. Product code needs a recovery path for unavailable or
invalidated keys that informs the user without logging stored values.

Use storage only for bounded sensitive records. The provided limit is 1 MiB per
value. Clear plaintext byte arrays in caller-owned buffers where practical
after a successful write.

## Verification

After the root includes are present, run:

    gradlew.bat :core:model:testDebugUnitTest :core:security:testDebugUnitTest

The unit tests cover model contracts, purpose isolation, grant expiry and
revocation, safe text normalization, redaction-safe logging, ciphertext key
binding, and malformed payload rejection.
