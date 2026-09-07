# APK inspector module handoff

Current-source review: 18 August 2026. This module is included in the root
build and composed by the app, so the capabilities below are source-integrated
unless explicitly marked unavailable. No current Gradle, device/OEM, signed
artifact, or Play verification is claimed; the release ledger remains
**Not assessed / TBD**.

`engine:apk-inspector` is wired into the root build and the app's APK analysis
flow. It is a local, blocking inspection engine: callers must invoke it from a
worker or I/O dispatcher. It does not contact a service and never extracts APK
entries to a user-visible directory.

## Public capability

- `ApkInspector.inspect(uri, request)` copies the selected APK/ZIP into the
  app-private cache through a bounded `ContentResolver` stream while calculating
  SHA-256, then removes that temporary artifact after inspection.
- `inspectInstalledPackage(packageName, request)` sends an installed base APK
  through the same bounded private-copy path.
- `.apks` and `.xapk` containers receive bounded, read-only nested-APK/metadata
  inspection. The result is evidence about the container and its bounded
  entries, not an installability or reinstallability claim.
- The sequential ZIP reader enforces source size, entry count, per-entry and
  total expanded-size, and compression-ratio limits. It detects ZIP-slip style
  entry names but never extracts them.
- Output includes archive metadata, bounded DEX/native/assets inventories,
  manifest summary data, signer/certificate summaries through `ApkVerifier`,
  and literal-only tracker/endpoint observations.
- Every potentially user-visible APK-engine state is now code-first:
  `HeuristicFindingCode`, `RiskExplanationCode`, `RiskLimitationCode`,
  `SigningDiagnosticCode`, and `InspectionProgressCode`. `HeuristicFinding`
  and `RiskExplanation` carry only stable codes, severity/confidence/points,
  and `ApkTechnicalEvidence` values. `InspectionFailure` deliberately exposes
  only its stable code and typed fields. UI and export adapters must localize
  codes themselves and encode evidence values as data rather than interpolate
  them into a sentence.
- The readable binary `AndroidManifest.xml` view is rendered with `apksig`'s
  binary XML parser. Its UTF-8 output limit is checked before every
  attacker-controlled attribute is committed. If rendering reaches the limit,
  it emits a well-formed XML document with a truncation comment and closes all
  already-rendered elements. Non-Android attribute namespaces are retained via
  deterministic `nsN` prefixes and inline namespace declarations.

## Result honesty and failure semantics

- `HeuristicScanTruncated` means candidate-byte scanning was bounded.
- `HeuristicFindingsTruncated` means the configured distinct-finding output
  limit was reached. It is a typed `InspectionFailure`, feeds a risk limitation,
  and makes `ApkInspectionResult.isComplete` false.
- Archive safety limits, malformed ZIP input, manifest text decode failure,
  unavailable signing verification, and temporary-file cleanup failure are also
  typed failures. The transparent risk score carries corresponding limitations.
- A complete inspection is not a malware verdict. Literal namespaces/endpoints
  do not prove code execution, data collection, or traffic transmission.

## Configuration bounds

`InspectionLimits.maxDecodedManifestBytes` is constrained to 128 bytes through
8 MiB. The non-zero lower bound is intentional: a valid XML declaration,
truncation marker, and closing tags must fit even at the configured minimum.

## Intent-filter evidence handoff

`ManifestComponent` now carries bounded `intentFilters` plus a
component-level `intentFiltersTruncated` flag. Each `IntentFilterEvidence`
contains declared actions, categories, and typed `IntentFilterDataEvidence`:
scheme, host, port, MIME type, and path entries with a `IntentFilterPathKind`.
`ManifestSummary.intentFiltersTruncated` records a global collection or
manifest-rendering bound.

The collector parses the same bounded binary AXML pass as the readable
manifest. It accepts Android-namespace attributes only, normalizes relative
component names for the `PackageManager` summary join, caps filters globally
and per component, and caps actions, categories, data declarations, paths, and
UTF-8 value size per filter. It retains no exception text.

App integration must present this as declarative local APK evidence, never a
claim that a component runs, receives traffic, exposes data, or collects data.
Map `ComponentType` and `IntentFilterPathKind` to localized labels; render raw
values with output encoding and a localized field label. Show every truncation
flag as a limitation. Do not add an export-only raw packet or network claim.

## Validation to run when Gradle execution is available

```powershell
.\gradlew.bat :engine:apk-inspector:testDebugUnitTest
```

The focused JVM coverage includes ZIP safety and inventory behaviour, bounded
copy/cancellation, risk-score explanations, finding-limit partial results, and
UTF-8/namespace-safe readable-manifest rendering. Current source changes still
need this command after the execution limit is lifted; no post-change Gradle
verification is claimed here.

## Deliberate limits

- Static local inspection only; no dynamic sandboxing, code execution, or
  malware verdict.
- The Android package parser remains the manifest-summary source. A readable
  binary XML rendering failure leaves the summary available but records a typed
  limitation.
- `ApkVerifier` is synchronous and cannot be cancelled mid-verification.
- The installed-app helper analyses the base APK, not a reconstructed split APK
  set. The app's installed export can copy the base plus available split APKs
  to a user-selected document, but that artifact is not reinstall-guaranteed:
  Android/device configuration, signatures, installer policy, and split
  completeness still determine whether it can be installed.
- `.apks`/`.xapk` bounded inspection and base-plus-split export are source-
  integrated but have not been compiled or device-tested in this review.
- `ApkTechnicalEvidence` can contain bounded archive paths, literal endpoint
  values, manifest identifiers, and signer-independent numeric observations.
  Treat all string values as untrusted technical data; do not turn them into
  display prose without output encoding and a localized surrounding label.
