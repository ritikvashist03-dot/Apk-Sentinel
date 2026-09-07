# Local reporting handoff

## What this module does

`core:reporting` renders a bounded in-memory `LocalReport` to deterministic
JSON or CSV. It does **not** write a file, persist a report, upload data, open a
share sheet, contact a server, or store a report history.

The current JSON schema version is `3`. It emits a report type/timestamp,
`truncated`, `redacted`, and `sensitiveContentOmitted` metadata, structured
fields with `sectionId`, legacy public `limitations`, and sensitivity-tagged
`notes`.

## Required caller contract

1. Classify values at the source as `PUBLIC_SUMMARY`, `TECHNICAL`, or
   `SENSITIVE`. The renderer deliberately does not infer sensitivity from a
   label or a key.
2. Use `ReportExportPolicy()` for ordinary exports. It includes public and
   technical fields, but excludes sensitive fields and notes.
3. To export sensitive content, set both `includeSensitive = true` and
   `sensitiveExportAuthorization = USER_CONFIRMED` for that one export. The UI
   must obtain the confirmation immediately before rendering/saving and must
   state what categories will be shared.
4. Keep the legacy `limitations: List<String>` public-only. Use `ReportNote`
   for any note that needs technical/sensitive gating.
5. Render only after the user has selected a Storage Access Framework document
   destination. Clear any app-owned byte buffer/temporary file after the write
   attempt. A user-selected SAF document is outside app ownership and must not
   be silently deleted later.

All strings are display-normalized and bounded; JSON escapes control characters
and malformed UTF-16, while CSV quotes cells and prefixes formula-like cells
with an apostrophe to avoid spreadsheet formula injection.

## PCAP/capture metadata policy

Use `PcapMetadataReportFactory.create(...)` for a capture summary. Its input
type intentionally has no packet payload, destination, app ID, path, or raw
PCAP field. It exports only counts/format by default; timing, app count, and
destination count are `SENSITIVE`; an optional file digest is `TECHNICAL`.

The factory can tell the user that a source capture may contain payloads, but
it never serializes payloads. Any raw PCAP/PCAPNG binary export needs a separate
explicit consent flow, its own retention/deletion implementation, and security
review. Do not pass binary capture content through `ReportField`.

## Retention and deletion

`LocalReportRetentionPlanner` describes only app-owned temporary-artifact
cleanup. Its default is immediate deletion. An app integration may implement
`AppOwnedReportArtifactStore` for a private cache/database and call it with the
planner's deadline. It must never use that interface to delete documents the
user saved through SAF or another external provider.

## Limitations

- The renderer cannot prove a caller classified a field correctly.
- JSON/CSV are metadata reports, not evidence-preserving PCAP exporters.
- The module has no content encryption or file I/O because it never persists
  artifacts itself; the app layer owns destination permissions and encryption
  choices.
- `maximumSections`, `maximumFields`, `maximumNotes`, and per-value limits are
  output safety limits, not a substitute for a capture retention policy.

## Test surface

The unit tests cover dual sensitive authorization, valid JSON escaping,
spreadsheet-formula neutralization, output truncation, PCAP metadata defaults,
and app-owned retention decisions. Build execution remains owned by the root
release verification pass.
