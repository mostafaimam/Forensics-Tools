# mobile_appcommon

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Shared SQLite / plist / protobuf helpers for mobile-extraction parsers.**

The common back end for the mobile and chat-app parsers when they run against a
phone extraction: robust WAL-aware SQLite opening, plist decoding, a minimal
protobuf reader, and Apple / Android timestamp helpers. Not run directly.

## Planned scope

- WAL / SHM handling, deleted-row recovery, freelist scavenging
- Binary plist + `NSKeyedArchiver` unwrapping (shared with `macos_plist`)
- Schemaless protobuf decode with a field-hint mechanism
- Timestamp conversions: Cocoa, Mach, Unix ms, WebKit

## Inputs

N/A — imported by `mobile_iosbackup`, `mobile_android`, `app_chat`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mobile_iosbackup`, `mobile_android`, `app_chat`, `macos_plist`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
