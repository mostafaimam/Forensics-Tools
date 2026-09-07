# macos_quarantine

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse LaunchServices quarantine events (downloads).**

Reads `com.apple.LaunchServices.QuarantineEventsV2` (SQLite) — the 'downloaded
from the internet' provenance store — listing each quarantined file: originating
URL, referrer, the agent that downloaded it, and the timestamp.

## Planned scope

- Decode the events table; Cocoa timestamp conversion
- Join to on-disk files via the `com.apple.quarantine` extended attribute
- Flag executables / disk images / scripts from the internet
- Timeline + JSON

## Inputs

`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_fsevents`, `browser_downloads`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
