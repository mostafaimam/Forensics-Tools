# macos_knowledgec

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse knowledgeC.db / CoreDuet app-usage and device state.**

Reads the `knowledgeC.db` SQLite store — app in-focus intervals, notifications,
device lock / unlock, plugged-in state, Safari usage, and more — into per-event
rows with start / end / duration and the originating device.

## Planned scope

- Decode the `ZOBJECT` / `ZSTRUCTUREDMETADATA` / `ZSOURCE` schema and the stream
  types
- Apple (Cocoa / Mach) timestamp conversion; local vs. UTC handling
- Per-stream views: app usage, device state, notifications, intents
- Recover deleted rows from freelist / WAL

## Inputs

`~/Library/Application Support/Knowledge/knowledgeC.db` (user and system).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_powerlog`, `macos_screentime`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
