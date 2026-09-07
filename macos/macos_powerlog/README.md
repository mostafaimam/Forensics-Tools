# macos_powerlog

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the macOS PowerLog (CurrentPowerlog.PLSQL).**

Reads the PowerLog SQLite database — app usage, process start / stop, device
state, screen on/off, and (on portables) coarse location — one of the richest
macOS activity-timeline sources.

## Planned scope

- Enumerate the many `PLxxxAgent_EventPoint/Interval_*` tables
- Per-domain views: app usage, process, display, network, location
- Apple timestamp conversion; interval reconstruction
- Recover archived / rotated logs

## Inputs

`/var/db/powerlog/Library/BatteryLife/CurrentPowerlog.PLSQL` (+ archives).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_knowledgec`, `macos_coreanalytics`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
