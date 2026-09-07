# windows_timeline

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the Windows 10/11 Timeline (ActivitiesCache.db).**

Reads `ActivitiesCache.db` (SQLite) — the Windows Timeline / Activity History
feed — into app- and file-activity rows: application, displayed text, content
URI, start / end / duration, and the originating device.

## Planned scope

- Decode the `Activity` / `Activity_PackageId` tables and the JSON payloads
- Resolve AppId to executable / AUMID; extract clipboard-copy activity
- Per-activity timeline with device attribution
- Recover rows from freelist / WAL where possible

## Inputs

`%LOCALAPPDATA%\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
