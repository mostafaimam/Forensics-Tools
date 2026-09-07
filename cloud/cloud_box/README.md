# cloud_box

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the Box Drive metadata database.**

Reads the Box Drive local metadata store for the synced-file inventory: item id,
name, parent folder, size, modified time, and sync / offline state, plus the
linked account.

## Planned scope

- SQLite schema decode across Box Drive versions
- Folder-tree reconstruction from parent ids
- Offline-pinned vs. streamed items; recent activity where recorded
- CSV / JSON

## Inputs

`%LOCALAPPDATA%\Box\Box\` / `~/Library/Application Support/Box/Box/`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`analysis_timeline`, `windows_sqlmap`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
