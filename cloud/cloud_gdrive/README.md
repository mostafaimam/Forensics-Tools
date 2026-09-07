# cloud_gdrive

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Google Drive / Backup & Sync metadata.**

Reads Drive for Desktop / Backup & Sync state — `metadata_sqlite_db`,
`snapshot.db`, `cloud_graph` — for the synced-file inventory with Google file
ids, versions, parents, and local mirror paths.

## Planned scope

- Decode `metadata_sqlite_db` items / stable_ids; join the content cache
- File id → name → parent path reconstruction; shared-drive items
- Local pinned vs. cloud-only state; trashed items
- CSV / JSON

## Inputs

`%LOCALAPPDATA%\Google\DriveFS\` / `~/Library/Application
Support/Google/DriveFS/`.

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
