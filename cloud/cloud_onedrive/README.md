# cloud_onedrive

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse OneDrive sync metadata and ODL logs.**

Reconstructs OneDrive sync state and activity from `<UserCid>.dat` /
`SyncEngineDatabase`, `SyncDiagnostics`, `settings/*.ini`, and the obfuscated
ODL logs (`*.odl` / `*.odlgz` / `*.aold`) — synced files and folders, the linked
account, and file add / modify / delete events.

## Planned scope

- `SyncEngineDatabase` (ESE / SQLite by version) file-inventory decode
- ODL log de-obfuscation using the bundled string map + `*.odlgz` decompression
- Account id → email; per-file cloud vs. local state
- Activity timeline; CSV / JSON

## Inputs

`%LOCALAPPDATA%\Microsoft\OneDrive\{settings,logs}` on a Windows image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_esedb`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
