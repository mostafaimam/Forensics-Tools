# cloud_dropbox

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Dropbox sync databases.**

Reads the Dropbox client databases — `filecache.dbx` / `config.dbx` (SQLite,
historically obfuscated) and `deleted.dbx` — for the synced-file inventory, the
linked account / host id, and locally recorded deletions.

## Planned scope

- Handle the historical obfuscation (supplied key / known scheme) and modern
  plaintext schema
- File inventory: server path, local path, size, mtime, sync state
- Account / host metadata from `config.dbx`
- CSV / JSON

## Inputs

`%LOCALAPPDATA%\Dropbox\instance*\` / `~/.dropbox/`.

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
