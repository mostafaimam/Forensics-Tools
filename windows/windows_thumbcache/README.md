# windows_thumbcache

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Extract thumbnails from thumbcache_*.db and map them to paths.**

Parses `thumbcache_*.db` and `thumbcache_idx.db` to recover cached thumbnails
and, via the index and Windows.edb / shell artefacts, maps each one back to its
original file path — evidence of pictures and documents that no longer exist on
disk.

## Planned scope

- Parse the CMMM cache format and the IMMM index
- `--extract` every thumbnail (JPEG / PNG / BMP) to a folder
- Resolve cache-entry hash → path where the index / other artefacts allow
- Contact-sheet HTML output

## Inputs

`%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db` (+ `_idx`).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`analysis_gallery`, `windows_shellbags`, `windows_search`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
