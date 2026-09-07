# browser_cache

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**List and extract cached HTTP responses.**

Reads the Chromium Simple Cache and block-file cache and the Firefox `cache2`
store: cached URL, content-type, size, request / response timestamps, and (with
`--extract`) the cached response bodies written back to disk.

## Planned scope

- Simple Cache entry format (key, stream 0/1, EOF records) and block-file
  `data_#` / index
- Firefox cache2 entry + metadata parsing
- `--extract` bodies with content-type-correct extensions; SHA-256 each
- Manifest CSV / JSON

## Inputs

`Cache/Cache_Data` (Chromium) / `cache2/entries` (Firefox) directories.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_history`, `network_http`, `analysis_gallery`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
