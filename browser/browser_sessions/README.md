# browser_sessions

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Open windows / tabs / form data at last close.**

Reconstructs the browsing session that was open when the browser last closed:
Chromium `Sessions` / `Tabs` / `Last Session` / `Current Session` and Firefox
`sessionstore.jsonlz4` (mozLz4) — window / tab list, navigation history per tab,
and unsent form data.

## Planned scope

- Chromium SNSS command-stream parser; per-tab navigation entries
- mozLz4 decompression + sessionstore JSON walk
- Recovered form field values and scroll positions
- Per-tab timeline; JSON

## Inputs

Chromium `Sessions/` directory, Firefox `sessionstore*.jsonlz4` /
`sessionstore-backups/`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_history`, `browser_downloads`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
