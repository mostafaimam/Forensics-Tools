# browser_bookmarks

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Bookmarks with added / modified times.**

Reads Chromium `Bookmarks` (JSON, plus the `Bookmarks.bak`) and Firefox
`moz_bookmarks` in `places.sqlite`: the full folder tree, each item's URL,
title, and date added / last modified.

## Planned scope

- Recursive folder-tree flattening with full paths
- Chromium checksum note; recover items only in `Bookmarks.bak`
- Firefox bookmark / place join with visit counts
- CSV / JSON

## Inputs

Chromium `Bookmarks` / `Bookmarks.bak`, Firefox `places.sqlite`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_history`, `browser_favicons`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
