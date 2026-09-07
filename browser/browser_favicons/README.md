# browser_favicons

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Favicons DB — sites visited even after history was cleared.**

Reads the Chromium `Favicons` database and Firefox `favicons.sqlite`: the
icon-to-page-URL mapping and last-updated times frequently survive a history
clear, revealing which sites were visited.

## Planned scope

- `icon_mapping` / `favicons` / `favicon_bitmaps` join; page URL recovery
- `--extract` the icon images
- Diff favicon page-URLs against surviving history to surface cleared visits
- CSV / JSON

## Inputs

Chromium `Favicons`, Firefox `favicons.sqlite`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_history`, `browser_bookmarks`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
