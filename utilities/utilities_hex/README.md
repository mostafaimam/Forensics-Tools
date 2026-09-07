# utilities_hex

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Hex viewer and data interpreter.**

A hex viewer with a cursor-driven data interpreter — shows the value under the
cursor as int8/16/32/64 (LE/BE), float, FILETIME, Unix / DOS date, GUID, and
more — available both as a standalone tool and as the widget the other GUIs
embed.

## Planned scope

- Paged reading for arbitrarily large files / devices
- Interpreter panel: signed / unsigned ints, floats, all common timestamp
  formats, GUID, RGB
- Search (hex / text / regex), bookmarks, byte-range export
- Importable widget for the suite's `tkinter` GUIs

## Inputs

Any file, image, or device; an offset to seek to.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records
- `--gui` — `tkinter` table / tree viewer (and a self-contained HTML view)

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`utilities_ezview`, `mounting_image`, `memory_image`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
