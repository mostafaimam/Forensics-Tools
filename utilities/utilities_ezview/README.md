# utilities_ezview

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Zero-dependency viewer for common document and text formats.**

A standalone viewer for `.txt` / `.log` / `.csv` / `.rtf` / `.htm(l)` / `.mht`
and best-effort `.doc(x)` / `.xls(x)` / `.pdf` text extraction; anything it
can't render opens in the `utilities_hex` widget.

## Planned scope

- Format sniffing by content, not just extension
- Text / CSV table / basic HTML rendering; RTF and MHT decode
- Best-effort OOXML / OLE / PDF text extraction (shared with `utilities_ole`)
- Fallback to the hex/data-interpreter view

## Inputs

A file path (any type).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records
- `--gui` — `tkinter` table / tree viewer (and a self-contained HTML view)

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`utilities_hex`, `utilities_ole`, `analysis_view`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
