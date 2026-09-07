# windows_spooler

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse print-spool artefacts (.spl / .shd).**

Reads the print spool files left in `C:\Windows\System32\spool\PRINTERS` — the
`.shd` job header (document name, owner, machine, printer, timestamps) and the
`.spl` data — and renders EMF / XPS spool content back to viewable pages where
possible.

## Planned scope

- Parse the SHD structure across Windows versions
- EMF record walk / XPS (ZIP) extraction of the printed content
- Job timeline: submitted, owner, pages, printer
- `--extract` rendered pages / raw spool

## Inputs

`*.shd` / `*.spl` files (live or carved).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`recovery_carve`, `analysis_gallery`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
