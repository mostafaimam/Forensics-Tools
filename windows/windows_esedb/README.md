# windows_esedb

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Generic ESE / JET (.edb) database reader.**

A standalone, dependency-free ESE (Extensible Storage Engine) reader used by
`windows_srum`, `windows_webcache`, `windows_sum` and Windows Search
(`Windows.edb`). Dumps catalogue, tables, and rows; recovers data from dirty
databases where possible.

## Planned scope

- Parse the database header, catalogue (MSysObjects), B-trees, long values
- Column types incl. multi-valued and tagged columns
- Dirty-database recovery: replay / tolerate an unclean shutdown
- `list-tables`, `dump <table>`, CSV / JSON per table

## Inputs

Any `.edb` / ESE database (SRUDB, WebCacheV01, Windows.edb, `*.mdb` UAL, …).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_srum`, `windows_webcache`, `windows_sum`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
