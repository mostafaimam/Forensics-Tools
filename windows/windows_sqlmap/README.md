# windows_sqlmap

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Locate SQLite databases in a target and process them with named maps.**

Finds SQLite databases anywhere in a mounted image or folder tree and runs named
extraction maps against them — each map is per-artefact SQL plus column
definitions — producing normalised CSV / JSON. A generic engine for the long
tail of app databases.

## Planned scope

- Recursive SQLite discovery by header magic (not just extension)
- Map format: match rules (filename / schema), queries, column types, timestamp
  conversions
- Bundled maps for common artefacts; `--map-dir` for user maps
- WAL-aware read-only opening

## Inputs

A mounted image / directory tree; a map directory.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_esedb`, `analysis_search`, `app_chat`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
