# macos_spotlight

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the Spotlight metadata store (.spotlight-V100 store.db).**

Reads the Spotlight `store.db` / `.store.db` metadata index — per-file
attributes such as `kMDItemContentType`, `kMDItemWhereFroms`,
`kMDItemLastUsedDate`, and content-creation metadata — which persists even after
files are deleted.

## Planned scope

- Parse the store header, property / category / index blocks
- Reconstruct per-item metadata dictionaries; map item id → path
- Extract `kMDItemWhereFroms` (download URLs), used dates, content types
- CSV / JSON; feeds `analysis_timeline`

## Inputs

`.spotlight-V100/Store-V2/**/store.db` on a volume.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_fsevents`, `macos_quarantine`, `analysis_search`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
