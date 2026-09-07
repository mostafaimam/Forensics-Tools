# memory_filescan

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Scan for _FILE_OBJECT structures in a memory image.**

Pool-tag / signature scan for `_FILE_OBJECT` structures across a Windows memory
image, recovering the full file path, device, and the presence of data / image
section objects — the index for `memory_dumpfiles`.

## Planned scope

- `File` pool-tag scan; `_FILE_OBJECT` field validation without a profile
- Resolve the name via `_FILE_OBJECT.FileName` + `_DEVICE_OBJECT` chain
- Note which files have cached data (VACB) or image sections
- Filter by path / extension

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_dumpfiles`, `memory_handles`, `memory_malfind`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
