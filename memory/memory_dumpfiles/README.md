# memory_dumpfiles

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Reconstruct file contents from the memory cache manager.**

Rebuilds file contents from a Windows memory image using the cache manager's
VACB structures and the shared-cache / image section objects — recovering
documents, scripts and executables that were open or recently accessed, straight
from RAM.

## Planned scope

- Walk the VACB array / shared cache map for a `_FILE_OBJECT`'s data sections
- Reassemble sparse cached pages (mark gaps); dump data and/or image sections
- `--pid` / `--path` / `--physaddr` selection
- SHA-256 every reconstructed file

## Inputs

A Windows memory image (+ a `memory_filescan` result).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_filescan`, `memory_malfind`, `analysis_kff`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
