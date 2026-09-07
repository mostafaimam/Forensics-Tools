# windows_recentfilecache

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse RecentFileCache.bcf.**

Reads `RecentFileCache.bcf` (the pre-Amcache program-execution artefact on
Windows 7) and lists the executables it recorded, with the file reference and
recovered path.

## Planned scope

- Parse the BCF header and the length-prefixed UTF-16 path records
- One row per executable: path, derived name
- Cross-reference with `windows_amcache` / `windows_shimcache` output

## Inputs

`C:\Windows\AppCompat\Programs\RecentFileCache.bcf`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_amcache`, `windows_shimcache`, `windows_prefetch`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
