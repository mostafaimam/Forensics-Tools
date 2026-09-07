# windows_bam

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Background Activity Moderator / DAM last-execution data.**

Reads `SYSTEM\…\bam\State\UserSettings\<SID>` (and DAM) for the last-execution
time of each binary per user — a compact, reliable program-execution artefact on
Windows 10 1709+.

## Planned scope

- Enumerate per-SID value lists; decode the 8-byte FILETIME payload
- Resolve the SID to a username via SAM / SOFTWARE
- One row per (user, executable, last-run)
- Confirm overlap / gaps vs. Prefetch, Amcache, ShimCache

## Inputs

The SYSTEM hive (offline or live).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `windows_prefetch`, `windows_amcache`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
