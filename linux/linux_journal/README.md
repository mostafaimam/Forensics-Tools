# linux_journal

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Read the systemd journal (.journal) binary format.**

A from-scratch reader for systemd journal files: iterates entries, resolves the
data-object hash tables, and filters by any field (`_SYSTEMD_UNIT`, `_PID`,
`PRIORITY`, `_BOOT_ID`, …), with per-boot grouping and monotonic / realtime
timestamps.

## Planned scope

- Parse the journal header, object arrays, entry / data / field objects
- Verify tags where FSS sealing is present; tolerate truncated / corrupt files
- Field filters, boot listing, `--since` / `--until`, priority threshold
- Merge multiple files into one ordered timeline

## Inputs

`/var/log/journal/**/*.journal` and `/run/log/journal` (+ rotated).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_syslog`, `linux_audit`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
