# linux_units

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Inventory systemd unit files and review persistence.**

Collects every systemd unit — `/etc/systemd`, `/usr/lib/systemd`,
`/run/systemd`, user units, and drop-ins — and produces one row per unit:
`ExecStart*`, `Type`, `WantedBy`, enabled state, and the drop-in / override
chain, flagging suspicious execs and unit locations.

## Planned scope

- Merge base unit + `*.conf` drop-ins + symlink enable state
- Flag units in `/tmp` / user-writable paths, `curl|sh` execs, transient units
- Resolve `WantedBy` / `RequiredBy` to the effective boot targets
- Feeds `linux_persistence`

## Inputs

A mounted Linux image or live system.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_persistence`, `linux_cron`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
