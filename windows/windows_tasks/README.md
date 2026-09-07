# windows_tasks

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Scheduled Tasks (Tasks XML + TaskCache registry).**

Correlates `C:\Windows\System32\Tasks\**` task XML with the
`SOFTWARE\…\Schedule\TaskCache\{Tree,Tasks}` registry keys into one row per
task: triggers, actions (ExecStart + arguments), principal, hidden flag, author,
and last / next run time; flags suspicious actions.

## Planned scope

- Join TaskCache GUIDs to the on-disk XML; detect orphaned / registry-only tasks
- Decode triggers to plain language; expand action command lines
- Flag LOLBins, user-writable binaries, base64 / encoded commands, hidden tasks
- CSV / JSON; feeds `analysis_timeline`

## Inputs

The `Tasks` directory and the SOFTWARE hive (offline or live).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `linux_cron`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
