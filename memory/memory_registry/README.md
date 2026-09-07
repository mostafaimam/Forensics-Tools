# memory_registry

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Locate registry hives in memory and read keys only present in RAM.**

Finds the loaded hives in a Windows memory image (`hivelist`), exports them to
disk, and runs `windows_registry` plugins directly against the in-memory hive —
recovering keys and values that were never flushed to disk.

## Planned scope

- Scan for `_CMHIVE` / `HBASE_BLOCK` (`regf`) signatures; rebuild the hive-list
- Map hive cells through the memory translation layer
- `--dump` a hive to a file; `--plugin` to run a registry plugin live
- Diff in-memory vs. on-disk values

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_registry`, `memory_pslist`, `memory_image`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
