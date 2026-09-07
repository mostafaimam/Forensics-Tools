# memory_timers

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Enumerate kernel timers (KTIMER) from a memory image.**

Walks the kernel timer table of a Windows memory image, resolving each
`_KTIMER`'s DPC routine and owning module — a persistence and stealth-execution
surface used by rootkits to schedule code without a thread.

## Planned scope

- Locate `KiTimerTableListHead` / per-processor timer tables
- Resolve the DPC routine address to a module (or flag 'unknown / unbacked')
- Report due time, period, and associated DPC
- Flag timers whose routine is outside any loaded driver

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_callbacks`, `memory_ssdt`, `memory_malfind`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
