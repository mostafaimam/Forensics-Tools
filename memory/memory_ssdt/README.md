# memory_ssdt

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Inspect the SSDT / IDT and driver IRP tables for hooks.**

Dumps the System Service Descriptor Table, the Interrupt Descriptor Table, and
the major-function (IRP) tables of key drivers from a Windows memory image,
flagging entries that point outside the expected module — classic kernel
hooking.

## Planned scope

- Locate `KeServiceDescriptorTable` (+ shadow); resolve each entry to a module
- IDT per-processor dump; driver `MajorFunction[]` table dump
- Flag pointers into unknown / unbacked memory or the wrong module
- Baseline comparison against expected owners

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_callbacks`, `memory_timers`, `memory_malfind`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
