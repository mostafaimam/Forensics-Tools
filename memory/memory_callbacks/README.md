# memory_callbacks

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Enumerate kernel notification callbacks.**

Lists the registered kernel callbacks in a Windows memory image — process /
thread / image-load creation notifications, registry callbacks, bugcheck
callbacks, filesystem / shutdown callbacks — with the owning driver for each; a
primary EDR and rootkit hooking surface.

## Planned scope

- Parse `PspCreateProcessNotifyRoutine`, `PspLoadImageNotifyRoutine`,
  `CmRegisterCallback` lists, etc.
- Resolve each routine to a driver; flag unbacked / suspicious owners
- Note callbacks removed from the array but still resident
- One row per callback: type, routine, module

## Inputs

A Windows memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_timers`, `memory_ssdt`, `memory_dlllist`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
