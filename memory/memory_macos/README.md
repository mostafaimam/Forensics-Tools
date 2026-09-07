# memory_macos

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**macOS memory-image analysis (best-effort, version-gated).**

Best-effort structural analysis of macOS memory images — process list, loaded
kexts (`kextstat`), network connections, and the trust cache — using bundled
per-build layout data. Coverage is version-gated and clearly marked as such.

## Planned scope

- `proc` / `task` list via the allproc list and a pool scan
- kext inventory with load address and version
- Network connection enumeration (inpcb / tcpcb)
- Trust-cache dump for injected / unsigned code detection

## Inputs

A macOS memory image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_image`, `memory_linux`, `memory_malfind`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
