# memory_yara

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Scan process and kernel memory with YARA-style rules.**

Runs YARA-style rules (a bundled minimal matcher — strings, hex patterns,
wildcards, simple conditions — no `yara-python`) against process address spaces
and kernel memory in a dump, reporting the owning process / module and the
physical + virtual address of each hit.

## Planned scope

- Parse a practical subset of the YARA grammar; compile to a scanner
- Per-process VA-space scanning via the translation layer; kernel-range scanning
- Report: rule, process / module, offsets, matched strings
- Bundled starter ruleset for common implants

## Inputs

Any memory image (Windows / Linux / macOS) plus a rules file.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_malfind`, `memory_linux`, `analysis_kff`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
