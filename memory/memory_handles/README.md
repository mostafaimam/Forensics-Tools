# memory_handles

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**List open handles per process and the kernel object table.**

Walks the handle table of each process (and the kernel handle table) from a
Windows memory image — files, registry keys, events, sections, mutants, tokens,
threads, processes — resolving each object's name and the granted-access mask.

## Planned scope

- `_HANDLE_TABLE` / `_HANDLE_TABLE_ENTRY` walk with the level-based indirection
- `_OBJECT_HEADER` type index resolution without a profile where possible
- Per-type views; filter by object name substring
- Flag handles to other processes' memory, SAM / SECURITY keys, named pipes

## Inputs

A raw / crash-dump / LiME Windows memory image (via `memory_image`).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_pslist`, `memory_malfind`, `memory_filescan`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
