# memory_linux

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Linux memory-image analysis (process list, modules, network, history).**

Brings the structural memory tools to Linux dumps — task list, loaded kernel
modules (`lsmod`), open network sockets (`netstat`), mount table, `bash` history
in heap, tty buffers, and injected / anonymous executable VMAs — driven by a
bundled per-kernel structure-layout file.

## Planned scope

- Structure-layout files keyed by kernel version / banner; a generator from
  `vmlinux` / `System.map`
- `task_struct` list + orphan scan; `module` list + orphan scan
- Socket enumeration; mount namespace; env / argv / cwd per task
- Anonymous RWX / RX VMA detection for injected code

## Inputs

A raw / LiME / ELF-core Linux memory image (via `memory_image`).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_image`, `memory_malfind`, `memory_yara`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
