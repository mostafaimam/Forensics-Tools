# mounting_vsc

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Enumerate and mount every Volume Shadow Copy on a volume.**

Lists the Volume Shadow Copies present on a disk image or live volume and mounts
a chosen snapshot (or all of them) read-only to a drive letter / mount point, so
the other parsers can run against a point-in-time view of the file system.

## Planned scope

- Parse the VSS catalogue and store: snapshot id, creation time, originating
  volume, size, provider
- Reconstruct a snapshot's block map and expose it as a read-only device /
  folder without copying the whole volume
- Mount one snapshot, a range, or all; unmount cleanly
- Feed a mounted snapshot straight into `mounting_image` / `recovery_metadata`

## Inputs

A raw / EWF / VHD image or a live volume; the VSS store on it.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records
- `--gui` — `tkinter` table / tree viewer (and a self-contained HTML view)

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mounting_image`, `recovery_fs`, `windows_mft`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
