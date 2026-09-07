# recovery_fs

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Generic read-only file-system walker (NTFS / FAT / exFAT / ext / HFS+ / APFS).**

One engine that walks any supported file system read-only: list files (allocated
and deleted), extract by path or inode, and emit a MACB timeline bodyfile for
`analysis_timeline`. Shares the metadata engine with `recovery_metadata`.

## Planned scope

- Pluggable per-filesystem back ends behind one API
- Recursive listing with allocation state, size, and all four timestamps
- Extract a file, a directory tree, or slack / unallocated
- Bodyfile + JSON output; `--deleted-only`, path globs

## Inputs

A partition image or whole-disk image (with `--offset` / auto-detect), or a live
volume.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`recovery_metadata`, `recovery_carve`, `analysis_timeline`, `mounting_image`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
