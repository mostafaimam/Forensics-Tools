# mounting_partitions

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Map the partition layout of a disk image (no mounting).**

A read-only inspector that prints the full container and partition layout of a
disk image: MBR, GPT, BSD disklabels, APFS containers, and LVM2 physical volumes
/ volume groups / logical volumes. Layout only — mounting lives in
`mounting_image` and `mounting_vsc`.

## Planned scope

- MBR (incl. extended / logical chains) and GPT (with backup-header check)
- APFS container superblock → volume roles, sizes, encryption state
- LVM2 metadata → PV / VG / LV geometry and segment maps
- One normalised row per volume: start, length, type, filesystem hint, flags

## Inputs

Raw / split / EWF / VHD / VMDK disk images.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mounting_image`, `mounting_vsc`, `recovery_fs`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
