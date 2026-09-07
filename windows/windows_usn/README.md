# windows_usn

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Standalone $UsnJrnl:$J parser / carver.**

Parses the NTFS USN change journal (`$Extend\$UsnJrnl:$J`) into a file-system
change timeline — create, rename, data / metadata change, delete — and carves
USN records out of unallocated space or a raw image when the journal itself is
gone.

## Planned scope

- USN_RECORD v2/v3/v4; reason-flag decoding; parent-reference path rebuild
- Sparse-region aware (skip the zeroed head of $J)
- Signature-based carving mode for orphaned records
- Bodyfile + JSON; merge with `windows_mft`

## Inputs

`$UsnJrnl:$J` (extracted), a partition image, or a raw dump for carving.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_mft`, `windows_logfile`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
