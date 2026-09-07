# windows_logfile

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Analyse the NTFS $LogFile transaction log.**

Parses `$LogFile` — the NTFS journal — into recent metadata transactions: file
create / rename / delete, MFT record and index changes that have not yet reached
`$UsnJrnl`, giving the finest-grained view of very recent file-system activity.

## Planned scope

- Parse RSTR restart areas and RCRD record pages; redo / undo op-code decode
- Reconstruct high-level operations (create file, set name, delete) from the op
  stream
- Correlate LSNs with `$MFT` and `$UsnJrnl`
- Bodyfile + JSON

## Inputs

`$LogFile` (extracted) or a partition image.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_mft`, `windows_usn`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
