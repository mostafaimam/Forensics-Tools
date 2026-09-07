# macos_installhistory

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse InstallHistory.plist and /var/db/receipts.**

Lists software installation events from `InstallHistory.plist` (display name,
version, process, date, package identifiers) and cross-references the
`/var/db/receipts/*.plist` + `*.bom` receipts for the file lists each package
placed on disk.

## Planned scope

- Parse InstallHistory entries; normalise to (date, name, version, installer,
  packages)
- BOM (bill-of-materials) reader for per-package file lists
- Flag installs by non-Apple installers, re-installs, MDM-pushed packages
- Timeline + JSON

## Inputs

`/Library/Receipts/InstallHistory.plist` and `/var/db/receipts/**`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_plist`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
