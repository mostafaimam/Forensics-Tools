# browser_downloads

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Download history: source URL, referrer, target path, danger flag.**

Lists every recorded file download across the Chromium family, Firefox and
Safari — source and referring URL, saved path, byte count, danger /
safe-browsing verdict, start / end time — and cross-references `.crdownload` /
`.part` leftovers and NTFS `:Zone.Identifier` streams.

## Planned scope

- Per-browser schema handling; merge into one schema across browsers
- Join to on-disk files and Zone.Identifier / quarantine provenance
- Flag executables / archives / scripts and downloads from raw IPs
- Timeline + JSON; feeds `analysis_timeline`

## Inputs

Chromium `History`, Firefox `places.sqlite` / `downloads.sqlite`, Safari
`History.db`, plus the download folder.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_history`, `windows_usbdevices`, `macos_quarantine`,
`analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
