# utilities_strings

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**String extraction with a built-in forensic regex library.**

Extracts ASCII and UTF-16 (LE / BE) strings from any file or device, with offset
output and a built-in library of forensic patterns — URLs, emails, IPs, GUIDs,
registry paths, base64 runs, credit-card / key material — and is aware of locked
files on Windows.

## Planned scope

- Configurable minimum length; encoding selection; offset in dec / hex
- `--pattern <name>` / `--category` to filter to the built-in regex library
- Raw-device and volume-shadow-aware reads
- CSV / JSON with offset, encoding, match category

## Inputs

Any file, image, or device (`\\.\C:` / `/dev/sdX`).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`memory_strings`, `analysis_search`, `utilities_hex`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
