# macos_tcc

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the TCC.db privacy-permission database.**

Reads the system and per-user `TCC.db` (Transparency, Consent and Control) —
which applications were granted or denied access to Camera, Microphone, Full
Disk Access, Accessibility, Automation, etc. — with the decision, prompt count,
and last-modified time.

## Planned scope

- Decode the `access` table across schema versions; service-name mapping
- Resolve client bundle id / path; indirect (Automation) target apps
- Flag Full Disk Access / Accessibility grants to non-Apple / user binaries
- CSV / JSON

## Inputs

`/Library/Application Support/com.apple.TCC/TCC.db` and the per-user copy.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_plist`, `macos_launchd`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
