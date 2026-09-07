# mobile_android

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Read adb backups and logical Android copies.**

Handles `adb backup` archives (`.ab` → tar, with the optional password /
compression) and logical-copy directory trees: discovers app `databases/`, and
parses `accounts.db`, the call log and SMS (`mmssms.db` / `calllog.db`),
`usagestats`, and bug reports.

## Planned scope

- `.ab` header handling (none / AES / deflate) → tar extraction
- Recursive app-database discovery; per-app map application
- usagestats XML / protobuf decode; contacts / calls / SMS normalisation
- Per-artefact CSV / JSON + combined timeline

## Inputs

An `.ab` file or a logical extraction directory.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mobile_appcommon`, `app_chat`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
