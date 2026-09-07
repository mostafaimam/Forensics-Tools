# mobile_iosbackup

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Read iTunes / Finder iOS backups.**

Parses an iOS backup: `Manifest.db` + `Manifest.plist` (domain / relative-path
mapping, decrypting with a supplied backup password), then surfaces the
high-value stores — `sms.db`, `CallHistory.storedata`, `knowledgeC.db`,
`interactionC.db`, `AddressBook`, Safari history, `Photos.sqlite`.

## Planned scope

- Manifest.db file table → real filenames; keybag / class-key unwrap with the
  supplied password
- `--extract` the decrypted file tree by domain
- Built-in maps for the common SQLite stores → messages / calls / contacts / web
  history
- Per-artefact CSV / JSON + a combined timeline

## Inputs

An iOS backup directory (encrypted or not) + the backup password if set.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`mobile_appcommon`, `macos_knowledgec`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
