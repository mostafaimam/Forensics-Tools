# macos_screentime

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Screen Time app-usage data (RMAdminStore / knowledgeC).**

Reads the Screen Time stores — `RMAdminStore-Local.sqlite` and the Screen Time
streams in `knowledgeC` — for per-app and per-category usage totals by day and
device, including usage synced from other Apple devices on the same account.

## Planned scope

- Decode the usage / category / device tables
- Per-app daily totals; web-domain usage; device attribution
- Apple timestamp conversion
- CSV / JSON

## Inputs

`~/Library/Application Support/Knowledge/` and
`/private/var/folders/**/com.apple.ScreenTimeAgent/`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_knowledgec`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
