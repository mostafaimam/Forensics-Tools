# macos_coreanalytics

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse CoreAnalytics (.core_analytics) app-usage aggregates.**

Reads `/Library/Logs/DiagnosticReports/Analytics*` and the `.core_analytics`
files — daily aggregated app launch counts, foreground durations, crash counts
and hardware / OS context — a compact 'what ran, how long' source spanning
weeks.

## Planned scope

- Parse the newline-delimited JSON aggregate format
- Extract per-app: launches, active time, foreground time, day
- Normalise to a daily usage timeline
- CSV / JSON

## Inputs

`/Library/Logs/DiagnosticReports/Analytics-*/*.core_analytics`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_knowledgec`, `macos_powerlog`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
