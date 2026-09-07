# cloud_m365ual

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Normalise the Microsoft 365 Unified Audit Log.**

Parses M365 Unified Audit Log exports (CSV or JSON, including the nested
`AuditData`) and normalises the disparate workload schemas — Exchange,
SharePoint / OneDrive, Entra ID, Teams — into one activity row per event with
actor, IP, target and result.

## Planned scope

- Flatten `AuditData` JSON; per-workload field mapping to a common schema
- Operation grouping (mailbox access, file ops, sign-ins, admin changes)
- Flag risky operations: mailbox rules, app consent, role grants, mass download
- Timeline + JSON; feeds `analysis_report`

## Inputs

UAL exports from the Purview portal / `Search-UnifiedAuditLog`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`cloud_azuread`, `analysis_timeline`, `analysis_report`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
