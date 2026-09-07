# cloud_azuread

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Entra ID (Azure AD) sign-in and audit logs.**

Normalises Entra ID sign-in logs (interactive, non-interactive, service
principal, managed identity) and directory audit logs from JSON exports — user,
app, IP, location, device, conditional-access result, MFA detail, and the risk
state.

## Planned scope

- Sign-in schema: status codes, CA policies, auth methods, device / client app
- Audit schema: activity, initiator, target resources, modified properties
- Flag legacy-auth sign-ins, impossible travel, new-country, risky sign-ins
- Timeline + JSON

## Inputs

Entra ID log JSON exports (portal / Graph / Log Analytics).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`cloud_m365ual`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
