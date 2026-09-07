# cloud_gws

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Google Workspace admin / login / Drive audit activity.**

Normalises Google Workspace audit exports (Admin console, Login, Drive, Token /
OAuth) into one activity schema — actor, IP, application, event, target — with
OAuth-grant and sharing-change highlighting.

## Planned scope

- Per-application event mapping (login, drive, admin, token, groups)
- Actor / IP / target normalisation; parameter flattening
- Flag third-party OAuth grants, external sharing, admin-role changes,
  suspicious-login events
- Timeline + JSON

## Inputs

Workspace audit CSV / JSON exports (Reports API or console).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`cloud_cloudtrail`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
