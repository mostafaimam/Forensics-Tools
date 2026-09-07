# cloud_cloudtrail

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Normalise AWS CloudTrail logs into events and summaries.**

Parses CloudTrail JSON (files, `.json.gz`, or an S3 export tree) into one row
per API call — identity, source IP, region, service, action, resources, error
code — with actor, source-IP and API-usage summaries and highlighting of
high-risk actions.

## Planned scope

- Iterate `Records[]`; flatten `userIdentity`, `requestParameters`,
  `responseElements`
- Assumed-role chain resolution; session-context attribution
- Flag IAM changes, `ConsoleLogin` without MFA, `GetSecretValue`, public-ACL /
  policy changes, `Delete*` bursts
- Timeline + summaries; JSON

## Inputs

CloudTrail `*.json` / `*.json.gz` files or an export directory.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`cloud_gws`, `analysis_timeline`, `analysis_report`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
