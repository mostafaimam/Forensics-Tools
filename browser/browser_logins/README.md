# browser_logins

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Saved-login metadata (origin, username, timestamps) — no passwords.**

Lists saved-login records — origin, username, created / last-used /
password-modified times, and blacklist entries — from Chromium `Login Data` and
Firefox `logins.json` / `key4.db`. Passwords stay encrypted and are never
output.

## Planned scope

- Schema across Chromium versions; Firefox `logins.json` + NSS key DB structure
- Report metadata and the count of stored credentials only
- Optionally verify decryptability given a supplied key — without printing
  secrets
- CSV / JSON

## Inputs

Chromium `Login Data`, Firefox `logins.json` + `key4.db`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_autofill`, `analysis_dpapi`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
