# browser_autofill

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Autofill entries, saved profiles and masked payment cards.**

Reads Chromium `Web Data` (`autofill`, `autofill_profiles`, `credit_cards` —
metadata and masked PAN only) and Firefox `formhistory.sqlite`: what the user
typed into forms, saved addresses, and card metadata, with first / last use and
use count.

## Planned scope

- Decode the autofill key/value + date_created / date_last_used / count columns
- Structured address profiles; card metadata (network, last 4, expiry) — never
  full PAN
- Encrypted values only shown with a supplied DPAPI / keychain key
- CSV / JSON

## Inputs

Chromium `Web Data`, Firefox `formhistory.sqlite`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`browser_logins`, `analysis_dpapi`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
