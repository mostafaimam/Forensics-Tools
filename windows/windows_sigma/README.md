# windows_sigma

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Lightweight detection-rules engine over parsed event data.**

Runs Sigma-style YAML detection rules (a bundled ruleset, plus `--rule-dir`)
against normalised `windows_evtx` / Sysmon / PowerShell output and reports each
hit with the rule name, level, and matched fields — turning raw event exports
into prioritised leads.

## Planned scope

- Parse the Sigma condition grammar (of / all / 1 of / near) and field modifiers
  (contains / re / base64 / …)
- Map Sigma logsources to the suite's normalised fields
- Bundled starter ruleset; deterministic exit code on hits
- Output feeds `analysis_timeline` / `analysis_report`

## Inputs

CSV / JSON exports from `windows_evtx`, `windows_pslogging`, Sysmon.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_evtx`, `windows_pslogging`, `analysis_report`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
