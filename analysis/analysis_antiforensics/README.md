# analysis_antiforensics

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Correlate anti-forensic and tampering indicators into one report.**

A single report that pulls together evidence of evidence-destruction: event-log
clearing (1102 / 104) and gaps, `$LogFile` / `$UsnJrnl` truncation, timestomping
($SI vs $FN, zeroed sub-seconds), secure-wipe traces, disabled Prefetch / SRUM /
Amcache, known wiping-tool artefacts, VM / sandbox indicators, and recent mass
deletions.

## Planned scope

- Consume the other tools' CSV / JSON rather than re-parsing artefacts
- Each indicator: description, supporting evidence, confidence, timestamp(s)
- Timeline-gap detection across log sources
- Self-contained HTML + JSON report

## Inputs

Outputs from `windows_evtx`, `windows_mft`, `windows_usn`, `windows_registry`,
`windows_prefetch`, `windows_amcache`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_evtx`, `windows_mft`, `analysis_timeline`, `analysis_report`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
