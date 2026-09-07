# analysis_enrich

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Post-process a timeline bundle: IOC match, ATT&CK tags, geo, known-file.**

Takes an `analysis_timeline` bundle and enriches every event: match IOCs /
hashes / domains / IPs against supplied feeds, tag events with MITRE ATT&CK
technique ids from a bundled mapping, resolve GPS coordinates to place names
from an offline gazetteer, and mark known-good vs. unknown via `analysis_kff`.

## Planned scope

- Pluggable enrichers, each adding columns rather than rewriting rows
- IOC feed formats: plain lists, CSV, STIX-lite JSON
- Bundled ATT&CK technique map keyed by artefact / command patterns
- Offline reverse-geocoding gazetteer

## Inputs

An `analysis_timeline` JSON bundle plus optional IOC feeds / gazetteer.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`analysis_timeline`, `analysis_kff`, `analysis_report`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
