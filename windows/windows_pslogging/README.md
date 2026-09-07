# windows_pslogging

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**PowerShell forensics: ScriptBlock, Module logging and transcripts.**

Reassembles PowerShell ScriptBlock logging (event 4104) across its multi-part
records, pulls Module logging (4103) and pipeline events, and parses on-disk
`PowerShell_transcript.*` files — then decodes base64 / gzip / `-EncodedCommand`
payloads found inside.

## Planned scope

- Order and concatenate 4104 fragments into complete scripts
- Decode `-enc`, `FromBase64String`, `GzipStream`, `IEX (New-Object …)`
- Flag download cradles, AMSI bypass strings, obfuscation markers
- Per-script output with host, user, time; feeds `analysis_report`

## Inputs

`Microsoft-Windows-PowerShell/Operational.evtx`, `Windows PowerShell.evtx`,
transcript files.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_evtx`, `windows_wmi`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
