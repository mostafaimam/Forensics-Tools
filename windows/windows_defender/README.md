# windows_defender

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse Microsoft Defender logs, detection history and quarantine.**

Reads Defender's `MPLog` (scan and RTP activity timeline), the binary
`DetectionHistory` records, `Service\Detections`, and the `Quarantine\` store —
recovering the threat name, original resource path, and (where possible) the
quarantined file itself.

## Planned scope

- MPLog line grammar: process images, loaded resources, detections, RTP stats
- DetectionHistory binary record parser — threat, path, action, user, time
- Quarantine entry decode + `--extract` (RC4-unwrap the stored file)
- One normalised detection timeline

## Inputs

`%PROGRAMDATA%\Microsoft\Windows Defender\{Support,Scans,Quarantine}`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_evtx`, `analysis_timeline`, `analysis_kff`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
