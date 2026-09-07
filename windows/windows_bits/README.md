# windows_bits

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse the BITS transfer history (qmgr.db / qmgr*.dat).**

Reads the Background Intelligent Transfer Service job database — modern
`qmgr.db` (ESE) and legacy `qmgr0/1.dat` — listing download / upload jobs:
remote URL, local path, owner SID, state, bytes, and create / complete times. A
common malware download channel.

## Planned scope

- Legacy binary `qmgr*.dat` record parser and modern ESE schema
- One row per job with all file transfers and URLs
- Flag jobs owned by non-service SIDs, jobs to raw IPs, LOLBin-created jobs

## Inputs

`%ALLUSERSPROFILE%\Microsoft\Network\Downloader\qmgr*.dat` / `qmgr.db`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`windows_esedb`, `windows_evtx`, `network_http`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
