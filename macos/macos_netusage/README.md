# macos_netusage

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse netusage.sqlite per-process network usage.**

Reads `netusage.sqlite` — per-process cumulative network bytes in / out and
live-connection intervals — showing which binaries used the network and roughly
when.

## Planned scope

- Decode the process, live-usage and network-attachment tables
- Per-process totals and per-interval rows with timestamps
- Flag unexpected binaries with significant egress
- CSV / JSON

## Inputs

`/private/var/networkd/netusage.sqlite`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`macos_powerlog`, `network_pcap`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
