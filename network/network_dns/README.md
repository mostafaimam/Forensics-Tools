# network_dns

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**DNS activity from captures, OS resolver caches and hosts files.**

Consolidates DNS evidence: queries and answers carved from a pcap, the live OS
resolver cache (`ipconfig /displaydns` text, `systemd-resolved`), and `hosts`
files — into one name-resolution timeline, flagging tunnelling, DGA-looking
names, and suspicious record types.

## Planned scope

- Reuse `network_pcap`'s DNS decoder; add cache / hosts parsers
- Per-name rows: first / last seen, query types, answers, TTLs, resolver
- Flag long TXT / NULL responses, high-entropy labels, fast-flux answer churn,
  hosts-file overrides
- CSV / JSON; feeds `analysis_timeline`

## Inputs

`.pcap` / `.pcapng`, resolver-cache text dumps, `hosts` files.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`network_pcap`, `network_arp`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
