# network_logs

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Normalise firewall / proxy / IDS text logs into one schema.**

One normaliser for the common network-log formats — iptables / nftables, pf,
Windows Firewall, Squid, Zeek (`conn.log` and friends), Suricata `eve.json` —
emitting a single flow / event schema that feeds `analysis_timeline` and
correlates with pcap-derived data.

## Planned scope

- Per-format parsers behind one output schema (ts, src, dst, ports, proto,
  action, bytes, verdict)
- Zeek TSV header handling; Suricata event-type routing (alert / http / dns /
  flow)
- Alert / block views; `--min-severity`
- CSV / JSON

## Inputs

Firewall / proxy / IDS log files (text, TSV, JSON).

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`network_flows`, `network_pcap`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
