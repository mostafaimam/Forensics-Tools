# network_flows

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**NetFlow v5/v9 / IPFIX / sFlow record reader and conversation summary.**

Parses exported flow records — NetFlow v5 and v9, IPFIX (with template
handling), and sFlow — into a flow table and rolls them up into conversation and
top-talker summaries with bytes, packets, duration and port profile.

## Planned scope

- v9 / IPFIX template cache; common field (IE) set coverage
- Flow table normalised to the suite's flow schema (shared with `network_pcap`)
- Top talkers, port summary, long / high-volume / beaconing flows
- CSV / JSON

## Inputs

NetFlow / IPFIX / sFlow capture files or exports.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`network_pcap`, `network_logs`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
