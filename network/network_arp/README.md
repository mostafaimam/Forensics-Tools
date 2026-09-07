# network_arp

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**IP ↔ MAC ↔ hostname ↔ time mapping from ARP and DHCP data.**

Builds an address-mapping timeline from ARP / neighbour tables and DHCP lease
data — `dhcpd.leases`, Windows DHCP audit logs, `ip neigh` / `arp -a` dumps, and
ARP frames in a pcap — answering 'which host had this IP at this time'.

## Planned scope

- ISC `dhcpd.leases` grammar; Windows DHCP audit format; neighbour-table parsers
- ARP frame extraction (reuse `network_pcap` layers)
- Per-lease / per-binding rows: IP, MAC, hostname, start, end, vendor (OUI)
- Conflict detection (same IP, different MAC); CSV / JSON

## Inputs

`dhcpd.leases`, DHCP audit CSV, ARP-table text dumps, `.pcap`.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`network_pcap`, `network_dns`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
