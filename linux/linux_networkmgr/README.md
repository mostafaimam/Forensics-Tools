# linux_networkmgr

> **Status — planned.** This directory is a specification stub; the tool is
> not implemented yet. The design below is the contract it will be built to and
> may be refined during development.

**Parse NetworkManager profiles, wpa_supplicant and network config.**

Collects saved network configuration and connection history: NetworkManager
connection profiles and logs, `wpa_supplicant` known networks, `/etc/hosts`,
`resolv.conf`, netplan / ifupdown / systemd-networkd — IP / DNS / proxy settings
and which networks the host has joined.

## Planned scope

- NetworkManager keyfile / ifcfg profiles: SSID, BSSID, security, autoconnect,
  timestamps
- wpa_supplicant.conf known networks and PSK presence (never output)
- Static DNS / proxy / hosts overrides
- Timeline of last-connected where logged

## Inputs

A mounted Linux image or live system.

## Outputs

- Human-readable summary on stdout
- `--csv PATH` — UTF-8 with BOM, spreadsheet-injection-safe
- `--json PATH` — structured records

All timestamps UTC (ISO-8601). Exit code is non-zero when nothing is found or
(where applicable) when a flagged item is present.

## Related tools

`linux_syslog`, `linux_journal`, `analysis_timeline`.

---

Part of **Forensics Tools** — Python 3.11+, standard library only,
cross-platform, read-only. See the [top-level README](../../README.md).
