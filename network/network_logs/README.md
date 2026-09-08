# network_logs

**One schema for every network log.** `network_logs` reads the common
firewall, proxy and IDS text formats and normalises them to a single
flow / event row — time, source, destination, ports, protocol, action, bytes,
and the rule or signature — so a mixed pile of logs becomes one sortable,
filterable timeline that drops straight into `analysis_timeline`.

Formats recognised (auto-detected per file):

| format | source |
|--------|--------|
| **iptables / nftables** | kernel `SRC=… DST=… PROTO=… DPT=…` log lines (UFW, `LOG` target) |
| **pflog** | `tcpdump -r pflog` text (`rule …/(match) block in on …`) |
| **Windows Firewall** | `pfirewall.log` (W3C `#Fields:` header) |
| **Squid** | `access.log` (native format) |
| **Zeek** | `conn.log` and other TSV logs (`#separator` / `#fields` header) |
| **Suricata** | `eve.json` (`alert`, `flow`, `http`, `dns`, `tls` events) |

![network_logs GUI](docs/screenshot.png)

## Usage

```
network_logs /var/log/ufw.log
network_logs conn.log eve.json pfirewall.log --csv events.csv
network_logs *.log --notable-only --min-severity high
network_logs access.log --action deny --src 10.0.0.66
network_logs eve.json --grep 'cobalt|beacon'
network_logs *.log --gui
```

| flag | effect |
|------|--------|
| `--action` | `allow` / `deny` / `drop` / `reject` / `alert` / `info` |
| `--src IP` / `--dst IP` / `--port N` | endpoint filters |
| `--fmt NAME` | only events from one log format |
| `--grep REGEX` | match the signature / message / requested host |
| `--notable-only` / `--min-severity` | filter by the flags raised |
| `--csv PATH` / `--json PATH` | write the table instead of the text report |
| `--gui` | open the graphical viewer |

The text report prints cross-log **findings** (blocked-event bursts, port
sweeps, IDS-alert counts) above the event list.

## Why it matters

The firewall, the proxy and the IDS each see a different slice of the same
traffic and each writes it differently. Normalising them lets you sort one
timeline by time, pivot on a source address across all three, and line the
result up against `network_pcap` / `network_flows` output.

## Flags

| flag | meaning |
|------|---------|
| `IDS alert (severity N): …` | a Suricata alert (severity 1–2 → high) |
| `blocked inbound connection from a public address` | a deny/drop from a routable source to a service port |
| `connection to a commonly-abused port (N)` | an *allowed* flow to 4444 / 1337 / 6667 / … |
| `credentials embedded in a proxied URL` | `http://user:pass@host/…` in a Squid line |
| `request to a raw-IP host (no domain)` | proxied request whose host is a bare public IP |
| `large proxy transfer (N MB)` | a Squid response of 50 MB or more |
| `allowed outbound to a public host on port N` | egress on a non-standard port |
| `part of a blocked-event burst from X` | the source generated 20+ blocked events |

## Limitations (v0.1)

- **Text formats only.** Binary `pflog` must be rendered to text first
  (`tcpdump -r`); `nfcapd` and native Zeek binary logs are out of scope.
- syslog-style lines carry no year — the current year is assumed.
- The iptables parser keys on `SRC=`/`DST=`/`PROTO=` and a leading action
  word (`BLOCK` / `DROP` / `ACCEPT` / …); an unusual `--log-prefix` may not
  classify the action.
- Squid parsing targets the native `access.log` format, not a custom
  `logformat`.

## Chain of custody

Every run writes a `<output>.manifest.json` sidecar recording the tool version,
the exact command line, `--case-id` / `--examiner` / `--evidence-id`, start and
finish time (UTC), the host, and the **SHA-256 of every input and output file**.
CSV rows carry `evidence_source` / `parser_confidence` / `tz_provenance`
columns; JSON is wrapped as `{"manifest": {...}, "records": [...]}`.
`--no-provenance` disables this. `--max-input-bytes` / `--max-records` /
`--wall-seconds` bound a run against hostile or oversized evidence.

## Tests

```
cd network/network_logs && python -m pytest -q
```

Fixture logs for every format exercise the parsers, the per-event flags, the
cross-event findings (blocked bursts), multi-file merge / sort and the CLI.
