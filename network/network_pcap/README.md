# network_pcap

**Read a packet capture and summarise what happened.** A pure
standard-library reader for classic `pcap` (microsecond *and* nanosecond,
both byte orders) and `pcapng`. It decodes Ethernet / Linux-cooked /
raw-IP / loopback framing down to IPv4 / IPv6 and TCP / UDP / ICMP, then:

* reassembles packets into bidirectional **flows** (5-tuple) with byte and
  packet counts each way, duration and TCP handshake / teardown state;
* extracts **DNS** queries and answers, and **HTTP** request lines, hosts,
  user-agents and response codes;
* **flags** cleartext credentials, plaintext protocols to the internet,
  DNS tunnelling / DGA-style names, port scans and high-egress flows.

![`network_pcap --gui`](docs/screenshot.png)

```
network_pcap capture.pcap
network_pcap traffic.pcapng --dns --notable-only
network_pcap *.pcap --http --grep 'login|admin|\.exe' --csv http.csv
network_pcap c.pcap --flows --host 185.43.99.42 --json flow.json
```

No third-party capture library.

---

## Views

`--flows` (default), `--dns`, `--http` - each with its own columns.

**Flows** — `first_seen`, `last_seen`, `duration_s`, `proto`, `service`
(guessed from the port), `client`, `server`, `server_port`, `packets`,
`bytes`, `bytes_out` / `bytes_in`, `tcp_flags`, `notable`, `severity`.

**DNS** — `time`, `client`, `server`, `query`, `qtype`, `kind`, `rcode`,
`answers` (resolved A / AAAA / CNAME / TXT), `notable`.

**HTTP** — `time`, `client`, `server`, `server_port`, `method`, `url`,
`status` (the response is merged into its request), `content_type`,
`user_agent`, `referer`, `authorization`, `notable`.

CSV is UTF-8 with a BOM and formula-injection safe; `--json` for the same
rows.

---

## What gets flagged

| flag | on |
|---|---|
| `plaintext-<svc>-to-internet` | HTTP / FTP / Telnet / SMTP / POP3 / IMAP to a public IP |
| `smb-to-internet`, `rdp-to-internet`, `mssql-to-internet` … | admin services leaving the network |
| `no-dns-for-dst` | a flow to a public IP that no DNS answer in the capture resolved |
| `long-lived`, `large-egress` | a flow open for over an hour, or the client sending > 25 MB |
| `part of a port scan` / `part of a host sweep` | one source → many ports / many hosts |
| `tunnel-domain` | `*.ngrok.io`, `*.trycloudflare.com`, `*.loca.lt`, … |
| `high-entropy-subdomain`, `long-dns-label`, `txt-record-tunnelling?` | DNS exfiltration / C2 over DNS |
| `suspect-tld:.zip` / `.top` / `.xyz` … | look-alike / abused TLDs |
| `http-basic-auth-cleartext`, `password-in-http-body` | credentials on the wire |
| `http-to-ip-literal`, `scripted-user-agent`, `empty-user-agent` | beacon-shaped HTTP |
| `executable/script download` | `.exe` / `.dll` / `.ps1` / `.hta` / `.iso` over HTTP |

Rows are severity-scored; `--notable-only` and `--min-severity` cut a
million-packet capture down to the handful worth reading.

---

## Framing & protocols

| link type | decoded |
|---|---|
| Ethernet (1), with 802.1Q / QinQ VLAN tags | ✓ |
| raw IPv4 / IPv6 (101), BSD loopback (0 / 108) | ✓ |
| Linux cooked v1 (113) and v2 (276) | ✓ |
| IPv4, IPv6 (+ hop-by-hop / routing / fragment ext headers) | ✓ |
| TCP, UDP, ICMP / ICMPv6, ARP (counted) | ✓ |

---

## Limitations (v0.1)

* **No TCP stream reassembly** - HTTP is read from the first packet of a
  request / response, so a header split across segments, or HTTP/2, is not
  parsed. TLS is only seen as a flow (SNI extraction is planned).
* Only the **first** query / answer of a DNS message is surfaced.
* Beacon-interval detection (regular callbacks to one host) is planned for
  v0.2.
* Gzipped / chunked HTTP bodies are not inflated.
* Object carving (pulling transferred files out of the streams) is a
  separate planned tool (`network_http`).

## Chain of custody

Every run writes a `<output>.manifest.json` sidecar recording the tool version,
the exact command line, `--case-id` / `--examiner` / `--evidence-id`, start and
finish time (UTC), the host, and the **SHA-256 of every input and output file**.
CSV rows carry `evidence_source` / `parser_confidence` / `tz_provenance`
columns; JSON is wrapped as `{"manifest": {...}, "records": [...]}`.
`--no-provenance` disables this. `--max-input-bytes` / `--max-records` /
`--wall-seconds` bound a run against hostile or oversized evidence.

