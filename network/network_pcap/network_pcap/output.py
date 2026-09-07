"""Row shaping and CSV / JSON writers for each view."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from network_pcap import flags as _flags

FLOW_COLUMNS = ["first_seen", "last_seen", "duration_s", "proto", "service",
                "client", "server", "server_port", "packets", "bytes",
                "bytes_out", "bytes_in", "tcp_flags", "notable", "severity"]
DNS_COLUMNS = ["time", "client", "server", "query", "qtype", "kind", "rcode",
               "answers", "notable", "severity"]
HTTP_COLUMNS = ["time", "client", "server", "server_port", "method", "url",
                "status", "content_type", "user_agent", "referer",
                "authorization", "notable", "severity"]
PACKET_COLUMNS = ["time", "proto", "src", "sport", "dst", "dport", "length",
                  "tcp_flags", "info"]


def _iso(ts: float) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (OverflowError, OSError, ValueError):
        return ""


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def flow_row(f) -> dict:
    return {
        "first_seen": _iso(f.first_ts), "last_seen": _iso(f.last_ts),
        "duration_s": f.duration, "proto": f.proto,
        "service": f.service or "", "client": f.client_ip,
        "server": f.server_ip,
        "server_port": (f.b_port if f.server_ip == f.b_ip else f.a_port) or "",
        "packets": f.packets, "bytes": f.bytes,
        "bytes_out": f.egress_bytes, "bytes_in": f.bytes - f.egress_bytes,
        "tcp_flags": "".join(sorted(f.tcp_flags)),
        "notable": ";".join(f.notable),
        "severity": _flags.severity(f.notable),
    }


def dns_row(d) -> dict:
    return {
        "time": _iso(d.ts), "client": d.client, "server": d.server,
        "query": d.query, "qtype": d.qtype,
        "kind": "response" if d.response else "query",
        "rcode": d.rcode,
        "answers": ", ".join(f"{t}={v}" for t, v in d.answers if v),
        "notable": ";".join(d.notable), "severity": _flags.severity(d.notable),
    }


def http_row(h) -> dict:
    return {
        "time": _iso(h.ts), "client": h.client, "server": h.server,
        "server_port": h.server_port, "method": h.method, "url": h.url,
        "status": h.status or "", "content_type": h.content_type,
        "user_agent": h.user_agent, "referer": h.referer,
        "authorization": h.authorization,
        "notable": ";".join(h.notable), "severity": _flags.severity(h.notable),
    }


def _writer(rows, cols, path: Path):
    with Path(path).open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: _san(r.get(k, "")) for k in cols})


def write_csv(rows, cols, path):
    _writer(rows, cols, path)


def write_json(rows, path):
    Path(path).write_text(json.dumps(list(rows), indent=2), encoding="utf-8")


def render_flows(rows) -> str:
    out = io.StringIO()
    out.write(f"{'START':<24} {'DUR':>8} {'PROTO':<5} {'SERVICE':<10} "
              f"{'CLIENT':<22} -> {'SERVER':<22} {'PKTS':>6} {'BYTES':>10}\n")
    out.write("-" * 130 + "\n")
    for r in rows:
        sp = f":{r['server_port']}" if r['server_port'] else ""
        out.write(f"{r['first_seen']:<24} {r['duration_s']:>8} "
                  f"{r['proto']:<5} {r['service']:<10} "
                  f"{r['client']:<22} -> {r['server'] + sp:<22} "
                  f"{r['packets']:>6} {r['bytes']:>10}")
        if r['notable']:
            out.write(f"   [{r['severity']}] {r['notable']}")
        out.write("\n")
    return out.getvalue()


def render_dns(rows) -> str:
    out = io.StringIO()
    for r in rows:
        if r["kind"] != "query":
            continue
        line = f"{r['time'][:23]:<24} {r['client']:<22} {r['qtype']:<6} " \
               f"{r['query']}"
        ans = next((x for x in rows if x["query"] == r["query"]
                    and x["kind"] == "response"), None)
        if ans and ans["answers"]:
            line += f"  ->  {ans['answers']}"
        if r["notable"]:
            line += f"   [{r['severity']}] {r['notable']}"
        out.write(line + "\n")
    return out.getvalue()


def render_http(rows) -> str:
    out = io.StringIO()
    for r in rows:
        line = f"{r['time'][:23]:<24} {r['client']:<18} {r['method']:<7} " \
               f"{r['url']}"
        if r["status"]:
            line += f"  ({r['status']})"
        out.write(line + "\n")
        if r["user_agent"]:
            out.write(f"{'':25}UA: {r['user_agent']}\n")
        if r["notable"]:
            out.write(f"{'':25}! {r['notable']}\n")
    return out.getvalue()
