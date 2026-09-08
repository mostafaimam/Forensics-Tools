"""Per-format parsers for firewall / proxy / IDS text logs.

Every parser yields :class:`Event` on one schema.  A format is picked per
file by :func:`detect`; the raw line / record is kept for reference.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Event:
    ts: float | None
    fmt: str                         # iptables | pflog | winfw | squid | zeek | suricata
    action: str = ""                 # allow | deny | drop | reject | alert | info
    proto: str = ""
    src: str = ""
    sport: int = 0
    dst: str = ""
    dport: int = 0
    bytes: int = 0
    direction: str = ""              # in | out | ""
    iface: str = ""
    rule: str = ""                   # rule number / chain / SID
    signature: str = ""              # IDS signature / Squid method+URL
    severity: str = ""               # from the source, if any
    host: str = ""                   # proxy: requested host; fw: log host
    user: str = ""
    message: str = ""
    raw: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "time": _iso(self.ts), "fmt": self.fmt, "action": self.action,
            "proto": self.proto, "src": self.src, "sport": self.sport or "",
            "dst": self.dst, "dport": self.dport or "", "bytes": self.bytes,
            "direction": self.direction, "iface": self.iface,
            "rule": self.rule, "signature": self.signature,
            "severity": self.severity, "host": self.host, "user": self.user,
            "message": self.message, "notable": ";".join(self.notable),
        }


def _iso(ts):
    if ts is None:
        return ""
    return datetime.fromtimestamp(ts, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S") + "Z"


_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"], 1)}


def _syslog_ts(line: str, year: int | None = None) -> float | None:
    m = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        mon = _MONTHS.get(m.group(1))
        if not mon:
            return None
        y = year or datetime.now(timezone.utc).year
        try:
            return datetime(y, mon, int(m.group(2)), int(m.group(3)),
                            int(m.group(4)), int(m.group(5)),
                            tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", line)
    if m:
        try:
            return datetime(*(int(x) for x in m.groups()),
                            tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------
# iptables / nftables kernel log lines
# --------------------------------------------------------------------------

_IPT_KV = re.compile(r"\b([A-Z]+)=(\S*)")
_IPT_ACTION = re.compile(
    r"(BLOCK|DROP|DENY|DENIED|REJECT|ACCEPT|ALLOW|PASS)", re.I)
_IPT_MARK = re.compile(r"(SRC|DST)=\d|IN=\S* OUT=", re.I)


def parse_iptables(text: str):
    for line in text.splitlines():
        if "SRC=" not in line or "DST=" not in line:
            continue
        kv = dict(_IPT_KV.findall(line))
        act = ""
        am = _IPT_ACTION.search(line.split("SRC=")[0])
        if am:
            act = {"block": "deny", "drop": "drop", "deny": "deny",
                   "denied": "deny", "reject": "reject", "accept": "allow",
                   "allow": "allow", "pass": "allow"}[am.group(1).lower()]
        proto = kv.get("PROTO", "").upper()
        pfx = ""
        pm = re.search(r"\]?\s*([A-Za-z0-9 _-]{0,30}?)\s*(?:IN=)", line)
        if pm:
            pfx = pm.group(1).strip(" :[]")
        yield Event(
            ts=_syslog_ts(line[line.find(" ") - 15:] if False else line),
            fmt="iptables", action=act or "info", proto=proto,
            src=kv.get("SRC", ""), dst=kv.get("DST", ""),
            sport=int(kv["SPT"]) if kv.get("SPT", "").isdigit() else 0,
            dport=int(kv["DPT"]) if kv.get("DPT", "").isdigit() else 0,
            bytes=int(kv["LEN"]) if kv.get("LEN", "").isdigit() else 0,
            iface=kv.get("IN") or kv.get("OUT", ""),
            direction="in" if kv.get("IN") else ("out" if kv.get("OUT")
                                                 else ""),
            rule=pfx, message=pfx, raw=line.strip())


# --------------------------------------------------------------------------
# pflog  (tcpdump -tttt -r pflog0 text)
# --------------------------------------------------------------------------

_PF = re.compile(
    r"rule (?P<rule>[\d.]+/\(?\w*\)?|[\d.]+) *(?P<act>pass|block|match|rdr|nat)"
    r" (?P<dir>in|out) on (?P<if>\S+):?\s+"
    r"(?P<src>[0-9a-f:.]+)\.(?P<sport>\d+) > "
    r"(?P<dst>[0-9a-f:.]+)\.(?P<dport>\d+)", re.I)
_PF2 = re.compile(
    r"(?P<act>pass|block|match) (?P<dir>in|out) on (?P<if>\S+):?\s+"
    r"(?P<src>[0-9]+(?:\.[0-9]+){3})\.(?P<sport>\d+) > "
    r"(?P<dst>[0-9]+(?:\.[0-9]+){3})\.(?P<dport>\d+):\s*(?P<flags>\S+)?")


def parse_pflog(text: str):
    for line in text.splitlines():
        m = _PF.search(line) or _PF2.search(line)
        if not m:
            continue
        g = m.groupdict()
        proto = "TCP"
        if "UDP" in line or "udp" in line:
            proto = "UDP"
        elif "icmp" in line.lower():
            proto = "ICMP"
        yield Event(
            ts=_syslog_ts(line), fmt="pflog",
            action={"pass": "allow", "block": "deny",
                    "match": "info"}.get(g["act"].lower(), g["act"].lower()),
            proto=proto, src=g["src"], dst=g["dst"],
            sport=int(g["sport"]), dport=int(g["dport"]),
            direction=g["dir"].lower(), iface=g["if"],
            rule=g.get("rule", ""), raw=line.strip())


# --------------------------------------------------------------------------
# Windows Firewall  pfirewall.log  (W3C)
# --------------------------------------------------------------------------

def parse_winfw(text: str):
    fields: list[str] = []
    for line in text.splitlines():
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
            continue
        if line.startswith("#") or not line.strip():
            continue
        if not fields:
            fields = ["date", "time", "action", "protocol", "src-ip",
                      "dst-ip", "src-port", "dst-port", "size", "tcpflags",
                      "tcpsyn", "tcpack", "tcpwin", "icmptype", "icmpcode",
                      "info", "path", "pid"]
        parts = line.split()
        if len(parts) < len(fields) - 3:
            continue
        rec = dict(zip(fields, parts))
        ts = _syslog_ts(f"{rec.get('date', '')} {rec.get('time', '')}")
        act = rec.get("action", "").lower()
        yield Event(
            ts=ts, fmt="winfw",
            action={"allow": "allow", "drop": "drop",
                    "block": "deny"}.get(act, act or "info"),
            proto=rec.get("protocol", "").upper(),
            src=_na(rec.get("src-ip")), dst=_na(rec.get("dst-ip")),
            sport=_int(rec.get("src-port")), dport=_int(rec.get("dst-port")),
            bytes=_int(rec.get("size")),
            direction=(rec.get("path", "") or "").lower()
            if rec.get("path") in ("SEND", "RECEIVE") else "",
            message=_na(rec.get("path")), raw=line.strip())


# --------------------------------------------------------------------------
# Squid access.log
# --------------------------------------------------------------------------

_SQUID = re.compile(
    r"^(?P<ts>\d{10}\.\d{3})\s+(?P<elapsed>\d+)\s+(?P<client>\S+)\s+"
    r"(?P<code>\S+?)/(?P<status>\d{3})\s+(?P<bytes>\d+)\s+(?P<method>\S+)\s+"
    r"(?P<url>\S+)\s+(?P<user>\S+)\s+(?P<hier>\S+?)/(?P<peer>\S+)\s+"
    r"(?P<ctype>\S+)")


def parse_squid(text: str):
    for line in text.splitlines():
        m = _SQUID.match(line)
        if not m:
            continue
        g = m.groupdict()
        code = g["code"].upper()
        act = ("deny" if "DENIED" in code or g["status"] == "403"
               else "allow")
        host = ""
        mh = re.search(r"://([^/:@]+(?::[^/@]+)?@)?([^/:]+)", g["url"])
        if mh:
            host = mh.group(2)
        yield Event(
            ts=float(g["ts"]), fmt="squid", action=act, proto="HTTP",
            src=g["client"], dst=_na(g["peer"]),
            dport=443 if g["url"].startswith("https") or g["method"]
            == "CONNECT" else 80,
            bytes=int(g["bytes"]), direction="out",
            rule=code, signature=f"{g['method']} {g['url']}"[:400],
            host=host, user=_na(g["user"]),
            message=f"{code}/{g['status']} {g['ctype']}", raw=line.strip())


# --------------------------------------------------------------------------
# Zeek conn.log  (TSV)
# --------------------------------------------------------------------------

def parse_zeek(text: str):
    lines = text.splitlines()
    fields: list[str] = []
    sep = "\t"
    path = "conn"
    for line in lines:
        if line.startswith("#separator"):
            s = line.split(None, 1)[1].strip()
            sep = s.replace("\\x09", "\t").replace("\\t", "\t") or "\t"
            continue
        if line.startswith("#fields"):
            fields = line.split(sep)[1:]
            continue
        if line.startswith("#path"):
            path = line.split()[-1]
            continue
        if line.startswith("#") or not line.strip():
            continue
        if not fields:
            return
        parts = line.split(sep)
        rec = dict(zip(fields, parts))

        def gv(k):
            v = rec.get(k, "")
            return "" if v in ("-", "(empty)") else v

        if path == "conn":
            state = gv("conn_state")
            act = "deny" if state in ("REJ", "S0") else "allow"
            ob = _int(gv("orig_bytes"))
            rb = _int(gv("resp_bytes"))
            yield Event(
                ts=_float(gv("ts")), fmt="zeek", action=act,
                proto=(gv("proto") or "").upper(),
                src=gv("id.orig_h"), sport=_int(gv("id.orig_p")),
                dst=gv("id.resp_h"), dport=_int(gv("id.resp_p")),
                bytes=ob + rb, rule=state,
                signature=gv("service"),
                message=f"{state} orig={ob} resp={rb}", raw=line.strip())
        else:
            yield Event(
                ts=_float(gv("ts")), fmt="zeek", action="info",
                src=gv("id.orig_h") or gv("src"),
                dst=gv("id.resp_h") or gv("dst"),
                signature=path, message=line.strip()[:300], raw=line.strip())


# --------------------------------------------------------------------------
# Suricata eve.json
# --------------------------------------------------------------------------

def parse_suricata(text: str):
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        et = j.get("event_type", "")
        ts = _eve_ts(j.get("timestamp", ""))
        base = dict(
            ts=ts, fmt="suricata", proto=(j.get("proto", "") or "").upper(),
            src=j.get("src_ip", ""), sport=_int(j.get("src_port")),
            dst=j.get("dest_ip", ""), dport=_int(j.get("dest_port")),
            raw=line[:1000])
        if et == "alert":
            al = j.get("alert", {})
            sev = al.get("severity")
            yield Event(action="alert", severity=str(sev) if sev else "",
                        rule=str(al.get("signature_id", "")),
                        signature=al.get("signature", ""),
                        message=al.get("category", ""), **base)
        elif et == "flow":
            fl = j.get("flow", {})
            yield Event(action="info",
                        bytes=_int(fl.get("bytes_toserver"))
                        + _int(fl.get("bytes_toclient")),
                        signature="flow",
                        message=fl.get("state", ""), **base)
        elif et in ("http", "dns", "tls"):
            d = j.get(et, {})
            host = d.get("hostname") or d.get("rrname") or d.get("sni") or ""
            yield Event(action="info", signature=et, host=host,
                        message=(d.get("url") or d.get("rrname")
                                 or d.get("subject") or "")[:400], **base)


# --------------------------------------------------------------------------
# helpers + detection
# --------------------------------------------------------------------------

def _na(v):
    return "" if v in (None, "-", "(none)") else v


def _int(v):
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return 0


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _eve_ts(s: str):
    if not s:
        return None
    s = s.replace("Z", "+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return None


_PARSERS = {
    "iptables": parse_iptables, "pflog": parse_pflog, "winfw": parse_winfw,
    "squid": parse_squid, "zeek": parse_zeek, "suricata": parse_suricata,
}


def detect(head: str, name: str) -> str:
    n = name.lower()
    if head.lstrip().startswith("{") and '"event_type"' in head:
        return "suricata"
    if "#fields" in head and ("id.orig_h" in head or "conn_state" in head):
        return "zeek"
    if "#Version:" in head and "#Fields:" in head and "src-ip" in head:
        return "winfw"
    if re.search(r"^\d{10}\.\d{3}\s+\d+\s+\S+\s+\w+/\d{3}\s", head, re.M):
        return "squid"
    if re.search(r"\bSRC=\d|\bDPT=\d", head) and re.search(
            r"IN=|OUT=|PROTO=", head):
        return "iptables"
    if re.search(r"rule \S+ (pass|block|match) (in|out) on ", head):
        return "pflog"
    if "pfirewall" in n:
        return "winfw"
    if "conn.log" in n:
        return "zeek"
    if "eve" in n and n.endswith(".json"):
        return "suricata"
    if "access.log" in n or "squid" in n:
        return "squid"
    return ""


class LogError(Exception):
    pass


def read(path: str):
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    fmt = detect(text[:8192], p.name)
    if not fmt:
        raise LogError(f"{path}: unrecognised log format")
    yield from _PARSERS[fmt](text)
