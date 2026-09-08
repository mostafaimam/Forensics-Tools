"""Pull DNS events out of captures, resolver-cache dumps and hosts files.

Every source yields :class:`Event` records on one schema so the analyser
does not care where a name resolution came from.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from network_dns import dnsmsg
from network_dns import pcap as _pcap
from network_dns.layers import decode


@dataclass
class Event:
    ts: float | None                 # epoch seconds, or None if unknown
    source: str                      # pcap | displaydns | hosts | resolved
    kind: str                        # query | response | static
    qname: str = ""
    qtype: str = ""
    rcode: str = ""
    client: str = ""
    server: str = ""                 # resolver
    transport: str = ""              # udp | tcp | ""
    answers: list = field(default_factory=list)   # [(type, value, ttl)]
    truncated: bool = False
    edns: bool = False


# --------------------------------------------------------------------------
# pcap / pcapng
# --------------------------------------------------------------------------

def _tcp_dns_payloads(stream: bytes):
    """A TCP/53 stream is length-prefixed DNS messages."""
    i, n = 0, len(stream)
    while i + 2 <= n:
        ln = struct.unpack_from(">H", stream, i)[0]
        if ln == 0 or i + 2 + ln > n:
            break
        yield stream[i + 2:i + 2 + ln]
        i += 2 + ln


def from_pcap(path: str):
    for ts, lt, data in _pcap.read(path):
        pkt = decode(ts, lt, data)
        if not pkt or pkt.proto not in ("UDP", "TCP"):
            continue
        if 53 not in (pkt.sport, pkt.dport):
            continue
        payloads = ([pkt.payload] if pkt.proto == "UDP"
                    else list(_tcp_dns_payloads(pkt.payload)))
        for payload in payloads:
            m = dnsmsg.parse(payload)
            if m is None:
                continue
            server = pkt.src if pkt.sport == 53 else pkt.dst
            client = pkt.dst if pkt.sport == 53 else pkt.src
            yield Event(
                ts=ts, source="pcap",
                kind="response" if m.is_response else "query",
                qname=m.qname, qtype=m.qtype,
                rcode=m.rcode if m.is_response else "",
                client=client, server=server,
                transport=pkt.proto.lower(),
                answers=[(rr.rtype, rr.value, rr.ttl) for rr in m.answers],
                truncated=m.flags_tc, edns=m.edns_udp_size is not None)


# --------------------------------------------------------------------------
# Windows `ipconfig /displaydns`
# --------------------------------------------------------------------------

_DD_NAME = re.compile(r"Record Name[ .]*:\s*(.+?)\s*$", re.I)
_DD_TYPE = re.compile(r"Record Type[ .]*:\s*(\d+)", re.I)
_DD_TTL = re.compile(r"Time To Live[ .]*:\s*(\d+)", re.I)
_DD_SEC = re.compile(r"Section[ .]*:\s*(\w+)", re.I)
_DD_DATA = re.compile(r"(?:Record|"
                      r"A \(Host\)|AAAA|CNAME|PTR|MX|SRV|TXT|NS|SOA)"
                      r"[^:]*:\s*(.+?)\s*$", re.I)
_DD_HEADER = re.compile(r"^\s{2,}(\S.*?)\s*$")


def from_displaydns(path: str):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    # split on the dashed separators that precede each record block
    blocks = re.split(r"\n\s*-{5,}\s*\n", text)
    pending_name = ""
    for blk in blocks:
        name = ""
        rtype = ""
        ttl = 0
        section = ""
        value = ""
        for line in blk.splitlines():
            if (mm := _DD_NAME.search(line)):
                name = mm.group(1).lower()
            elif (mm := _DD_TYPE.search(line)):
                rtype = dnsmsg.type_name(int(mm.group(1)))
            elif (mm := _DD_TTL.search(line)):
                ttl = int(mm.group(1))
            elif (mm := _DD_SEC.search(line)):
                section = mm.group(1).lower()
            elif ":" in line and any(
                    k in line for k in ("Record", "(Host)", "AAAA", "CNAME",
                                        "PTR Record", "MX", "SRV", "TXT",
                                        "NS Record")):
                if (mm := _DD_DATA.search(line)):
                    value = mm.group(1).strip()
        if not name and not value:
            # the block just before a separator is often the bare query name
            for line in reversed(blk.splitlines()):
                if (mm := _DD_HEADER.match(line)) and "." in mm.group(1) \
                        and ":" not in line:
                    pending_name = mm.group(1).strip().lower()
                    break
            continue
        qn = name or pending_name
        if not qn:
            continue
        answers = [(rtype or "A", value, ttl)] if value and \
            section in ("answer", "", "additional") else []
        yield Event(ts=None, source="displaydns", kind="response",
                    qname=qn, qtype=rtype, rcode="NOERROR", answers=answers)
        pending_name = ""


# --------------------------------------------------------------------------
# hosts file
# --------------------------------------------------------------------------

_IP4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IP6 = re.compile(r"^[0-9A-Fa-f:]+:[0-9A-Fa-f:]*$")


def from_hosts(path: str):
    mtime = None
    try:
        mtime = Path(path).stat().st_mtime
    except OSError:
        pass
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or not (_IP4.match(parts[0]) or _IP6.match(parts[0])):
            continue
        ip = parts[0]
        rtype = "AAAA" if ":" in ip else "A"
        for host in parts[1:]:
            yield Event(ts=mtime, source="hosts", kind="static",
                        qname=host.lower(), qtype=rtype, rcode="NOERROR",
                        answers=[(rtype, ip, 0)])


# --------------------------------------------------------------------------
# systemd-resolved  (`resolvectl query` / `systemd-resolve` text)
# --------------------------------------------------------------------------

_RES_LINE = re.compile(
    r"^(?P<name>\S+): (?P<val>\S+).*?-- link:", re.I)


def from_resolved(path: str):
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        m = _RES_LINE.match(raw.strip())
        if not m:
            continue
        val = m.group("val")
        rtype = "AAAA" if ":" in val else "A"
        yield Event(ts=None, source="resolved", kind="response",
                    qname=m.group("name").lower(), qtype=rtype,
                    rcode="NOERROR", answers=[(rtype, val, 0)])


# --------------------------------------------------------------------------
# dispatcher
# --------------------------------------------------------------------------

def read(path: str):
    p = Path(path)
    head = b""
    try:
        with p.open("rb") as fh:
            head = fh.read(4096)
    except OSError as e:
        raise _pcap.PcapError(f"{path}: {e}") from e

    magic = head[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a") \
            or magic == b"\xa1\xb2\x3c\x4d" or magic == b"\x4d\x3c\xb2\xa1":
        yield from from_pcap(path)
        return

    text = head.decode("utf-8", "replace").lower()
    name = p.name.lower()
    if "record name" in text or "displaydns" in text or "record type" in text:
        yield from from_displaydns(path)
    elif "-- link:" in text or name.startswith("resolvectl"):
        yield from from_resolved(path)
    elif name == "hosts" or name.endswith("hosts") or _looks_like_hosts(head):
        yield from from_hosts(path)
    else:
        # last resort: try each text parser, keep whichever yields the most
        best: list = []
        for fn in (from_hosts, from_displaydns, from_resolved):
            try:
                got = list(fn(path))
            except Exception:  # noqa: BLE001
                got = []
            if len(got) > len(best):
                best = got
        yield from best


def _looks_like_hosts(head: bytes) -> bool:
    lines = head.decode("utf-8", "replace").splitlines()
    hits = 0
    for line in lines:
        s = line.split("#", 1)[0].split()
        if len(s) >= 2 and (_IP4.match(s[0]) or _IP6.match(s[0])):
            hits += 1
    return hits >= 2
