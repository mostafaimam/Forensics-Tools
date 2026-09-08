"""Pull IP<->MAC observations out of leases, neighbour tables and captures."""

from __future__ import annotations

import csv as _csv
import io
import re
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from network_arp import oui
from network_arp import pcap as _pcap


@dataclass
class Obs:
    ts: float | None
    ip: str
    mac: str
    source: str                      # dhcpd | windhcp | arptable | pcap-arp | pcap-passive
    hostname: str = ""
    iface: str = ""
    kind: str = ""                   # lease | renew | release | request | reply | gratuitous | neighbour | passive
    state: str = ""


class ArpError(Exception):
    pass


# --------------------------------------------------------------------------
# ISC dhcpd.leases
# --------------------------------------------------------------------------

_LEASE = re.compile(r'lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{(.*?)\}', re.S)


def _dhcpd_time(s: str) -> float | None:
    m = re.search(r"(\d{4})/(\d{2})/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", s)
    if not m:
        return None
    try:
        return datetime(*(int(x) for x in m.groups()),
                        tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def from_dhcpd(text: str):
    for m in _LEASE.finditer(text):
        ip, body = m.group(1), m.group(2)
        mac = ""
        hw = re.search(r"hardware\s+ethernet\s+([0-9a-fA-F:]+)", body)
        if hw:
            mac = oui.norm(hw.group(1))
        host = ""
        hm = re.search(r'client-hostname\s+"([^"]*)"', body)
        if hm:
            host = hm.group(1)
        starts = re.search(r"starts\s+\d+\s+([^;]+);", body)
        ends = re.search(r"ends\s+\d+\s+([^;]+);", body)
        binding = re.search(r"binding state\s+(\w+)", body)
        ts = _dhcpd_time(starts.group(1)) if starts else None
        if not mac:
            continue
        yield Obs(ts=ts, ip=ip, mac=mac, source="dhcpd", hostname=host,
                  kind="release" if binding and binding.group(1) == "free"
                  else "lease",
                  state=(binding.group(1) if binding else ""))
        if ends and _dhcpd_time(ends.group(1)):
            yield Obs(ts=_dhcpd_time(ends.group(1)), ip=ip, mac=mac,
                      source="dhcpd", hostname=host, kind="lease-end")


# --------------------------------------------------------------------------
# Windows DHCP audit CSV
# --------------------------------------------------------------------------

_WIN_EVENT = {
    "10": "lease", "11": "renew", "12": "release", "13": "conflict",
    "14": "pool-exhausted", "15": "lease-denied", "30": "renew",
    "31": "renew-fail", "32": "renew",
}


def from_windhcp(text: str):
    # skip the header block; the data rows start after a line of column names
    lines = text.splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if ln.lower().startswith("id,date,time") or (
                ln.startswith("ID,") and "IP Address" in ln):
            start = i
            break
    reader = _csv.reader(io.StringIO("\n".join(lines[start:])))
    header = next(reader, None)
    if not header:
        return
    idx = {h.strip().lower(): i for i, h in enumerate(header)}

    def g(row, *names):
        for nm in names:
            if nm in idx and idx[nm] < len(row):
                return row[idx[nm]].strip()
        return ""

    for row in reader:
        if not row or not row[0].strip().isdigit():
            continue
        ev = row[0].strip()
        date = g(row, "date")
        tm = g(row, "time")
        ts = None
        m = re.match(r"(\d{2})/(\d{2})/(\d{2,4})", date)
        tmm = re.match(r"(\d{2}):(\d{2}):(\d{2})", tm)
        if m and tmm:
            mo, dy, yr = m.groups()
            yr = int(yr) + (2000 if len(yr) == 2 else 0)
            try:
                ts = datetime(yr, int(mo), int(dy), *(int(x) for x in
                                                     tmm.groups()),
                              tzinfo=timezone.utc).timestamp()
            except ValueError:
                ts = None
        ip = g(row, "ip address", "ipaddress")
        host = g(row, "host name", "hostname")
        mac = g(row, "mac address", "macaddress")
        if not ip or not mac:
            continue
        yield Obs(ts=ts, ip=ip, mac=oui.norm(mac), source="windhcp",
                  hostname=host.rstrip("."),
                  kind=_WIN_EVENT.get(ev, f"event{ev}"))


# --------------------------------------------------------------------------
# arp -a  /  ip neigh  /  Windows arp -a
# --------------------------------------------------------------------------

_LINUX_ARP = re.compile(
    r"^(?P<host>\S+)?\s*\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
    r"(?P<mac>[0-9a-fA-F:]{17}|<incomplete>)"
    r"(?:\s+\[\w+\])?(?:\s+on\s+(?P<if>\S+))?")
_IP_NEIGH = re.compile(
    r"^(?P<ip>[0-9a-fA-F:.]+)\s+dev\s+(?P<if>\S+)\s+lladdr\s+"
    r"(?P<mac>[0-9a-fA-F:]{17})\s*(?P<state>\w+)?")
_WIN_ARP = re.compile(
    r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F-]{17})\s+"
    r"(?P<type>dynamic|static)", re.I)


def from_arptable(text: str):
    cur_if = ""
    for line in text.splitlines():
        mi = re.match(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)", line)
        if mi:
            cur_if = mi.group(1)
            continue
        m = _LINUX_ARP.match(line.strip())
        if m and m.group("mac") != "<incomplete>":
            host = (m.group("host") or "").rstrip(".")
            yield Obs(ts=None, ip=m.group("ip"), mac=oui.norm(m.group("mac")),
                      source="arptable",
                      hostname="" if host in ("?", "") else host,
                      iface=m.group("if") or "", kind="neighbour")
            continue
        m = _IP_NEIGH.match(line.strip())
        if m:
            yield Obs(ts=None, ip=m.group("ip"), mac=oui.norm(m.group("mac")),
                      source="arptable", iface=m.group("if"),
                      kind="neighbour", state=(m.group("state") or ""))
            continue
        m = _WIN_ARP.match(line)
        if m:
            yield Obs(ts=None, ip=m.group("ip"), mac=oui.norm(m.group("mac")),
                      source="arptable", iface=cur_if, kind="neighbour",
                      state=m.group("type").lower())


# --------------------------------------------------------------------------
# pcap / pcapng - ARP frames + passive src bindings
# --------------------------------------------------------------------------

def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def from_pcap(path: str):
    for ts, lt, data in _pcap.read(path):
        if lt != 1 or len(data) < 14:
            continue
        etype = struct.unpack_from(">H", data, 12)[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype = struct.unpack_from(">H", data, off + 2)[0]
            off += 4
        if etype == 0x0806 and len(data) >= off + 28:
            (htype, ptype, hlen, plen, op) = struct.unpack_from(
                ">HHBBH", data, off)
            if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
                continue
            sha = _mac(data[off + 8:off + 14])
            spa = socket.inet_ntoa(data[off + 14:off + 18])
            tha = _mac(data[off + 18:off + 24])
            tpa = socket.inet_ntoa(data[off + 24:off + 28])
            if op == 1:
                if spa != "0.0.0.0":
                    yield Obs(ts=ts, ip=spa, mac=sha, source="pcap-arp",
                              kind="gratuitous" if spa == tpa else "request")
            elif op == 2:
                yield Obs(ts=ts, ip=spa, mac=sha, source="pcap-arp",
                          kind="reply")
                if tpa != "0.0.0.0" and tha not in ("00:00:00:00:00:00",
                                                    "ff:ff:ff:ff:ff:ff"):
                    yield Obs(ts=ts, ip=tpa, mac=tha, source="pcap-arp",
                              kind="reply-target")
        elif etype in (0x0800, 0x86DD) and len(data) >= off + 20:
            src_mac = _mac(data[6:12])
            if etype == 0x0800:
                src_ip = socket.inet_ntoa(data[off + 12:off + 16])
            else:
                src_ip = socket.inet_ntop(socket.AF_INET6,
                                          data[off + 8:off + 24])
            if src_ip not in ("0.0.0.0", "::"):
                yield Obs(ts=ts, ip=src_ip, mac=src_mac, source="pcap-passive",
                          kind="passive")


# --------------------------------------------------------------------------
# dispatcher
# --------------------------------------------------------------------------

def read(path: str):
    p = Path(path)
    try:
        head = p.read_bytes()[:4096]
    except OSError as e:
        raise ArpError(f"{path}: {e}") from e
    magic = head[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                 b"\x0a\x0d\x0d\x0a", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        yield from from_pcap(path)
        return
    text = p.read_text(encoding="utf-8", errors="replace")
    low = text[:4096].lower()
    if "lease " in low and "hardware ethernet" in low:
        yield from from_dhcpd(text)
    elif ("id,date,time" in low or ("ip address" in low and "mac address" in low
                                    and "," in low)):
        yield from from_windhcp(text)
    elif re.search(r"\(\d+\.\d+\.\d+\.\d+\) at |dev \S+ lladdr |Interface: ",
                   text) or re.search(r"[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-",
                                      text, re.I):
        yield from from_arptable(text)
    else:
        raise ArpError(f"{path}: unrecognised ARP / DHCP / neighbour source")
