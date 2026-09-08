"""Hand-built DNS packets + pcap container for the test-suite."""

from __future__ import annotations

import socket
import struct

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")

_TYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "NULL": 10, "PTR": 12,
         "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255, "AXFR": 252}


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(payload, etype=0x0800, src=MAC_A, dst=MAC_B):
    return dst + src + struct.pack(">H", etype) + payload


def ipv4(payload, proto, src, dst, ttl=64):
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, ttl, proto,
                      0, socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack(">H", _cksum(hdr)) + hdr[12:]
    return hdr + payload


def udp(payload, sport, dport):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(payload, sport, dport, *, flags="P.", seq=1):
    fb = 0
    for c, b in (("F", 1), ("S", 2), ("R", 4), ("P", 8), (".", 16)):
        if c in flags:
            fb |= b
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 1, 0x50, fb,
                       0xFFFF, 0, 0) + payload


def _qname(name: str) -> bytes:
    out = b""
    for lbl in name.rstrip(".").split("."):
        out += bytes([len(lbl)]) + lbl.encode("latin-1")
    return out + b"\x00"


def _rdata(rtype: str, val):
    if rtype == "A":
        return socket.inet_aton(val)
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, val)
    if rtype in ("CNAME", "NS", "PTR"):
        return _qname(val)
    if rtype in ("TXT",):
        b = val.encode("latin-1")
        out = b""
        for i in range(0, len(b), 255):
            chunk = b[i:i + 255]
            out += bytes([len(chunk)]) + chunk
        return out or b"\x00"
    if rtype == "NULL":
        return bytes.fromhex(val) if isinstance(val, str) else bytes(val)
    if rtype == "MX":
        return struct.pack(">H", 10) + _qname(val)
    raise ValueError(rtype)


def dns(name, qtype="A", *, response=False, answers=None, rcode=0,
        tid=0x1234, tc=False):
    ancount = len(answers or [])
    flags = (0x8000 if response else 0) | (0x0200 if tc else 0) | rcode
    if not response:
        flags |= 0x0100                                    # RD
    body = struct.pack(">HHHHHH", tid, flags, 1, ancount, 0, 0)
    body += _qname(name) + struct.pack(">HH", _TYPE[qtype], 1)
    for a_type, a_val, a_ttl in (answers or []):
        rd = _rdata(a_type, a_val)
        body += (b"\xc0\x0c" + struct.pack(">HHIH", _TYPE[a_type], 1, a_ttl,
                                           len(rd)) + rd)
    return body


def q(name, qtype="A", *, client="10.0.0.50", server="10.0.0.1", tid=0x1234):
    return eth(ipv4(udp(dns(name, qtype, tid=tid), 51000, 53), 17,
                    client, server))


def r(name, qtype="A", *, answers=None, rcode=0, client="10.0.0.50",
      server="10.0.0.1", tid=0x1234, tc=False):
    return eth(ipv4(udp(dns(name, qtype, response=True, answers=answers,
                            rcode=rcode, tid=tid, tc=tc), 53, 51000), 17,
                    server, client))


def tcp_dns(name, qtype="AXFR", *, response=False, answers=None,
            client="10.0.0.50", server="10.0.0.1"):
    msg = dns(name, qtype, response=response, answers=answers)
    framed = struct.pack(">H", len(msg)) + msg
    if response:
        return eth(ipv4(tcp(framed, 53, 45000), 6, server, client))
    return eth(ipv4(tcp(framed, 45000, 53), 6, client, server))


def pcap(packets, linktype=1):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0x40000, linktype)
    t = 1_700_000_000.0
    for i, data in enumerate(packets):
        ts = t + i * 0.5
        sec = int(ts)
        frac = int((ts - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, frac, len(data), len(data)) + data
    return out
