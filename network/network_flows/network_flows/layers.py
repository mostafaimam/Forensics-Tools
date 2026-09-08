"""Decode link / network / transport headers to a flat Packet."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

# libpcap link types we handle
LINK_NULL = 0
LINK_ETHERNET = 1
LINK_RAW = 101
LINK_LINUX_SLL = 113
LINK_LINUX_SLL2 = 276
LINK_LOOP = 108

_TCP_FLAGS = [(0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
              (0x10, "."), (0x20, "U"), (0x40, "E"), (0x80, "C")]


@dataclass
class Packet:
    ts: float
    src: str = ""
    dst: str = ""
    proto: str = ""            # TCP / UDP / ICMP / ICMPv6 / IPv4 / IPv6 / ...
    sport: int = 0
    dport: int = 0
    length: int = 0            # on-wire length
    payload_len: int = 0       # transport payload
    tcp_flags: str = ""
    tcp_seq: int = 0
    ttl: int = 0
    payload: bytes = b""
    ip_version: int = 0


def _ipv4(pkt: Packet, buf: bytes, off: int) -> None:
    if len(buf) < off + 20:
        return
    ihl = (buf[off] & 0x0F) * 4
    total = struct.unpack_from(">H", buf, off + 2)[0]
    proto = buf[off + 9]
    pkt.ttl = buf[off + 8]
    pkt.src = socket.inet_ntop(socket.AF_INET, buf[off + 12:off + 16])
    pkt.dst = socket.inet_ntop(socket.AF_INET, buf[off + 16:off + 20])
    pkt.ip_version = 4
    _transport(pkt, buf, off + ihl, proto, max(0, total - ihl))


def _ipv6(pkt: Packet, buf: bytes, off: int) -> None:
    if len(buf) < off + 40:
        return
    plen = struct.unpack_from(">H", buf, off + 4)[0]
    nxt = buf[off + 6]
    pkt.ttl = buf[off + 7]
    pkt.src = socket.inet_ntop(socket.AF_INET6, buf[off + 8:off + 24])
    pkt.dst = socket.inet_ntop(socket.AF_INET6, buf[off + 24:off + 40])
    pkt.ip_version = 6
    p = off + 40
    # walk a couple of extension headers
    for _ in range(4):
        if nxt in (0, 43, 60):                # hop-by-hop / routing / dest opts
            if p + 2 > len(buf):
                return
            hlen = (buf[p + 1] + 1) * 8
            nxt = buf[p]
            p += hlen
        elif nxt == 44:                       # fragment
            nxt = buf[p]
            p += 8
        else:
            break
    _transport(pkt, buf, p, nxt, plen)


def _transport(pkt: Packet, buf: bytes, off: int, proto: int, plen: int) -> None:
    if proto == 6 and len(buf) >= off + 20:
        pkt.proto = "TCP"
        pkt.sport, pkt.dport, seq = struct.unpack_from(">HHI", buf, off)
        doff = (buf[off + 12] >> 4) * 4
        flags = buf[off + 13]
        pkt.tcp_seq = seq
        pkt.tcp_flags = "".join(c for bit, c in _TCP_FLAGS if flags & bit)
        pkt.payload = buf[off + doff:]
        pkt.payload_len = max(0, plen - doff) if plen else len(pkt.payload)
    elif proto == 17 and len(buf) >= off + 8:
        pkt.proto = "UDP"
        pkt.sport, pkt.dport, ulen, _ = struct.unpack_from(">HHHH", buf, off)
        pkt.payload = buf[off + 8:]
        pkt.payload_len = max(0, ulen - 8) if ulen else len(pkt.payload)
    elif proto == 1:
        pkt.proto = "ICMP"
        pkt.payload = buf[off:]
    elif proto == 58:
        pkt.proto = "ICMPv6"
        pkt.payload = buf[off:]
    else:
        pkt.proto = f"IP proto {proto}"


def decode(ts: float, linktype: int, data: bytes) -> Packet | None:
    pkt = Packet(ts=ts, length=len(data))
    try:
        if linktype == LINK_ETHERNET:
            if len(data) < 14:
                return None
            etype = struct.unpack_from(">H", data, 12)[0]
            off = 14
            while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
                etype = struct.unpack_from(">H", data, off + 2)[0]
                off += 4
            if etype == 0x0800:
                _ipv4(pkt, data, off)
            elif etype == 0x86DD:
                _ipv6(pkt, data, off)
            elif etype == 0x0806:
                pkt.proto = "ARP"
            else:
                pkt.proto = f"ethertype {etype:#06x}"
        elif linktype == LINK_RAW:
            v = data[0] >> 4 if data else 0
            (_ipv4 if v == 4 else _ipv6)(pkt, data, 0)
        elif linktype in (LINK_NULL, LINK_LOOP):
            fam = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
            if fam in (2,):
                _ipv4(pkt, data, 4)
            elif fam in (24, 28, 30):
                _ipv6(pkt, data, 4)
        elif linktype == LINK_LINUX_SLL:
            if len(data) < 16:
                return None
            etype = struct.unpack_from(">H", data, 14)[0]
            if etype == 0x0800:
                _ipv4(pkt, data, 16)
            elif etype == 0x86DD:
                _ipv6(pkt, data, 16)
        elif linktype == LINK_LINUX_SLL2:
            if len(data) < 20:
                return None
            etype = struct.unpack_from(">H", data, 0)[0]
            if etype == 0x0800:
                _ipv4(pkt, data, 20)
            elif etype == 0x86DD:
                _ipv6(pkt, data, 20)
        else:
            v = data[0] >> 4 if data else 0
            if v == 4:
                _ipv4(pkt, data, 0)
            elif v == 6:
                _ipv6(pkt, data, 0)
    except (struct.error, IndexError, OSError, ValueError):
        return pkt if pkt.src else None
    return pkt
