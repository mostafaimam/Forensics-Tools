"""Hand-built packets and pcap / pcapng containers for the test-suite."""

from __future__ import annotations

import socket
import struct

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(payload: bytes, etype=0x0800, src=MAC_A, dst=MAC_B) -> bytes:
    return dst + src + struct.pack(">H", etype) + payload


def ipv4(payload: bytes, proto: int, src: str, dst: str, ttl=64) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, ttl, proto,
                      0, socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack(">H", _cksum(hdr)) + hdr[12:]
    return hdr + payload


def ipv6(payload: bytes, nxt: int, src: str, dst: str) -> bytes:
    return struct.pack(">IHBB16s16s", 0x60000000, len(payload), nxt, 64,
                       socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst)) + payload


def tcp(payload: bytes, sport: int, dport: int, *, flags="P.", seq=1, ack=1) -> bytes:
    fbits = 0
    for c, b in (("F", 1), ("S", 2), ("R", 4), ("P", 8), (".", 16), ("U", 32)):
        if c in flags:
            fbits |= b
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, fbits,
                       0xFFFF, 0, 0) + payload


def udp(payload: bytes, sport: int, dport: int) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def frame_udp(src, dst, sport, dport, payload, ttl=64) -> bytes:
    return eth(ipv4(udp(payload, sport, dport), 17, src, dst, ttl))


def frame_tcp(src, dst, sport, dport, payload=b"", *, flags="P.", seq=1,
              ttl=64) -> bytes:
    return eth(ipv4(tcp(payload, sport, dport, flags=flags, seq=seq), 6,
                    src, dst, ttl))


def frame6_tcp(src, dst, sport, dport, payload=b"", *, flags="P.") -> bytes:
    return eth(ipv6(tcp(payload, sport, dport, flags=flags), 6, src, dst),
               etype=0x86DD)


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(name: str, qtype=1, tid=0x1234) -> bytes:
    return (struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
            + _dns_name(name) + struct.pack(">HH", qtype, 1))


def dns_response(name: str, ips, qtype=1, tid=0x1234) -> bytes:
    body = (struct.pack(">HHHHHH", tid, 0x8180, 1, len(ips), 0, 0)
            + _dns_name(name) + struct.pack(">HH", qtype, 1))
    for ip in ips:
        rdata = (socket.inet_aton(ip) if qtype == 1
                 else socket.inet_pton(socket.AF_INET6, ip))
        body += (b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 300, len(rdata))
                 + rdata)
    return body


def dns_txt_response(name: str, txt: str, tid=0x1234) -> bytes:
    t = txt.encode()
    rdata = bytes([len(t)]) + t
    return (struct.pack(">HHHHHH", tid, 0x8180, 1, 1, 0, 0)
            + _dns_name(name) + struct.pack(">HH", 16, 1)
            + b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata))
            + rdata)


def http_get(host: str, path="/", ua="Mozilla/5.0", extra="") -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"{extra}\r\n").encode()


def http_post(host: str, path: str, body: str, ua="curl/8.4.0") -> bytes:
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}").encode()


def http_response(status=200, ctype="text/html", server="nginx",
                  body="ok") -> bytes:
    return (f"HTTP/1.1 {status} OK\r\nServer: {server}\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n"
            f"{body}").encode()


# --------------------------------------------------------------------------
# containers
# --------------------------------------------------------------------------

def pcap(packets, linktype=1, nano=False) -> bytes:
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    tick = 1_000_000_000 if nano else 1_000_000
    out = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 0x40000, linktype)
    for ts, data in packets:
        sec = int(ts)
        frac = int((ts - sec) * tick)
        out += struct.pack("<IIII", sec, frac, len(data), len(data)) + data
    return out


def pcapng(packets, linktype=1) -> bytes:
    def block(btype, body):
        total = 12 + len(body)
        pad = (4 - total % 4) % 4
        total += pad
        return (struct.pack("<II", btype, total) + body + b"\x00" * pad
                + struct.pack("<I", total))

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(0x00000001, struct.pack("<HHI", linktype, 0, 0x40000))
    out = shb + idb
    for ts, data in packets:
        us = int(ts * 1_000_000)
        cap_pad = (4 - len(data) % 4) % 4
        body = (struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF,
                            len(data), len(data)) + data + b"\x00" * cap_pad)
        out += block(0x00000006, body)
    return out
