"""Hand-built HTTP-over-TCP captures for the test-suite (stdlib only)."""

from __future__ import annotations

import gzip
import socket
import struct
import zlib

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


def tcp(payload: bytes, sport: int, dport: int, *, flags="P.", seq=1,
        ack=1) -> bytes:
    fbits = 0
    for c, b in (("F", 1), ("S", 2), ("R", 4), ("P", 8), (".", 16), ("U", 32)):
        if c in flags:
            fbits |= b
    return struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, fbits,
                       0xFFFF, 0, 0) + payload


def frame_tcp(src, dst, sport, dport, payload=b"", *, flags="P.", seq=1,
              ttl=64) -> bytes:
    return eth(ipv4(tcp(payload, sport, dport, flags=flags, seq=seq), 6,
                    src, dst, ttl))


def frame6_tcp(src, dst, sport, dport, payload=b"", *, flags="P.", seq=1) -> bytes:
    return eth(ipv6(tcp(payload, sport, dport, flags=flags, seq=seq), 6,
                    src, dst), etype=0x86DD)


# --------------------------------------------------------------------------
# HTTP message builders
# --------------------------------------------------------------------------

def request(method: str, path: str, host: str, *, headers=None,
            body: bytes = b"") -> bytes:
    h = {"Host": host, "User-Agent": "Mozilla/5.0", "Accept": "*/*"}
    if headers:
        h.update(headers)
    if body and "Content-Length" not in h:
        h["Content-Length"] = str(len(body))
    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in h.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def _chunk_encode(body: bytes, size: int = 17) -> bytes:
    out = bytearray()
    for i in range(0, len(body), size):
        piece = body[i:i + size]
        out += f"{len(piece):x}\r\n".encode() + piece + b"\r\n"
    out += b"0\r\n\r\n"
    return bytes(out)


def response(body: bytes = b"", *, status=200, reason="OK", ctype=None,
             headers=None, chunked=False, encoding=None, server="nginx/1.24",
             disposition=None) -> bytes:
    h = {"Server": server}
    if ctype:
        h["Content-Type"] = ctype
    if disposition:
        h["Content-Disposition"] = disposition
    if headers:
        h.update(headers)
    payload = body
    if encoding == "gzip":
        payload = gzip.compress(body)
        h["Content-Encoding"] = "gzip"
    elif encoding == "deflate":
        payload = zlib.compress(body)
        h["Content-Encoding"] = "deflate"
    if chunked:
        h["Transfer-Encoding"] = "chunked"
        payload = _chunk_encode(payload)
    else:
        h["Content-Length"] = str(len(payload))
    lines = [f"HTTP/1.1 {status} {reason}"]
    lines += [f"{k}: {v}" for k, v in h.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + payload


# --------------------------------------------------------------------------
# TCP conversation -> list[(ts, frame)]
# --------------------------------------------------------------------------

def convo(client_data: bytes, server_data: bytes, *, client_ip="10.0.0.5",
          server_ip="93.184.216.34", cport=51500, sport=80, t0=1_000_000.0,
          mss=1460, v6=False, server_out_of_order=False):
    mk = frame6_tcp if v6 else frame_tcp
    if v6:
        client_ip, server_ip = "fd00::5", "fd00::99"
    pkts = []
    t = [t0]

    def emit(fr):
        t[0] += 0.01
        pkts.append((t[0], fr))

    emit(mk(client_ip, server_ip, cport, sport, flags="S", seq=1000))
    emit(mk(server_ip, client_ip, sport, cport, flags="S.", seq=5000))

    seq = 1001
    for i in range(0, len(client_data), mss):
        c = client_data[i:i + mss]
        emit(mk(client_ip, server_ip, cport, sport, c, flags="P.", seq=seq))
        seq += len(c)

    segs = []
    s = 5001
    for i in range(0, len(server_data), mss):
        c = server_data[i:i + mss]
        segs.append(mk(server_ip, client_ip, sport, cport, c, flags="P.", seq=s))
        s += len(c)
    if server_out_of_order:
        segs = segs[::-1]
    for fr in segs:
        emit(fr)

    emit(mk(client_ip, server_ip, cport, sport, flags="F.", seq=seq))
    return pkts


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
