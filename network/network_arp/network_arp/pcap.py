"""Iterate packets from a classic pcap or a pcapng file.

Yields ``(timestamp: float, linktype: int, data: bytes)``.
"""

from __future__ import annotations

import struct
from pathlib import Path

_PCAP_MAGICS = {
    0xA1B2C3D4: ("<", 1_000_000),      # LE, microseconds
    0xD4C3B2A1: (">", 1_000_000),      # BE, microseconds
    0xA1B23C4D: ("<", 1_000_000_000),  # LE, nanoseconds
    0x4D3CB2A1: (">", 1_000_000_000),  # BE, nanoseconds
}
_PCAPNG_SHB = 0x0A0D0D0A


class PcapError(Exception):
    pass


def read(path: str | Path):
    data = Path(path).read_bytes()
    if len(data) < 8:
        raise PcapError("file too short")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == _PCAPNG_SHB or data[:4] == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
    elif magic in _PCAP_MAGICS:
        yield from _read_classic(data, magic)
    else:
        raise PcapError(f"not a pcap/pcapng file (magic {magic:#x})")


def _read_classic(data: bytes, magic: int):
    endian, tick = _PCAP_MAGICS[magic]
    (ver_major, ver_minor, _tz, _sig, snaplen, linktype) = struct.unpack_from(
        endian + "HHiIII", data, 4)
    linktype &= 0xFFFF
    pos = 24
    n = len(data)
    while pos + 16 <= n:
        ts_sec, ts_frac, incl, orig = struct.unpack_from(
            endian + "IIII", data, pos)
        pos += 16
        if pos + incl > n:
            break
        pkt = data[pos:pos + incl]
        pos += incl
        yield ts_sec + ts_frac / tick, linktype, pkt


def _read_pcapng(data: bytes):
    pos = 0
    n = len(data)
    endian = "<"
    if_linktypes: dict[int, int] = {}
    if_tsresol: dict[int, int] = {}
    iface = 0
    while pos + 12 <= n:
        block_type = struct.unpack_from(endian + "I", data, pos)[0]
        if block_type == _PCAPNG_SHB:
            bom = struct.unpack_from("<I", data, pos + 8)[0]
            endian = "<" if bom == 0x1A2B3C4D else ">"
            block_type = _PCAPNG_SHB
        total_len = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if total_len < 12 or pos + total_len > n:
            break
        body = data[pos + 8:pos + total_len - 4]

        if block_type == 0x00000001:                       # IDB
            lt = struct.unpack_from(endian + "H", body, 0)[0]
            if_linktypes[iface] = lt
            if_tsresol[iface] = 1_000_000                   # default 10**-6 s
            for name, val in _iter_options(body[8:], endian):
                if name == 9 and val:                      # if_tsresol
                    r = val[0]
                    if_tsresol[iface] = (2 ** (r & 0x7F) if r & 0x80
                                         else 10 ** r)
            iface += 1
        elif block_type == 0x00000006:                     # EPB
            if_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(
                endian + "IIIII", body, 0)
            pkt = body[20:20 + cap_len]
            res = if_tsresol.get(if_id, 1_000_000) or 1_000_000
            ts = ((ts_hi << 32) | ts_lo) / res
            yield ts, if_linktypes.get(if_id, 1), pkt
        elif block_type == 0x00000003:                     # simple packet
            (orig_len,) = struct.unpack_from(endian + "I", body, 0)
            pkt = body[4:4 + orig_len]
            yield 0.0, if_linktypes.get(0, 1), pkt

        pos += total_len
        if total_len % 4:
            pos += 4 - (total_len % 4)


def _iter_options(buf: bytes, endian: str):
    p = 0
    while p + 4 <= len(buf):
        code, length = struct.unpack_from(endian + "HH", buf, p)
        p += 4
        if code == 0:
            return
        yield code, buf[p:p + length]
        p += length + ((4 - length % 4) % 4)
