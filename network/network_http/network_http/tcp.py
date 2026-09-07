"""Minimal TCP stream reassembly from decoded packets.

Per connection we build the two directional byte streams by ordering
segments on their sequence number, filling gaps with zero bytes and
dropping pure retransmits.  Good enough to hand a coherent stream to the
HTTP parser; it is not a full TCP state machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from network_http.layers import Packet


@dataclass
class Direction:
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    syn_seq: int | None = None
    raw: list = field(default_factory=list)          # [(abs_seq, data)]
    first_ts: float = 0.0
    fin: bool = False

    def add(self, seq: int, data: bytes, ts: float) -> None:
        if data:
            self.raw.append((seq, data))
        if not self.first_ts:
            self.first_ts = ts

    def _base(self) -> int:
        if self.syn_seq is not None:
            return (self.syn_seq + 1) & 0xFFFFFFFF
        return min(s for s, _ in self.raw)

    def stream(self, cap: int = 64 * 1024 * 1024) -> bytes:
        if not self.raw:
            return b""
        base = self._base()
        segs: dict[int, bytes] = {}
        for seq, data in self.raw:
            rel = (seq - base) & 0xFFFFFFFF
            if rel > 0x7FFFFFFF:                     # wrapped before base
                rel -= 0x100000000
            if rel < 0:
                continue
            segs.setdefault(rel, data)
        out = bytearray()
        for rel in sorted(segs):
            if rel > len(out):
                gap = min(rel - len(out), 1 << 20)
                out.extend(b"\x00" * gap)
            data = segs[rel]
            end = rel + len(data)
            if end <= len(out):
                continue
            out.extend(data[len(out) - rel:] if rel < len(out) else data)
            if len(out) > cap:
                break
        return bytes(out)


@dataclass
class Conn:
    a: Direction
    b: Direction
    server: str = ""

    def client_to_server(self) -> Direction:
        return self.a if self.server == self.b.src else self.b

    def server_to_client(self) -> Direction:
        return self.b if self.server == self.b.src else self.a


class Assembler:
    def __init__(self):
        self.conns: dict[tuple, Conn] = {}

    def add(self, p: Packet) -> None:
        if p.proto != "TCP" or not p.src:
            return
        a = (p.src, p.sport)
        b = (p.dst, p.dport)
        key = (min(a, b), max(a, b))
        c = self.conns.get(key)
        if c is None:
            (a_ip, a_pt), (b_ip, b_pt) = min(a, b), max(a, b)
            c = Conn(a=Direction(src=a_ip, dst=b_ip, sport=a_pt, dport=b_pt),
                     b=Direction(src=b_ip, dst=a_ip, sport=b_pt, dport=a_pt))
            # server = lower port, or the SYN target
            if "S" in p.tcp_flags and "." not in p.tcp_flags:
                c.server = p.dst
            else:
                c.server = a_ip if a_pt <= b_pt else b_ip
            self.conns[key] = c
        d = c.a if (p.src, p.sport) == (c.a.src, c.a.sport) else c.b
        if "S" in p.tcp_flags:
            d.syn_seq = p.tcp_seq
        if p.payload:
            d.add(p.tcp_seq, p.payload, p.ts)
        if "F" in p.tcp_flags:
            d.fin = True

    def connections(self):
        return list(self.conns.values())
