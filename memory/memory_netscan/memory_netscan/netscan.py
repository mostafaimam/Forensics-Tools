"""Pool-tag scan for Windows network endpoints and listeners.

Profile-independent: allocations are found by their ``tcpip.sys`` pool tags
and parsed by content (plausible FILETIME, big-endian ports, a TCP-state
enum, kernel pointers that actually translate).  When a directory-table
base is available the owning process and the local / remote addresses are
resolved by following those pointers; otherwise the row is still reported
with whatever was inline, at lower confidence.
"""

from __future__ import annotations

import re
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from memory_netscan.pagemap import Pml4, find_kernel_dtb

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MIN_FT = int((datetime(2010, 1, 1, tzinfo=timezone.utc) - _FT_EPOCH)
              .total_seconds() * 10_000_000)
_MAX_FT = int((datetime(2040, 1, 1, tzinfo=timezone.utc) - _FT_EPOCH)
              .total_seconds() * 10_000_000)

# tcpip.sys pool tags (Vista and later)
_TAGS = {
    b"TcpE": ("TCP", "endpoint"),
    b"TcpL": ("TCP", "listener"),
    b"UdpA": ("UDP", "endpoint"),
}
_TAG_RE = re.compile(rb"TcpE|TcpL|UdpA")
_WINDOW = 0x400

_TCP_STATES = {
    0: "CLOSED", 1: "LISTENING", 2: "SYN_SENT", 3: "SYN_RCVD",
    4: "ESTABLISHED", 5: "FIN_WAIT1", 6: "FIN_WAIT2", 7: "CLOSE_WAIT",
    8: "CLOSING", 9: "LAST_ACK", 10: "TIME_WAIT", 11: "DELETE_TCB",
}

_NAME_RE = re.compile(rb"(?<![\x21-\x7e])([\x21-\x7e]{2,15})\x00")
_PROC_NEAR = re.compile(rb"Proc")
_AF_INET, _AF_INET6 = 2, 23


@dataclass
class Endpoint:
    proto: str                 # TCP / UDP
    role: str                  # endpoint / listener
    state: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    pid: int
    process: str
    create_time: str
    phys_offset: int
    pool_tag: str
    confidence: str            # high | medium | low

    def key(self):
        return (self.proto, self.local_port, self.remote_port,
                self.local_addr, self.remote_addr, self.pid)


def ft_to_iso(ticks: int) -> str:
    if not (_MIN_FT <= ticks <= _MAX_FT):
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


def _is_kernel_ptr(v: int) -> bool:
    return (v >> 48) == 0xFFFF and (v & 0xF000000000000000) == 0xF000000000000000


def _plausible_port(p: int) -> bool:
    return 1 <= p <= 65535


def _looks_ipv4(b: bytes) -> bool:
    if len(b) < 4:
        return False
    o = b[:4]
    if o == b"\x00\x00\x00\x00" or o == b"\xff\xff\xff\xff":
        return False
    if o[0] in (0, 255) or o[0] >= 240:
        return False
    if o[0] == o[1] == o[2] == o[3]:
        return False
    return True


def _fmt_ipv4(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, b[:4])


def _fmt_ipv6(b: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET6, b[:16])
    except OSError:
        return ""


class _Resolver:
    """Follows endpoint pointers through the address space when we have one."""

    def __init__(self, pml4: Pml4 | None):
        self.p = pml4

    def address_family(self, inetaf_ptr: int) -> int | None:
        if not self.p:
            return None
        buf = self.p.read(inetaf_ptr, 0x40)
        for off in range(0, 0x40, 2):
            v = struct.unpack_from("<H", buf, off)[0]
            if v in (_AF_INET, _AF_INET6):
                # sanity: the neighbouring bytes should be mostly zero
                return v
        return None

    def chase_ip(self, ptr: int, want6: bool, depth: int = 4):
        if not self.p or depth <= 0 or not _is_kernel_ptr(ptr):
            return ""
        buf = self.p.read(ptr, 0x40)
        if want6:
            cand = buf[:16]
            if any(cand) and _fmt_ipv6(cand):
                txt = _fmt_ipv6(cand)
                if txt and not txt.startswith(("fe80", "0:0:0")):
                    return txt
        else:
            if _looks_ipv4(buf):
                return _fmt_ipv4(buf)
        # follow the first couple of embedded pointers
        for off in (0, 8, 0x10, 0x18):
            nxt = struct.unpack_from("<Q", buf, off)[0]
            if _is_kernel_ptr(nxt) and nxt != ptr:
                got = self.chase_ip(nxt, want6, depth - 1)
                if got:
                    return got
        return ""

    def owner_process(self, ptr: int):
        """(pid, name) for an _EPROCESS-ish pointer, else (0, '')."""
        if not self.p or not _is_kernel_ptr(ptr):
            return 0, ""
        body = self.p.read(ptr - 0x10, 0x800)
        if not body:
            return 0, ""
        names = [m for m in _NAME_RE.finditer(body)
                 if m.group(1).lower().endswith(b".exe")
                 or m.group(1) in (b"System", b"Registry", b"Memory")]
        name = names[0].group(1).decode("latin-1", "replace") if names else ""
        pid = 0
        for i in range(0, len(body) - 8, 4):
            v = struct.unpack_from("<Q", body, i)[0]
            if 0 < v < 0x40000 and v % 4 == 0:
                pid = v
                break
        return pid, name


def scan(img, *, use_translation: bool = True, progress=None) -> list[Endpoint]:
    pml4 = None
    if use_translation:
        dtb = find_kernel_dtb(img)
        if dtb is not None:
            pml4 = Pml4(img, dtb)
    resolver = _Resolver(pml4)

    found: list[Endpoint] = []
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG_RE.finditer(block):
            t = m.start()
            tag = block[t:t + 4]
            proto, role = _TAGS[tag]
            start = max(0, (t - 4) & ~7)
            win = block[start:t + _WINDOW]
            ep = _parse(win, base + start, tag.decode(), proto, role, resolver)
            if ep:
                found.append(ep)
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)

    best: dict = {}
    for e in found:
        k = e.key()
        if k not in best or _rank(e) > _rank(best[k]):
            best[k] = e
    return sorted(best.values(),
                  key=lambda e: (e.proto, e.local_port, e.remote_port))


def _rank(e: Endpoint) -> int:
    return {"high": 3, "medium": 2, "low": 1}[e.confidence]


def _parse(win: bytes, phys: int, tag: str, proto: str, role: str,
           resolver: _Resolver):
    # inline CreateTime
    create = ""
    for i in range(0, min(len(win), 0x300) - 8, 8):
        c = struct.unpack_from("<Q", win, i)[0]
        if _MIN_FT <= c <= _MAX_FT:
            create = ft_to_iso(c)
            break

    # TCP state enum (only meaningful for TcpE)
    state = ""
    if tag == "TcpE":
        for i in range(0, min(len(win), 0x80), 4):
            v = struct.unpack_from("<I", win, i)[0]
            if v in _TCP_STATES and v != 0:
                state = _TCP_STATES[v]
                break
    elif role == "listener":
        state = "LISTENING"

    # kernel pointers that translate (also used to mask out port scanning)
    ptrs: list[int] = []
    ptr_spans: list[tuple[int, int]] = []
    for i in range(0, min(len(win), 0x140) - 8, 8):
        v = struct.unpack_from("<Q", win, i)[0]
        if _is_kernel_ptr(v):
            ptr_spans.append((i, i + 8))
            if resolver.p is None or resolver.p.translate(v) is not None:
                ptrs.append(v)

    tag_off = win.find(tag.encode())
    masks = list(ptr_spans)
    if tag_off >= 0:
        masks.append((tag_off - 4, tag_off + 8))     # pool tag + size slot

    def _in_ptr(o: int) -> bool:
        return any(a <= o < b or a <= o + 1 < b for a, b in masks)

    def _u16le(o: int) -> int:
        return struct.unpack_from("<H", win, o)[0] if 0 <= o <= len(win) - 2 \
            else 1

    # big-endian ports: 2-aligned, outside pointer bytes, and bordered by a
    # zero halfword on at least one side (a genuine USHORT port field is)
    cand: list[tuple[int, int]] = []
    for i in range(2, min(len(win), 0x160) - 2, 2):
        if _in_ptr(i):
            continue
        be = struct.unpack_from(">H", win, i)[0]
        if not _plausible_port(be):
            continue
        if _u16le(i - 2) == 0 or _u16le(i + 2) == 0:
            cand.append((i, be))

    local_port = remote_port = 0
    if tag == "TcpE":
        for k in range(len(cand) - 1):
            o1, p1 = cand[k]
            o2, p2 = cand[k + 1]
            if o2 - o1 == 2:
                local_port, remote_port = p1, p2
                break
    if not local_port and cand:
        local_port = cand[0][1]

    pid, process = 0, ""
    laddr = raddr = ""
    want6 = False
    if resolver.p is not None and ptrs:
        af = None
        for pp in ptrs[:6]:
            af = resolver.address_family(pp)
            if af:
                want6 = af == _AF_INET6
                break
        for pp in ptrs:
            if not process:
                q, nm = resolver.owner_process(pp)
                if nm:
                    pid, process = q, nm
                    continue
            if not laddr:
                laddr = resolver.chase_ip(pp, want6)

    conf = "low"
    if create and (local_port or ptrs):
        conf = "medium"
    if process and local_port and create:
        conf = "high"
    if not (local_port or create or process):
        return None

    return Endpoint(proto=proto, role=role, state=state,
                    local_addr=laddr or ("::" if want6 else "0.0.0.0"),
                    local_port=local_port,
                    remote_addr=raddr, remote_port=remote_port,
                    pid=pid, process=process, create_time=create,
                    phys_offset=phys, pool_tag=tag, confidence=conf)
