"""Pool-tag scan for private executable memory regions (``_MMVAD_SHORT``).

``VadS`` allocations are private memory by construction (no control area /
subsection).  When such a region is also **executable** it is the classic
signature of code injection - a reflectively-loaded DLL, a hollowed
section, or raw shellcode.  The VPN pair sits at a stable offset inside the
node; the protection bits move between Windows 7 and 8+, so both known
positions are checked.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

_TAG_RE = re.compile(rb"Vad[Slmf]")
_PRIVATE_TAGS = {b"VadS", b"Vadl", b"Vadm"}

# MmProtectToValue base indices
_PROT_NAME = {
    0: "NOACCESS", 1: "READONLY", 2: "EXECUTE", 3: "EXECUTE_READ",
    4: "READWRITE", 5: "WRITECOPY", 6: "EXECUTE_READWRITE",
    7: "EXECUTE_WRITECOPY",
}
_EXEC_BASE = {2, 3, 6, 7}
_VAD_TYPE = {0: "private", 1: "phys", 2: "image", 3: "awe", 4: "writewatch",
             5: "largepage", 6: "rotate", 7: "largepagesection"}

_USER_MAX_VPN = 0x7FFFFFFF          # user space tops out well below this
_MAX_REGION_PAGES = 0x40000         # 1 GiB


@dataclass
class Vad:
    phys: int
    pool_tag: str
    start_vpn: int
    end_vpn: int
    protection: int
    protection_name: str
    vad_type: str
    private: bool
    flags_layout: str               # win7 | win8+

    @property
    def start(self) -> int:
        return self.start_vpn << 12

    @property
    def end(self) -> int:
        return ((self.end_vpn + 1) << 12) - 1

    @property
    def pages(self) -> int:
        return self.end_vpn - self.start_vpn + 1

    @property
    def executable(self) -> bool:
        return (self.protection & 0x07) in _EXEC_BASE

    def key(self):
        return (self.start_vpn, self.end_vpn, self.protection)


def _prot_at(flags: int, shift: int) -> int:
    return (flags >> shift) & 0x1F


def _parse_node(win: bytes, p: int):
    """Given a candidate StartingVpn offset *p*, return (start, end, prot,
    prot_shift_layout) or None."""
    if p + 8 > len(win):
        return None
    s = struct.unpack_from("<I", win, p)[0]
    e = struct.unpack_from("<I", win, p + 4)[0]
    if not (0 < s <= e <= _USER_MAX_VPN):
        return None
    if e - s + 1 > _MAX_REGION_PAGES:
        return None
    # high VPN bytes (Win8.1+) - keep it simple, ignore >44-bit ranges
    node = p - 0x18
    best = None
    # Win7: _MMVAD_FLAGS is a ULONGLONG at node+0x20, Protection at bit 56
    if node + 0x28 <= len(win):
        f7 = struct.unpack_from("<Q", win, node + 0x20)[0]
        pr = _prot_at(f7, 56)
        if pr in _PROT_NAME or (pr & 7) in _PROT_NAME:
            vt = (f7 >> 52) & 7
            priv = bool((f7 >> 63) & 1)
            best = (pr, "win7", vt, priv)
    # Win8/10: _MMVAD_FLAGS is a ULONG, Protection at bit 7; the dword sits
    # at node+0x28 (Win8) or node+0x30 (Win10)
    for foff, lbl in ((0x28, "win8"), (0x30, "win10")):
        if node + foff + 4 > len(win):
            continue
        f = struct.unpack_from("<I", win, node + foff)[0]
        pr = _prot_at(f, 7)
        if (pr & 7) in _EXEC_BASE or pr in (1, 4):
            vt = (f >> 4) & 7
            priv = bool((f >> 20) & 1)
            if best is None or (pr & 7) in _EXEC_BASE:
                best = (pr, lbl, vt, priv)
                break
    if best is None:
        return None
    pr, lbl, vt, priv = best
    return s, e, pr, lbl, vt, priv


def scan(img, *, executable_only: bool = True, progress=None) -> list[Vad]:
    found: list[Vad] = []
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG_RE.finditer(block):
            tag = block[m.start():m.start() + 4]
            if tag not in _PRIVATE_TAGS:
                continue
            t = m.start()
            start = max(0, (t - 4) & ~7)
            win = block[start:t + 0x80]
            # the node starts ~0xC after the tag; StartingVpn is node+0x18
            for base_off in range(0x18, 0x40, 4):
                parsed = _parse_node(win, base_off)
                if not parsed:
                    continue
                s, e, pr, lbl, vt, priv = parsed
                v = Vad(phys=base + start, pool_tag=tag.decode(),
                        start_vpn=s, end_vpn=e, protection=pr,
                        protection_name=_PROT_NAME.get(pr & 7, f"0x{pr:02x}"),
                        vad_type=_VAD_TYPE.get(vt, str(vt)),
                        private=priv or tag == b"VadS",
                        flags_layout=lbl)
                if executable_only and not v.executable:
                    continue
                found.append(v)
                break
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)

    best: dict = {}
    for v in found:
        k = v.key()
        if k not in best:
            best[k] = v
    return sorted(best.values(), key=lambda v: v.start_vpn)
