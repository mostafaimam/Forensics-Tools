"""Pool-tag scan for image / mapped-file VADs and their backing file name.

``Vad `` (trailing space) and ``Vadl`` allocations describe a mapped view -
for an image mapping that is a loaded module (a DLL or the process EXE).
The backing file's path is reached by chasing
``_MMVAD -> Subsection -> ControlArea -> FileObject -> FileName``; newer
Windows 10 builds also expose ``FileObject`` directly on the ``_MMVAD``.
Everything is best-effort and offset-searched, so it survives build
differences without a profile.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

_TAG_RE = re.compile(rb"Vad[ l]")
_IMAGE_TAGS = {b"Vad ", b"Vadl"}

_PROT_NAME = {
    0: "NOACCESS", 1: "READONLY", 2: "EXECUTE", 3: "EXECUTE_READ",
    4: "READWRITE", 5: "WRITECOPY", 6: "EXECUTE_READWRITE",
    7: "EXECUTE_WRITECOPY",
}
# user VA space is 128 TiB on Win8.1+, so the VPN can need up to ~36 bits
# (StartingVpn u32 + StartingVpnHigh byte at node+0x20 on 8.1+)
_USER_MAX_VPN = 0x8000000000
_MAX_REGION_PAGES = 0x100000


@dataclass
class ImageVad:
    phys: int
    pool_tag: str
    start: int
    end: int
    protection: str
    file_path: str
    vads_process: int            # kernel VA of owning _EPROCESS, or 0
    backed: bool

    @property
    def size(self) -> int:
        return self.end - self.start + 1

    def key(self):
        return (self.start, self.end)


def _is_kptr(v: int) -> bool:
    return (v >> 48) == 0xFFFF and (v & 0xF000000000000000) == 0xF000000000000000


def _read_unicode_string(pml4, addr: int) -> str:
    raw = pml4.read(addr, 16)
    length, maxlen = struct.unpack_from("<HH", raw, 0)
    buf_ptr = struct.unpack_from("<Q", raw, 8)[0]
    if not (0 < length <= maxlen <= 0x400) or length % 2 or not _is_kptr(buf_ptr):
        return ""
    data = pml4.read(buf_ptr, length)
    try:
        s = data.decode("utf-16-le", "replace").rstrip("\x00")
    except Exception:  # noqa: BLE001
        return ""
    if s and all(0x20 <= ord(c) < 0xFFFD or c == "\\" for c in s):
        return s
    return ""


def _file_name_from_fileobject(pml4, fo_addr: int) -> str:
    if not _is_kptr(fo_addr):
        return ""
    head = pml4.read(fo_addr, 4)
    # _FILE_OBJECT.Type is 5; be lenient (some builds put 0/garbage)
    typ = struct.unpack_from("<H", head, 0)[0]
    if typ not in (0, 5, 6):
        return ""
    for off in (0x58, 0x60, 0x50):
        s = _read_unicode_string(pml4, fo_addr + off)
        if s:
            return s
    return ""


def _resolve_path(pml4, node: bytes) -> tuple[str, int]:
    """Return (file_path, vads_process_kva)."""
    ptrs = []
    for i in range(0x28, min(len(node), 0xB0) - 8, 8):
        v = struct.unpack_from("<Q", node, i)[0]
        if _is_kptr(v):
            ptrs.append((i, v))

    path = ""
    vads_proc = 0

    # direct FileObject on the _MMVAD (Win10 1809+): a pointer whose target
    # yields a UNICODE_STRING path
    for _off, p in ptrs:
        if path:
            break
        cand = _file_name_from_fileobject(pml4, p)
        if cand and cand.lower().endswith((".dll", ".exe", ".sys", ".mui",
                                           ".acm", ".drv", ".ax", ".ocx",
                                           ".cpl", ".node", ".tsp")):
            path = cand

    # classic chain: Subsection -> ControlArea -> FilePointer -> FileObject
    if not path:
        for _off, sub in ptrs:
            try:
                ctrl = struct.unpack_from("<Q", pml4.read(sub, 8), 0)[0]
            except Exception:  # noqa: BLE001
                continue
            if not _is_kptr(ctrl):
                continue
            ca = pml4.read(ctrl, 0x80)
            for coff in range(0x20, 0x78, 8):
                fp = struct.unpack_from("<Q", ca, coff)[0] & ~0xF
                cand = _file_name_from_fileobject(pml4, fp)
                if cand:
                    path = cand
                    break
            if path:
                break

    # VadsProcess: an _EPROCESS pointer near the tail of the node
    for off, p in ptrs:
        if off >= 0x50:
            body = pml4.read(p - 0x10, 0x400)
            if b"\x00" in body and re.search(rb"[\x21-\x7e]{2,15}\.exe\x00",
                                             body):
                vads_proc = p
                break

    return path, vads_proc


def scan(img, *, want_kernel_dtb=True, progress=None) -> list[ImageVad]:
    from memory_dlllist.pagemap import Pml4, find_kernel_dtb
    pml4 = None
    if want_kernel_dtb:
        dtb = find_kernel_dtb(img)
        if dtb is not None:
            pml4 = Pml4(img, dtb)

    found: list[ImageVad] = []
    scanned = 0
    for base, block in img.stream_runs():
        for m in _TAG_RE.finditer(block):
            tag = block[m.start():m.start() + 4]
            if tag not in _IMAGE_TAGS:
                continue
            t = m.start()
            start = max(0, (t - 4) & ~7)
            win = block[start:t + 0xC0]
            node_off = None
            geom = None
            for bo in range(0x18, 0x40, 4):
                if bo + 10 > len(win):
                    break
                s = struct.unpack_from("<I", win, bo)[0]
                e = struct.unpack_from("<I", win, bo + 4)[0]
                s |= win[bo + 8] << 32          # StartingVpnHigh (Win8.1+)
                e |= win[bo + 9] << 32          # EndingVpnHigh
                if 0 < s <= e <= _USER_MAX_VPN and e - s + 1 <= _MAX_REGION_PAGES:
                    node_off = bo - 0x18
                    geom = (s, e)
                    break
            if node_off is None:
                continue
            s, e = geom
            prot = ""
            # Win7: _MMVAD_FLAGS ULONGLONG at node+0x20, Protection bit 56
            if node_off + 0x28 <= len(win):
                f7 = struct.unpack_from("<Q", win, node_off + 0x20)[0]
                pr7 = (f7 >> 56) & 0x1F
                if (pr7 & 7) in _PROT_NAME:
                    prot = _PROT_NAME[pr7 & 7]
            # Win8/10: _MMVAD_FLAGS ULONG at node+0x28 or node+0x30, bit 7
            for foff in (0x28, 0x30):
                if node_off + foff + 4 > len(win):
                    continue
                f = struct.unpack_from("<I", win, node_off + foff)[0]
                pr = (f >> 7) & 0x1F
                if (pr & 7) in (2, 3, 6, 7) or (not prot and (pr & 7) in
                                                _PROT_NAME and f):
                    prot = _PROT_NAME[pr & 7]
                    break
            node = win[node_off:node_off + 0xC0]
            path, vproc = ("", 0)
            if pml4 is not None:
                try:
                    path, vproc = _resolve_path(pml4, node)
                except Exception:  # noqa: BLE001
                    pass
            found.append(ImageVad(
                phys=base + start, pool_tag=tag.decode().rstrip(),
                start=s << 12, end=((e + 1) << 12) - 1,
                protection=prot or "EXECUTE_WRITECOPY",
                file_path=path, vads_process=vproc, backed=bool(path)))
        scanned += len(block)
        if progress:
            progress(scanned, img.mapped_size)

    best: dict = {}
    for v in found:
        k = v.key()
        if k not in best or (v.file_path and not best[k].file_path):
            best[k] = v
    return sorted(best.values(), key=lambda v: v.start)
