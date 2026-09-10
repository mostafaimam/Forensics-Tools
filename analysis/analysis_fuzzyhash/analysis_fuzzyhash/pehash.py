"""PE import hash (imphash) and Rich-header hash."""

from __future__ import annotations

import hashlib
import struct


def _rva_to_off(data, sections, rva):
    for vaddr, vsize, praw, psize in sections:
        if vaddr <= rva < vaddr + max(vsize, psize):
            return praw + (rva - vaddr)
    return None


def _cstr(data, off):
    end = data.find(b"\x00", off)
    return data[off:end if end >= 0 else off + 64]


def parse_pe(data: bytes) -> dict:
    out: dict = {"is_pe": False, "imphash": "", "rich_hash": "",
                 "imports": [], "machine": "", "timestamp": 0}
    if data[:2] != b"MZ" or len(data) < 0x40:
        return out
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return out
    out["is_pe"] = True

    # Rich header (between DOS stub and PE header)
    rich = data.find(b"Rich", 0, pe_off)
    if rich != -1 and rich + 8 <= len(data):
        key = struct.unpack_from("<I", data, rich + 4)[0]
        start = data.rfind(b"DanS".translate(bytes(range(256))), 0, rich)
        # DanS is xor'd; scan back for the decoded 'DanS'
        p = rich - 4
        vals = []
        while p >= 0x40:
            v = struct.unpack_from("<I", data, p)[0] ^ key
            vals.append(v)
            if v == 0x536E6144:                 # 'DanS'
                break
            p -= 4
        if vals and vals[-1] == 0x536E6144:
            vals = vals[::-1]
            packed = b"".join(struct.pack("<I", v) for v in vals)
            out["rich_hash"] = hashlib.md5(packed).hexdigest()

    coff = pe_off + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    out["timestamp"] = struct.unpack_from("<I", data, coff + 4)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    out["machine"] = {0x14C: "i386", 0x8664: "amd64",
                      0x1C0: "arm", 0xAA64: "arm64"}.get(machine, hex(machine))
    opt_off = coff + 20
    if opt_off + 2 > len(data):
        return out
    magic = struct.unpack_from("<H", data, opt_off)[0]
    plus = magic == 0x20B
    dd_off = opt_off + (0x70 if plus else 0x60)
    if dd_off + 16 > len(data):
        return out
    imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 8)

    sec_off = opt_off + opt_size
    sections = []
    for i in range(nsec):
        so = sec_off + i * 40
        if so + 40 > len(data):
            break
        vsize, vaddr, psize, praw = struct.unpack_from("<IIII", data, so + 8)
        sections.append((vaddr, vsize, praw, psize))

    if not imp_rva:
        return out
    it = _rva_to_off(data, sections, imp_rva)
    if it is None:
        return out
    imports: list[str] = []
    idx = 0
    while True:
        ent = it + idx * 20
        if ent + 20 > len(data):
            break
        orig_first, _t, _f, name_rva, first = struct.unpack_from(
            "<IIIII", data, ent)
        if name_rva == 0 and first == 0:
            break
        dll_off = _rva_to_off(data, sections, name_rva)
        dll = _cstr(data, dll_off).decode("latin-1", "replace").lower() \
            if dll_off is not None else ""
        dll_base = dll.rsplit(".", 1)[0]
        thunk_rva = orig_first or first
        toff = _rva_to_off(data, sections, thunk_rva)
        j = 0
        while toff is not None:
            step = 8 if plus else 4
            if toff + step > len(data):
                break
            val = struct.unpack_from("<Q" if plus else "<I", data, toff)[0]
            if val == 0:
                break
            ordinal_flag = 1 << (63 if plus else 31)
            if val & ordinal_flag:
                imports.append(f"{dll_base}.ord{val & 0xFFFF}")
            else:
                noff = _rva_to_off(data, sections, val & 0x7FFFFFFF)
                if noff is not None:
                    fn = _cstr(data, noff + 2).decode("latin-1", "replace")
                    imports.append(f"{dll_base}.{fn.lower()}")
            toff += step
            j += 1
            if j > 5000:
                break
        idx += 1
        if idx > 1000:
            break
    out["imports"] = imports
    if imports:
        out["imphash"] = hashlib.md5(
            ",".join(imports).encode("latin-1")).hexdigest()
    return out
