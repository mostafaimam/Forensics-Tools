"""Binary XML (the EVTX BinXml dialect) parser.

Everything is parsed against the containing 64 KiB chunk buffer using
chunk-relative offsets, because name strings, template definitions and even
substitution values are all referenced by chunk offset.  A template body is
parsed once (keeping ``Sub`` placeholders) and re-rendered per instance.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

T_EOF = 0x00
T_OPEN_START = 0x01
T_CLOSE_START = 0x02
T_CLOSE_EMPTY = 0x03
T_END_ELEMENT = 0x04
T_VALUE = 0x05
T_ATTRIBUTE = 0x06
T_CDATA = 0x07
T_CHARREF = 0x08
T_ENTITYREF = 0x09
T_PI_TARGET = 0x0A
T_PI_DATA = 0x0B
T_TEMPLATE_INSTANCE = 0x0C
T_NORMAL_SUB = 0x0D
T_OPTIONAL_SUB = 0x0E
T_FRAGMENT_HEADER = 0x0F


class BinXmlError(ValueError):
    pass


@dataclass
class Element:
    name: str
    attributes: list = field(default_factory=list)   # list[(str, value)]
    children: list = field(default_factory=list)      # Element | Sub | str


@dataclass
class Sub:
    index: int
    optional: bool


def filetime_to_iso(ticks: int) -> str:
    if ticks <= 0:
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, OSError, ValueError):
        return ""


class _R:
    __slots__ = ("b", "p")

    def __init__(self, b: bytes, p: int) -> None:
        self.b = b
        self.p = p

    def u8(self):
        v = self.b[self.p]; self.p += 1; return v

    def u16(self):
        v = struct.unpack_from("<H", self.b, self.p)[0]; self.p += 2; return v

    def u32(self):
        v = struct.unpack_from("<I", self.b, self.p)[0]; self.p += 4; return v

    def raw(self, n):
        v = self.b[self.p:self.p + n]; self.p += n; return v


class Context:
    def __init__(self, chunk: bytes) -> None:
        self.chunk = chunk
        self._names: dict[int, str] = {}
        self._templates: dict[int, list] = {}

    # -- name strings ------------------------------------------------
    def name_at(self, offset: int) -> str:
        cached = self._names.get(offset)
        if cached is not None:
            return cached
        b = self.chunk
        if offset + 8 > len(b):
            return ""
        length = struct.unpack_from("<H", b, offset + 6)[0]
        s = b[offset + 8: offset + 8 + length * 2].decode("utf-16-le", "replace")
        self._names[offset] = s
        return s

    # -- public entry point --------------------------------------
    def parse_from(self, offset: int) -> list[Element]:
        r = _R(self.chunk, offset)
        return self._content(r)

    # -- fragment content --------------------------------------
    def _content(self, r: _R) -> list[Element]:
        if r.p < len(r.b) and (r.b[r.p] & 0x0F) == T_FRAGMENT_HEADER:
            r.p += 4
        if r.p < len(r.b) and (r.b[r.p] & 0x0F) == T_TEMPLATE_INSTANCE:
            return self._instance(r)
        return [n for n in self._nodes(r) if isinstance(n, Element)]

    def _instance(self, r: _R) -> list[Element]:
        token_pos = r.p
        r.u8()                       # 0x0c
        r.u8()                       # unknown
        r.u32()                      # template id
        template_offset = r.u32()
        if template_offset >= token_pos:
            # resident definition begins right here
            data_length = struct.unpack_from("<I", r.b, r.p + 20)[0]
            body = self._nodes(_R(r.b, r.p + 24))
            self._templates[template_offset] = body
            r.p = r.p + 24 + data_length
        body = self._templates.get(template_offset)
        if body is None:
            body = self._nodes(_R(self.chunk, template_offset + 24))
            self._templates[template_offset] = body

        subs = self._subs(r)
        return [self._render(n, subs) for n in body if isinstance(n, Element)]

    def _subs(self, r: _R) -> list:
        count = r.u32()
        decl = []
        for _ in range(count):
            size = r.u16()
            vtype = r.u8()
            r.u8()
            decl.append((size, vtype))
        out = []
        for size, vtype in decl:
            start = r.p
            r.p += size
            if (vtype & 0x7F) == 0x21:       # nested BinXml, in place
                out.append(self.parse_from(start) if size else [])
            elif (vtype & 0x7F) == 0x00 or size == 0:
                out.append("")
            else:
                out.append(_variant(vtype, self.chunk[start:start + size], self))
        return out

    # -- node stream --------------------------------------------
    def _nodes(self, r: _R) -> list:
        out: list = []
        n = len(r.b)
        guard = 0
        while r.p < n:
            guard += 1
            if guard > 200000:
                raise BinXmlError("runaway parse")
            token = r.b[r.p] & 0x0F
            more = bool(r.b[r.p] & 0x40)
            if token == T_EOF:
                r.p += 1
                break
            if token == T_FRAGMENT_HEADER:
                r.p += 4
                continue
            if token == T_OPEN_START:
                out.append(self._element(r, more))
            elif token == T_CLOSE_START:
                r.p += 1
            elif token in (T_CLOSE_EMPTY, T_END_ELEMENT):
                r.p += 1
                break
            elif token == T_VALUE:
                out.append(self._value(r))
            elif token == T_NORMAL_SUB:
                r.u8(); idx = r.u16(); r.u8()
                out.append(Sub(idx, False))
            elif token == T_OPTIONAL_SUB:
                r.u8(); idx = r.u16(); r.u8()
                out.append(Sub(idx, True))
            elif token == T_TEMPLATE_INSTANCE:
                out.extend(self._instance(r))
            elif token == T_CDATA:
                r.u8()
                out.append(r.raw(r.u16()).decode("utf-16-le", "replace"))
            elif token in (T_CHARREF, T_ENTITYREF, T_PI_TARGET, T_PI_DATA):
                r.u8(); r.u16()
            else:
                raise BinXmlError(f"token {token:#x} @ {r.p}")
        return out

    def _element(self, r: _R, more: bool) -> Element:
        base = r.p
        r.u8()                       # token
        r.u16()                      # dependency id
        r.u32()                      # data size
        name_off = r.u32()           # r.p == base + 11
        if name_off >= base:
            name = self._inline_name(r)   # inline NameString sits right here
        else:
            name = self.name_at(name_off)
        if more:
            r.u32()                  # attribute list byte-size (after the name)
        el = Element(name)

        while r.p < len(r.b) and (r.b[r.p] & 0x0F) == T_ATTRIBUTE:
            el.attributes.append(self._attribute(r))

        t = r.b[r.p] & 0x0F
        if t == T_CLOSE_EMPTY:
            r.p += 1
            return el
        if t == T_CLOSE_START:
            r.p += 1
        el.children = self._nodes(r)
        return el

    def _inline_name(self, r: _R) -> str:
        base = r.p
        length = struct.unpack_from("<H", r.b, base + 6)[0]
        s = r.b[base + 8: base + 8 + length * 2].decode("utf-16-le", "replace")
        r.p = base + 8 + length * 2 + 2
        return s

    def _attribute(self, r: _R):
        base = r.p
        r.u8()                       # 0x06
        name_off = r.u32()
        if name_off >= base:
            name = self._inline_name(r)
        else:
            name = self.name_at(name_off)
        t = r.b[r.p] & 0x0F
        if t == T_VALUE:
            return (name, self._value(r))
        if t in (T_NORMAL_SUB, T_OPTIONAL_SUB):
            r.u8(); idx = r.u16(); r.u8()
            return (name, Sub(idx, t == T_OPTIONAL_SUB))
        return (name, "")

    def _value(self, r: _R):
        r.u8()                       # 0x05
        vtype = r.u8()
        if vtype == 0x00:
            return ""
        if vtype == 0x01:
            return r.raw(r.u16() * 2).decode("utf-16-le", "replace")
        return _variant_inline(vtype, r, self)

    # -- rendering ----------------------------------------------
    def _render(self, node, subs):
        if not isinstance(node, Element):
            return node
        e = Element(node.name)
        for k, v in node.attributes:
            rv = self._resolve(v, subs)
            if rv not in (None, ""):
                e.attributes.append((k, rv))
        for c in node.children:
            rc = self._resolve(c, subs)
            if rc is None:
                continue
            if isinstance(rc, list):
                e.children.extend(rc)
            else:
                e.children.append(rc)
        return e

    def _resolve(self, node, subs):
        if isinstance(node, Sub):
            if node.index >= len(subs):
                return None if node.optional else ""
            val = subs[node.index]
            if val is None or (node.optional and val == ""):
                return None
            return val
        if isinstance(node, Element):
            return self._render(node, subs)
        return node


# ---- variant value decoding -------------------------------------------
def _guid(b: bytes) -> str:
    if len(b) < 16:
        return ""
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    return (f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{b[8:10].hex().upper()}-{b[10:16].hex().upper()}}}")


def _sid(b: bytes) -> str:
    if len(b) < 8:
        return ""
    count = b[1]
    subs = struct.unpack_from(f"<{count}I", b, 8) \
        if len(b) >= 8 + 4 * count else ()
    return "S-{}-{}{}".format(b[0], int.from_bytes(b[2:8], "big"),
                              "".join(f"-{s}" for s in subs))


def _systemtime(b: bytes) -> str:
    if len(b) < 16:
        return ""
    y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", b, 0)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"


def _variant(vtype: int, data: bytes, ctx: Context):
    base = vtype & 0x7F
    if vtype & 0x80:
        return _variant_array(base, data)
    try:
        if base in (0x00,):
            return ""
        if base == 0x01:
            return data.decode("utf-16-le", "replace").rstrip("\x00")
        if base == 0x02:
            return data.decode("latin-1", "replace").rstrip("\x00")
        if base == 0x03:
            return str(struct.unpack_from("<b", data, 0)[0])
        if base == 0x04:
            return str(data[0])
        if base == 0x05:
            return str(struct.unpack_from("<h", data, 0)[0])
        if base == 0x06:
            return str(struct.unpack_from("<H", data, 0)[0])
        if base == 0x07:
            return str(struct.unpack_from("<i", data, 0)[0])
        if base == 0x08:
            return str(struct.unpack_from("<I", data, 0)[0])
        if base == 0x09:
            return str(struct.unpack_from("<q", data, 0)[0])
        if base == 0x0A:
            return str(struct.unpack_from("<Q", data, 0)[0])
        if base == 0x0B:
            return repr(struct.unpack_from("<f", data, 0)[0])
        if base == 0x0C:
            return repr(struct.unpack_from("<d", data, 0)[0])
        if base == 0x0D:
            return "true" if any(data) else "false"
        if base == 0x0E:
            return data.hex().upper()
        if base == 0x0F:
            return _guid(data)
        if base == 0x10:
            return str(int.from_bytes(data, "little"))
        if base == 0x11:
            return filetime_to_iso(struct.unpack_from("<Q", data, 0)[0])
        if base == 0x12:
            return _systemtime(data)
        if base == 0x13:
            return _sid(data)
        if base == 0x14:
            return "0x" + data[:4][::-1].hex()
        if base == 0x15:
            return "0x" + data[:8][::-1].hex()
    except (struct.error, IndexError):
        return ""
    return data.hex().upper()


def _variant_array(base: int, data: bytes) -> str:
    if base == 0x01:
        return " ".join(p for p in data.decode("utf-16-le", "replace")
                        .split("\x00") if p)
    fmt = {0x03: "b", 0x04: "B", 0x05: "h", 0x06: "H", 0x07: "i", 0x08: "I",
           0x09: "q", 0x0A: "Q"}.get(base)
    if not fmt:
        return data.hex().upper()
    sz = struct.calcsize("<" + fmt)
    return " ".join(str(struct.unpack_from("<" + fmt, data, i)[0])
                    for i in range(0, len(data) - sz + 1, sz))


def _variant_inline(vtype: int, r: _R, ctx: Context):
    fixed = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8,
             0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0D: 4, 0x0F: 16, 0x10: 8, 0x11: 8,
             0x12: 16, 0x14: 4, 0x15: 8}
    if vtype == 0x02:
        return r.raw(r.u16()).decode("latin-1", "replace")
    if vtype == 0x0E:
        return r.raw(r.u32()).hex().upper()
    if vtype == 0x13:
        count = r.b[r.p + 1]
        return _sid(r.raw(8 + 4 * count))
    return _variant(vtype, r.raw(fixed.get(vtype, 0)), ctx)
