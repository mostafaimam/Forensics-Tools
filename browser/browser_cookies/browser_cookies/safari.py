"""Safari ``Cookies.binarycookies`` - a packed binary format, no SQLite."""

from __future__ import annotations

import struct

from browser_cookies import timeconv as _t
from browser_cookies.model import Cookie


def _cstr(buf: bytes, off: int) -> str:
    if off <= 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    return buf[off:end if end != -1 else len(buf)].decode("utf-8", "replace")


def _parse_cookie(page: bytes, start: int, browser: str, profile: str,
                  src: str) -> Cookie | None:
    if start + 0x38 > len(page):
        return None
    (size,) = struct.unpack_from("<I", page, start)
    blob = page[start:start + size]
    if len(blob) < 0x38:
        return None
    flags = struct.unpack_from("<I", blob, 0x08)[0]
    url_o, name_o, path_o, val_o = struct.unpack_from("<IIII", blob, 0x10)
    expiry, creation = struct.unpack_from("<dd", blob, 0x28)
    host = _cstr(blob, url_o)
    name = _cstr(blob, name_o)
    path = _cstr(blob, path_o) or "/"
    value = _cstr(blob, val_o)
    if not host or not name:
        return None
    return Cookie(
        browser=browser, profile=profile,
        host=host.lstrip("."), name=name, path=path,
        created=_t.cocoa(creation),
        expires=_t.cocoa(expiry) if expiry else "",
        secure=bool(flags & 0x1), http_only=bool(flags & 0x4),
        samesite="unspecified", session=not expiry,
        value_len=len(value), value=value, source_db=src)


def parse(db_path: str, browser: str, profile: str) -> list[Cookie]:
    try:
        with open(db_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    if data[:4] != b"cook":
        return []
    out: list[Cookie] = []
    try:
        (n_pages,) = struct.unpack_from(">I", data, 4)
        page_sizes = struct.unpack_from(f">{n_pages}I", data, 8)
        pos = 8 + n_pages * 4
        for psize in page_sizes:
            page = data[pos:pos + psize]
            pos += psize
            if page[:4] != b"\x00\x00\x01\x00":
                continue
            (n_cookies,) = struct.unpack_from("<I", page, 4)
            offsets = struct.unpack_from(f"<{n_cookies}I", page, 8)
            for off in offsets:
                try:
                    c = _parse_cookie(page, off, browser, profile,
                                      str(db_path))
                    if c:
                        out.append(c)
                except (struct.error, IndexError):
                    continue
    except (struct.error, IndexError):
        pass
    return out
