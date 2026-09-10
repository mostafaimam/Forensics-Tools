"""Paged reading + hex-dump rendering + search."""

from __future__ import annotations

import re
from pathlib import Path


def read_region(path: str, offset: int, length: int) -> bytes:
    with Path(path).open("rb") as fh:
        fh.seek(offset)
        return fh.read(length)


def file_size(path: str) -> int | None:
    try:
        return Path(path).stat().st_size
    except OSError:
        return None


def hexdump(data: bytes, base: int = 0, width: int = 16) -> str:
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        hexs = f"{hexs:<{width * 3 - 1}}"
        mid = width * 3 // 2
        hexs = hexs[:mid] + " " + hexs[mid:]
        ascii_ = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        out.append(f"{base + i:08x}  {hexs}  |{ascii_}|")
    return "\n".join(out)


def _needle(term: str, kind: str) -> re.Pattern:
    if kind == "hex":
        h = re.sub(r"\s+", "", term)
        if len(h) % 2:
            raise ValueError("hex search needs an even number of nibbles")
        return re.compile(re.escape(bytes.fromhex(h)))
    if kind == "text":
        return re.compile(re.escape(term.encode("utf-8")))
    if kind == "utf16":
        return re.compile(re.escape(term.encode("utf-16-le")))
    if kind == "regex":
        return re.compile(term.encode("utf-8"))
    raise ValueError(f"unknown search kind: {kind}")


def search(path: str, term: str, *, kind: str = "text", start: int = 0,
           end: int | None = None, limit: int | None = None,
           context: int = 16):
    """Yield (offset, matched_bytes, context_bytes) for each hit."""
    rx = _needle(term, kind)
    chunk = 8 << 20
    overlap = 4096
    with Path(path).open("rb") as fh:
        fh.seek(start)
        pos = start
        carry = b""
        carry_base = start
        n = 0
        while True:
            block = fh.read(chunk)
            if not block:
                break
            buf = carry + block
            base = carry_base
            horizon = len(buf) - (overlap if len(block) == chunk else 0)
            for m in rx.finditer(buf):
                if m.start() >= horizon:
                    continue
                off = base + m.start()
                if end is not None and off >= end:
                    return
                c0 = max(0, m.start() - context)
                c1 = min(len(buf), m.end() + context)
                yield off, m.group(0), buf[c0:c1]
                n += 1
                if limit and n >= limit:
                    return
            carry = buf[horizon:]
            carry_base = base + horizon
            pos = base + len(buf)
            if end is not None and pos >= end:
                break
