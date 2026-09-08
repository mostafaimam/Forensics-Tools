"""Shared: parse an HTTP response header block into fields."""

from __future__ import annotations

import re

_STATUS = re.compile(rb"HTTP/\d\.\d\s+(\d{3})\s*([^\r\n\x00]*)")


def parse_headers(raw: bytes) -> dict:
    """*raw* is a status line + headers, separated by \\r\\n, \\n or \\0."""
    out: dict = {"status": 0, "reason": "", "headers": []}
    if not raw:
        return out
    m = _STATUS.search(raw)
    if m:
        out["status"] = int(m.group(1))
        out["reason"] = m.group(2).decode("latin-1", "replace").strip()
    # header lines can be split on any of \r\n, \n, or \0
    lines = re.split(rb"\r\n|\n|\x00", raw)
    for ln in lines[1:]:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        out["headers"].append((k.strip().decode("latin-1", "replace"),
                               v.strip().decode("latin-1", "replace")))
    return out


def header(fields: dict, name: str) -> str:
    nl = name.lower()
    for k, v in fields.get("headers", []):
        if k.lower() == nl:
            return v
    return ""


def decode_body(body: bytes, encoding: str) -> tuple[bytes, str]:
    enc = (encoding or "").lower().strip()
    try:
        if enc in ("gzip", "x-gzip"):
            import gzip
            return gzip.decompress(body), "gzip"
        if enc == "deflate":
            import zlib
            try:
                return zlib.decompress(body), "deflate"
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), "deflate(raw)"
        if enc == "br":
            return body, "br(not-decoded)"
    except (OSError, Exception):  # noqa: BLE001
        return body, f"{enc}(undecoded)"
    return body, ""
