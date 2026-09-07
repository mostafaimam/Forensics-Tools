"""Parse HTTP/1.x messages out of a reassembled byte stream."""

from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass, field

_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH",
            b"CONNECT", b"TRACE", b"PROPFIND", b"MKCOL")


@dataclass
class Message:
    is_request: bool
    method: str = ""
    target: str = ""
    version: str = ""
    status: int = 0
    reason: str = ""
    headers: list = field(default_factory=list)      # [(name, value)]
    body: bytes = b""
    body_truncated: bool = False
    raw_encoding: str = ""

    def header(self, name: str) -> str:
        nl = name.lower()
        for k, v in self.headers:
            if k.lower() == nl:
                return v
        return ""


def _headers(block: bytes):
    lines = block.split(b"\r\n")
    out = []
    for ln in lines:
        if b":" not in ln:
            continue
        k, _, v = ln.partition(b":")
        out.append((k.strip().decode("latin-1"),
                    v.strip().decode("latin-1", "replace")))
    return lines[0], out


def _dechunk(data: bytes) -> tuple[bytes, bool]:
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        j = data.find(b"\r\n", i)
        if j == -1:
            return bytes(out), True
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(out), True
        if size == 0:
            return bytes(out), False
        start = j + 2
        if start + size > n:
            out.extend(data[start:])
            return bytes(out), True
        out.extend(data[start:start + size])
        i = start + size + 2
    return bytes(out), True


def _decode_body(body: bytes, enc: str) -> tuple[bytes, str]:
    enc = enc.lower().strip()
    try:
        if enc in ("gzip", "x-gzip"):
            return gzip.decompress(body), "gzip"
        if enc == "deflate":
            try:
                return zlib.decompress(body), "deflate"
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS), "deflate(raw)"
    except (OSError, zlib.error, EOFError):
        return body, f"{enc}(undecoded)"
    return body, ""


def parse_stream(data: bytes, *, is_request: bool, max_body: int = 64 << 20):
    """Yield :class:`Message` objects found in *data*."""
    pos = 0
    n = len(data)
    while pos < n:
        hdr_end = data.find(b"\r\n\r\n", pos)
        if hdr_end == -1:
            break
        first, headers = _headers(data[pos:hdr_end])
        msg = Message(is_request=is_request)
        parts = first.split(b" ", 2)
        if is_request:
            if not parts or parts[0] not in _METHODS:
                pos = hdr_end + 4
                continue
            msg.method = parts[0].decode()
            msg.target = parts[1].decode("latin-1", "replace") if len(parts) > 1 \
                else ""
            msg.version = parts[2].decode("latin-1", "replace") if len(parts) > 2 \
                else ""
        else:
            if not first.startswith(b"HTTP/") or len(parts) < 2 \
                    or not parts[1].isdigit():
                pos = hdr_end + 4
                continue
            msg.version = parts[0].decode("latin-1")
            msg.status = int(parts[1])
            msg.reason = parts[2].decode("latin-1", "replace") if len(parts) > 2 \
                else ""
        msg.headers = headers
        body_start = hdr_end + 4

        te = msg.header("transfer-encoding").lower()
        cl = msg.header("content-length")
        head_only = (msg.method == "HEAD")
        no_body_status = msg.status in (204, 304) or (100 <= msg.status < 200)

        if head_only or no_body_status:
            body = b""
            pos = body_start
        elif "chunked" in te:
            body, trunc = _dechunk(data[body_start:])
            msg.body_truncated = trunc
            # advance past the terminating chunk if we can find it
            term = data.find(b"\r\n0\r\n\r\n", body_start)
            pos = (term + 7) if term != -1 else n
        elif cl.isdigit():
            length = int(cl)
            body = data[body_start:body_start + length]
            if len(body) < length:
                msg.body_truncated = True
            pos = body_start + length
        elif is_request:
            body = b""
            pos = body_start
        else:
            # response with no length: body runs to end of stream
            body = data[body_start:]
            pos = n

        if len(body) > max_body:
            body = body[:max_body]
            msg.body_truncated = True

        ce = msg.header("content-encoding")
        if ce and body:
            body, msg.raw_encoding = _decode_body(body, ce)
        msg.body = body
        yield msg


def transactions(client_stream: bytes, server_stream: bytes):
    reqs = list(parse_stream(client_stream, is_request=True))
    resps = list(parse_stream(server_stream, is_request=False))
    for i in range(max(len(reqs), len(resps))):
        yield (reqs[i] if i < len(reqs) else None,
               resps[i] if i < len(resps) else None)
