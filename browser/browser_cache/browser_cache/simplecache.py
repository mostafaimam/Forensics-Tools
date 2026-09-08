"""Chromium Simple Cache entry parser (Cache_Data/<hash>_0)."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from browser_cache.httphdr import header, parse_headers
from browser_cache.model import Entry

_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
_FINAL_MAGIC = 0xF4FA6F45970D41D8
_FLAG_HAS_CRC32 = 1
_FLAG_HAS_KEY_SHA256 = 2
_HEADER_LEN = 20                                  # Q + I + I + I
_EOF_LEN = 24                                     # Q + I + I + i
_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _win_time(v: int) -> str:
    if not v:
        return ""
    try:
        return (_E1601 + timedelta(microseconds=v)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _read_eof(data: bytes, end: int):
    """Parse a SimpleFileEOF that ENDS at offset *end*; return dict or None."""
    if end < _EOF_LEN:
        return None
    magic, flags, crc, size = struct.unpack_from("<QIIi", data, end - _EOF_LEN)
    if magic != _FINAL_MAGIC:
        return None
    return {"flags": flags, "stream_size": size, "start": end - _EOF_LEN}


def _parse_response_info(stream0: bytes) -> dict:
    """HttpResponseInfo pickle: [u32 payload_size][int flags][int64 req_time]
    [int64 resp_time][int hdr_len][raw headers ...]. Alignment = 4."""
    out = {"request_time": "", "response_time": "", "fields":
           {"status": 0, "reason": "", "headers": []}}
    if len(stream0) < 8:
        return out
    size = struct.unpack_from("<I", stream0, 0)[0]
    buf = stream0[4:4 + size] if 4 + size <= len(stream0) else stream0[4:]
    p = 0

    def rd_i():
        nonlocal p
        v = struct.unpack_from("<i", buf, p)[0]
        p += 4
        return v

    def rd_i64():
        nonlocal p
        v = struct.unpack_from("<q", buf, p)[0]
        p += 8
        p = (p + 3) & ~3
        return v

    try:
        rd_i()                                    # flags
        out["request_time"] = _win_time(rd_i64())
        out["response_time"] = _win_time(rd_i64())
        hdr_len = struct.unpack_from("<I", buf, p)[0]
        p += 4
        raw = buf[p:p + hdr_len]
        out["fields"] = parse_headers(raw)
    except (struct.error, IndexError):
        # fall back: scan for an HTTP status line anywhere in the pickle
        idx = buf.find(b"HTTP/1.")
        if idx == -1:
            idx = stream0.find(b"HTTP/1.")
            buf = stream0
        if idx != -1:
            out["fields"] = parse_headers(buf[idx:idx + 8192])
    return out


def parse_entry(path: str) -> Entry | None:
    data = Path(path).read_bytes()
    if len(data) < _HEADER_LEN + _EOF_LEN:
        return None
    magic, version, key_len, key_hash = struct.unpack_from("<QIII", data, 0)
    if magic != _INITIAL_MAGIC:
        return None
    key = data[_HEADER_LEN:_HEADER_LEN + key_len].decode("utf-8", "replace")
    key_end = _HEADER_LEN + key_len

    # the URL key may carry a cache-key prefix like "1/0/_dk_..." or
    # "_dk_https://... https://... https://example.com/x"
    url = key
    if " " in key and "://" in key:
        url = key.rsplit(" ", 1)[-1]

    ent = Entry(cache="simple", url=url, entry_file=Path(path).name)

    eof0 = _read_eof(data, len(data))
    stream0 = b""
    stream1_end = key_end
    if eof0:
        s0 = eof0["stream_size"]
        sha_len = 32 if (eof0["flags"] & _FLAG_HAS_KEY_SHA256) else 0
        s0_start = eof0["start"] - sha_len - s0
        if s0_start >= key_end:
            stream0 = data[s0_start:s0_start + s0]
        eof1 = _read_eof(data, s0_start - sha_len if False else s0_start)
        if eof1:
            stream1_end = eof1["start"]

    body = data[key_end:stream1_end] if stream1_end > key_end else b""
    ent._body = body
    ent.body_size = len(body)

    info = _parse_response_info(stream0) if stream0 else \
        {"request_time": "", "response_time": "",
         "fields": parse_headers(_scan_headers(data, key_end))}
    ent.request_time = info["request_time"]
    ent.response_time = info["response_time"]
    f = info["fields"]
    ent.status = f.get("status", 0)
    ent.reason = f.get("reason", "")
    ent.content_type = header(f, "content-type").split(";")[0].strip()
    ent.content_encoding = header(f, "content-encoding")
    cl = header(f, "content-length")
    ent.declared_length = int(cl) if cl.isdigit() else 0
    ent.last_modified = header(f, "last-modified")
    ent.expires = header(f, "expires")
    ent.server = header(f, "server")
    ent.etag = header(f, "etag")
    if ent.declared_length and ent.body_size and \
            ent.body_size < ent.declared_length:
        ent.truncated = True
    return ent


def _scan_headers(data: bytes, after: int) -> bytes:
    idx = data.find(b"HTTP/1.", after)
    return data[idx:idx + 8192] if idx != -1 else b""


def iter_entries(cache_dir: str):
    d = Path(cache_dir)
    files = []
    if d.is_dir():
        # Cache_Data/ under a Cache/ dir, or the dir itself
        for cand in (d / "Cache_Data", d):
            if cand.is_dir():
                files = sorted(cand.glob("*_0"))
                if files:
                    break
        if not files:
            files = sorted(d.rglob("*_0"))
    elif d.name.endswith("_0"):
        files = [d]
    for f in files:
        try:
            e = parse_entry(str(f))
        except (OSError, struct.error):
            e = None
        if e:
            yield e
