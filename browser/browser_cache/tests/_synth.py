"""Build Chromium Simple Cache + Firefox cache2 entry files for the tests."""

from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

_INITIAL_MAGIC = 0xFCFB6D1BA7725C30
_FINAL_MAGIC = 0xF4FA6F45970D41D8
_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_CHUNK = 256 * 1024


def win_us(dt):
    return int((dt - _E1601).total_seconds() * 1_000_000)


def unix_s(dt):
    return int(dt.timestamp())


def _resp_headers(status, ctype, length, extra=()):
    lines = [f"HTTP/1.1 {status} OK", f"Content-Type: {ctype}"]
    if length is not None:
        lines.append(f"Content-Length: {length}")
    lines += list(extra)
    return "\x00".join(lines).encode("latin-1") + b"\x00\x00"


def _http_headers_crlf(status, ctype, length, extra=()):
    lines = [f"HTTP/1.1 {status} OK", f"Content-Type: {ctype}"]
    if length is not None:
        lines.append(f"Content-Length: {length}")
    lines += list(extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


# --------------------------------------------------------------------------
# Chromium Simple Cache  ->  <hash>_0
# --------------------------------------------------------------------------

def simple_entry(path: Path, *, url, body=b"", status=200,
                 ctype="application/octet-stream", req_time=None, resp_time=None,
                 declared_length=None, extra_headers=(), version=8):
    key = url.encode("utf-8")
    hdr = struct.pack("<QIII", _INITIAL_MAGIC, version, len(key),
                      zlib.crc32(key) & 0xFFFFFFFF)

    # stream 0 = HttpResponseInfo pickle
    raw = _resp_headers(status, ctype,
                        declared_length if declared_length is not None
                        else len(body), extra_headers)
    payload = struct.pack("<i", 0)
    payload += struct.pack("<q", win_us(req_time) if req_time else 0)
    payload += struct.pack("<q", win_us(resp_time) if resp_time else 0)
    payload += struct.pack("<I", len(raw)) + raw
    stream0 = struct.pack("<I", len(payload)) + payload

    # SimpleFileEOF is 20 bytes of fields + 4 bytes tail padding (uint64 align)
    eof1 = struct.pack("<QIIi", _FINAL_MAGIC, 0, 0, len(body)) + b"\x00" * 4
    eof0 = struct.pack("<QIIi", _FINAL_MAGIC, 0, 0, len(stream0)) + b"\x00" * 4

    Path(path).write_bytes(hdr + key + body + eof1 + stream0 + eof0)


def simple_cache_dir(root: Path, entries: list[dict]) -> Path:
    cd = root / "Cache" / "Cache_Data"
    cd.mkdir(parents=True)
    for i, e in enumerate(entries):
        simple_entry(cd / f"{i:016x}_0", **e)
    return root / "Cache"


# --------------------------------------------------------------------------
# Firefox cache2  ->  entries/<sha1>
# --------------------------------------------------------------------------

def cache2_entry(path: Path, *, url, body=b"", status=200, ctype="text/html",
                 method="GET", fetch_count=1, last_fetched=None,
                 last_modified=None, expiration=None, declared_length=None,
                 extra_headers=(), version=3):
    key = f":{url}".encode("utf-8") + b"\x00"
    num_chunks = (len(body) + _CHUNK - 1) // _CHUNK if body else 0
    hashes = b"\x00\x00" * num_chunks

    header = struct.pack(
        ">8I", version, fetch_count,
        unix_s(last_fetched) if last_fetched else 0,
        unix_s(last_modified) if last_modified else 0,
        0,
        unix_s(expiration) if expiration else 0,
        len(key), 0)

    rh = _http_headers_crlf(
        status, ctype,
        declared_length if declared_length is not None else len(body),
        extra_headers)
    elements = (b"request-method\x00" + method.encode() + b"\x00"
                + b"response-head\x00" + rh + b"\x00")

    meta = hashes + header + key + elements
    meta_off = len(body)
    Path(path).write_bytes(body + meta + struct.pack(">I", meta_off))


def cache2_dir(root: Path, entries: list[dict]) -> Path:
    ed = root / "cache2" / "entries"
    ed.mkdir(parents=True)
    for i, e in enumerate(entries):
        cache2_entry(ed / f"{i:040X}", **e)
    return root / "cache2"
