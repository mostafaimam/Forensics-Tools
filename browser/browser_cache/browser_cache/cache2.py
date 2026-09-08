"""Firefox cache2 entry parser (cache2/entries/<sha1>)."""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from pathlib import Path

from browser_cache.httphdr import header, parse_headers
from browser_cache.model import Entry

_CHUNK = 256 * 1024


def _unix(v: int) -> str:
    if not v:
        return ""
    try:
        return datetime.fromtimestamp(v, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def _split_elements(blob: bytes) -> dict:
    parts = blob.split(b"\x00")
    out: dict = {}
    it = iter(parts)
    for name in it:
        try:
            value = next(it)
        except StopIteration:
            break
        if name:
            out[name.decode("latin-1", "replace")] = value
    return out


def parse_entry(path: str) -> Entry | None:
    data = Path(path).read_bytes()
    if len(data) < 8:
        return None
    meta_off = struct.unpack_from(">I", data, len(data) - 4)[0]
    if meta_off > len(data) - 4 or meta_off > len(data):
        # some builds store it differently - scan for a plausible key
        meta_off = _guess_meta_offset(data)
        if meta_off is None:
            return None
    body = data[:meta_off]
    meta = data[meta_off:len(data) - 4]

    num_chunks = (meta_off + _CHUNK - 1) // _CHUNK if meta_off else 0
    p = num_chunks * 2
    hdr_fields = {}
    key = ""
    elements: dict = {}
    try:
        version = struct.unpack_from(">I", meta, p)[0]
        hlen = 32 if version >= 2 else 28
        vals = struct.unpack_from(">%dI" % (hlen // 4), meta, p)
        (_v, fetch_count, last_fetched, last_modified, _frec, expiration,
         key_size) = vals[:7]
        p += hlen
        key = meta[p:p + key_size].split(b"\x00")[0].decode("utf-8", "replace")
        p += key_size
        elements = _split_elements(meta[p:])
        hdr_fields = dict(fetch_count=fetch_count, last_fetched=last_fetched,
                          last_modified=last_modified, expiration=expiration)
    except (struct.error, IndexError):
        # tolerant: find the key + response-head by scanning
        elements = _split_elements(meta)
        for cand in meta.split(b"\x00"):
            if b"://" in cand:
                key = cand.decode("utf-8", "replace")
                break

    url = key
    if ":" in key:
        # keys look like ":https://x/y", "a,:https://x/y", "O^pk,:https://x/y"
        i = key.rfind(":http")
        if i != -1:
            url = key[i + 1:]
    ent = Entry(browser="Firefox", cache="cache2", url=url,
                entry_file=Path(path).name,
                fetch_count=hdr_fields.get("fetch_count", 0) or 0,
                last_fetched=_unix(hdr_fields.get("last_fetched", 0)))
    ent.last_modified = _unix(hdr_fields.get("last_modified", 0)) or ""
    ent.expires = _unix(hdr_fields.get("expiration", 0)) or ""
    ent.method = (elements.get("request-method", b"GET")
                  .decode("latin-1", "replace") or "GET")
    ent._body = body
    ent.body_size = len(body)

    rh = elements.get("response-head") or elements.get(
        "original-response-headers") or b""
    if rh:
        f = parse_headers(rh)
        ent.status = f.get("status", 0)
        ent.reason = f.get("reason", "")
        ent.content_type = header(f, "content-type").split(";")[0].strip()
        ent.content_encoding = header(f, "content-encoding")
        cl = header(f, "content-length")
        ent.declared_length = int(cl) if cl.isdigit() else 0
        ent.server = header(f, "server")
        ent.etag = header(f, "etag")
        if not ent.last_modified:
            ent.last_modified = header(f, "last-modified")
        if not ent.expires:
            ent.expires = header(f, "expires")
    if not ent.content_type and "content-type" in elements:
        ent.content_type = elements["content-type"].decode(
            "latin-1", "replace").split(";")[0].strip()
    if ent.declared_length and ent.body_size and \
            ent.body_size < ent.declared_length:
        ent.truncated = True
    return ent


def _guess_meta_offset(data: bytes):
    idx = data.rfind(b"response-head")
    if idx == -1:
        return None
    # walk back to a likely metadata start (num_chunks*2 + header + key).
    # good enough: metadata starts within 8 KiB before "response-head".
    return max(0, idx - 4096)


def iter_entries(cache_dir: str):
    d = Path(cache_dir)
    files = []
    if d.is_dir():
        for cand in (d / "entries", d):
            if cand.is_dir():
                files = sorted(f for f in cand.iterdir() if f.is_file())
                if files:
                    break
        if not files:
            files = sorted(f for f in d.rglob("*") if f.is_file())
    elif d.is_file():
        files = [d]
    for f in files:
        try:
            e = parse_entry(str(f))
        except (OSError, struct.error):
            e = None
        if e and e.url:
            yield e
