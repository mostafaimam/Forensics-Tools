"""Discover cache stores, parse entries, flag, and optionally extract."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from browser_cache import cache2 as _cache2
from browser_cache import simplecache as _simple
from browser_cache.httphdr import decode_body

_EXEC = re.compile(r"\.(exe|dll|msi|scr|jar|apk|dmg|pkg)(\?|$)", re.I)
_ARCHIVE = re.compile(r"\.(zip|rar|7z|gz|tar|cab)(\?|$)", re.I)
_SCRIPT_CT = ("application/javascript", "text/javascript",
              "application/x-javascript")
_MAGIC = [(b"MZ", "application/x-dosexec"), (b"\x7fELF", "application/x-elf"),
          (b"PK\x03\x04", "application/zip"), (b"%PDF", "application/pdf"),
          (b"\x1f\x8b", "application/gzip")]


@dataclass
class Result:
    entries: list = field(default_factory=list)
    stores: int = 0
    extracted: int = 0
    errors: list = field(default_factory=list)


def _detect(body: bytes) -> str:
    for sig, ct in _MAGIC:
        if body[:8].startswith(sig):
            return ct
    return ""


def _flag(e) -> None:
    u = e.url
    host = ""
    try:
        host = urlparse(u).hostname or ""
    except ValueError:
        pass
    det = _detect(e._body) if e._body else ""
    if det in ("application/x-dosexec", "application/x-elf"):
        e.notable.append("cached response body is an executable")
    elif _EXEC.search(u):
        e.notable.append("cached URL is an executable / installer")
    elif _ARCHIVE.search(u) or det in ("application/zip", "application/gzip"):
        e.notable.append("cached archive")
    ct = (e.content_type or "").lower()
    if det and ct and det.split("/")[0] != ct.split("/")[0] and \
            ct not in ("application/octet-stream", ""):
        e.notable.append(f"content-type / body mismatch (says {ct}, is {det})")
    if host:
        try:
            if ipaddress.ip_address(host).is_global:
                e.notable.append("cached from a raw IP host")
        except ValueError:
            pass
    if any(ct.startswith(s) for s in _SCRIPT_CT) and e.body_size > 200000:
        e.notable.append("large cached script")
    if e.truncated:
        e.notable.append("body shorter than Content-Length (partial cache)")


def _discover(root: str) -> list[tuple[str, str]]:
    """Return [(kind, path)] for cache stores under *root*."""
    r = Path(root)
    out: list[tuple[str, str]] = []
    if r.is_file():
        if r.name.endswith("_0"):
            out.append(("simple", str(r)))
        else:
            out.append(("cache2", str(r)))
        return out
    for dirpath, dirnames, names in os.walk(r):
        base = Path(dirpath).name
        if base == "Cache_Data" and any(n.endswith("_0") for n in names):
            out.append(("simple", dirpath))
            dirnames[:] = []
        elif base == "entries" and Path(dirpath).parent.name == "cache2":
            out.append(("cache2", dirpath))
            dirnames[:] = []
    return out


def analyze(paths, *, extract_dir: str | None = None, keep_bodies=False,
            min_size: int = 0, decode: bool = True) -> Result:
    res = Result()
    keep = keep_bodies or extract_dir is not None
    for path in paths:
        try:
            stores = _discover(str(path))
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            continue
        for kind, sp in stores:
            res.stores += 1
            it = (_simple.iter_entries(sp) if kind == "simple"
                  else _cache2.iter_entries(sp))
            for e in it:
                if e.body_size < min_size:
                    continue
                if e._body and decode and e.content_encoding:
                    e._body, e.content_encoding = decode_body(
                        e._body, e.content_encoding)
                    e.body_size = len(e._body)
                _flag(e)
                if keep and e._body:
                    e.sha256 = hashlib.sha256(e._body).hexdigest()
                else:
                    e._body = b""
                res.entries.append(e)

    if extract_dir:
        res.extracted = _extract(res.entries, extract_dir)

    res.entries.sort(key=lambda e: (not (e.response_time or e.last_fetched),
                                    e.response_time or e.last_fetched or "",
                                    e.url))
    return res


def _extract(entries, out_dir: str) -> int:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    used: dict[str, int] = {}
    n = 0
    for i, e in enumerate(entries):
        if not e._body:
            continue
        name = e.filename or f"obj{i}"
        name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120] or f"obj{i}"
        if "." not in name and e.content_type:
            ext = {"text/html": "html", "text/css": "css",
                   "application/javascript": "js", "image/jpeg": "jpg",
                   "image/png": "png", "image/gif": "gif",
                   "image/webp": "webp", "application/json": "json",
                   "application/pdf": "pdf"}.get(e.content_type)
            if ext:
                name += f".{ext}"
        if name in used:
            used[name] += 1
            stem = Path(name)
            name = f"{stem.stem}_{used[name]}{stem.suffix}"
        else:
            used[name] = 0
        (d / name).write_bytes(e._body)
        e.saved_as = name
        n += 1
    return n
