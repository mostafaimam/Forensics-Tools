"""Turn a capture into HTTP transactions and extractable objects."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from network_http import flags as _flags
from network_http import pcap as _pcap
from network_http.httpmsg import transactions
from network_http.layers import decode
from network_http.tcp import Assembler

_MAGIC = [
    (b"MZ", "exe", "application/x-dosexec"),
    (b"\x7fELF", "elf", "application/x-elf"),
    (b"PK\x03\x04", "zip", "application/zip"),
    (b"Rar!\x1a\x07", "rar", "application/x-rar"),
    (b"\x1f\x8b", "gz", "application/gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed"),
    (b"%PDF", "pdf", "application/pdf"),
    (b"\xd0\xcf\x11\xe0", "ole", "application/x-ole-storage"),
    (b"\xff\xd8\xff", "jpg", "image/jpeg"),
    (b"\x89PNG", "png", "image/png"),
    (b"GIF8", "gif", "image/gif"),
    (b"<?xml", "xml", "text/xml"),
    (b"{", "json", "application/json"),
    (b"#!", "sh", "text/x-shellscript"),
]
_CT_EXT = {
    "text/html": "html", "text/plain": "txt", "text/css": "css",
    "application/javascript": "js", "text/javascript": "js",
    "application/json": "json", "application/xml": "xml",
    "image/jpeg": "jpg", "image/png": "png", "image/gif": "gif",
    "image/webp": "webp", "image/svg+xml": "svg",
    "application/zip": "zip", "application/x-msdownload": "exe",
    "application/x-dosexec": "exe", "application/pdf": "pdf",
    "application/octet-stream": "bin", "application/gzip": "gz",
    "application/vnd.ms-cab-compressed": "cab",
    "application/x-msi": "msi", "application/x-sh": "sh",
    "text/x-python": "py", "application/x-powershell": "ps1",
}


@dataclass
class Obj:
    ts: str
    direction: str            # download | upload
    client: str
    server: str
    server_port: int
    method: str
    url: str
    status: int
    request_ct: str = ""
    content_type: str = ""
    detected_type: str = ""
    encoding: str = ""
    filename: str = ""
    size: int = 0
    sha256: str = ""
    md5: str = ""
    truncated: bool = False
    user_agent: str = ""
    referer: str = ""
    server_hdr: str = ""
    notable: list = field(default_factory=list)
    _body: bytes = field(default=b"", repr=False)

    def row(self) -> dict:
        return {
            "time": self.ts, "direction": self.direction,
            "client": self.client, "server": self.server,
            "server_port": self.server_port, "method": self.method,
            "url": self.url, "status": self.status or "",
            "content_type": self.content_type,
            "detected_type": self.detected_type,
            "encoding": self.encoding, "filename": self.filename,
            "size": self.size, "sha256": self.sha256, "md5": self.md5,
            "truncated": "yes" if self.truncated else "",
            "user_agent": self.user_agent, "server_hdr": self.server_hdr,
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    objects: list = field(default_factory=list)
    packets: int = 0
    connections: int = 0
    transactions: int = 0
    errors: list = field(default_factory=list)


_FNAME_RE = re.compile(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', re.I)
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _detect(body: bytes) -> tuple[str, str]:
    head = body[:16]
    for sig, ext, ct in _MAGIC:
        if head.startswith(sig):
            return ext, ct
    if body[:64].strip().startswith((b"<!DOCTYPE", b"<html")):
        return "html", "text/html"
    return "", ""


def _filename(url: str, cd: str, ct: str, det_ct: str, n: int) -> str:
    if cd:
        m = _FNAME_RE.search(cd)
        if m:
            return _SAFE.sub("_", Path(m.group(1)).name)[:120] or f"obj{n}"
    p = url
    if "://" in p:                       # drop scheme://host, keep the path
        p = p.split("://", 1)[1]
        p = p[p.find("/"):] if "/" in p else "/"
    path = p.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    base = path.rsplit("/", 1)[-1]
    if base and "." in base:
        return _SAFE.sub("_", base)[:120]
    ext = _CT_EXT.get((det_ct or ct).split(";")[0].strip().lower(), "")
    return f"obj{n}" + (f".{ext}" if ext else "")


def analyze(paths, *, min_size: int = 0, keep_bodies: bool = False,
            progress=None) -> Result:
    res = Result()
    asm = Assembler()
    for path in paths:
        try:
            for ts, lt, data in _pcap.read(path):
                res.packets += 1
                pkt = decode(ts, lt, data)
                if pkt and pkt.proto == "TCP":
                    asm.add(pkt)
                if progress and res.packets % 5000 == 0:
                    progress(res.packets)
        except (_pcap.PcapError, OSError) as e:
            res.errors.append(f"{path}: {e}")

    n = 0
    for c in asm.connections():
        res.connections += 1
        cs = c.client_to_server()
        sc = c.server_to_client()
        cbytes = cs.stream()
        sbytes = sc.stream()
        if b"HTTP/" not in sbytes[:20000] and not any(
                cbytes.startswith(m) for m in (b"GET", b"POST", b"PUT",
                                               b"HEAD")):
            continue
        for req, resp in transactions(cbytes, sbytes):
            res.transactions += 1
            server = c.server
            server_port = sc.sport if sc.src == server else sc.dport
            client = cs.src if cs.src != server else cs.dst
            host = (req.header("host") if req else "") or server
            target = req.target if req else ""
            url = target if target.startswith("http") else \
                f"http://{host}{target}"
            ts = datetime.fromtimestamp(cs.first_ts or sc.first_ts,
                                        timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if (cs.first_ts
                                                       or sc.first_ts) else ""

            # response body -> download object
            if resp is not None and resp.body:
                _emit(res, "download", ts, client, server, server_port, req,
                      resp, url, resp.body, min_size, keep_bodies, n)
                n += 1
            # request body -> upload object
            if req is not None and req.body and len(req.body) >= max(1,
                                                                     min_size):
                _emit(res, "upload", ts, client, server, server_port, req,
                      resp, url, req.body, min_size, keep_bodies, n,
                      upload=True)
                n += 1
    return res


def _emit(res, direction, ts, client, server, port, req, resp, url, body,
          min_size, keep, n, *, upload=False):
    if len(body) < max(1, min_size):
        return
    det_ext, det_ct = _detect(body)
    ct = ((resp.header("content-type") if resp else "")
          if not upload else (req.header("content-type") if req else ""))
    cd = (resp.header("content-disposition") if resp and not upload else "")
    o = Obj(
        ts=ts, direction=direction, client=client, server=server,
        server_port=port,
        method=req.method if req else "",
        url=url, status=resp.status if resp else 0,
        content_type=ct.split(";")[0].strip(),
        detected_type=det_ct or "",
        encoding=(resp.raw_encoding if resp else "") if not upload
        else (req.raw_encoding if req else ""),
        filename=_filename(url, cd, ct, det_ct, n),
        size=len(body),
        sha256=hashlib.sha256(body).hexdigest(),
        md5=hashlib.md5(body).hexdigest(),
        truncated=(resp.body_truncated if resp and not upload else
                   (req.body_truncated if req else False)),
        user_agent=req.header("user-agent") if req else "",
        referer=req.header("referer") if req else "",
        server_hdr=resp.header("server") if resp else "",
        _body=body if keep else b"")
    o.notable = _flags.flag(o, body)
    res.objects.append(o)


def extract(res: Result, out_dir: str) -> int:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    written = 0
    used: dict[str, int] = {}
    for o in res.objects:
        if not o._body:
            continue
        name = o.filename or f"obj{written}"
        if name in used:
            used[name] += 1
            stem = Path(name)
            name = f"{stem.stem}_{used[name]}{stem.suffix}"
        else:
            used[name] = 0
        (d / name).write_bytes(o._body)
        o.filename = name
        written += 1
    return written
