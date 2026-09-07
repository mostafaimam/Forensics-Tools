"""Heuristic flags for a carved HTTP object."""

from __future__ import annotations

import ipaddress
import math
import re

_EXEC_EXT = re.compile(r"\.(exe|dll|scr|msi|msix|sys|ocx|cpl|drv|efi)$", re.I)
_SCRIPT_EXT = re.compile(r"\.(ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|wsh|hta|sh|"
                         r"py|pl|rb|lnk)$", re.I)
_ARCHIVE_EXT = re.compile(r"\.(zip|rar|7z|cab|iso|img|vhdx?|gz|tar|arj|ace)$",
                          re.I)
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf", b"\x1f\x8b",
                  b"MSCF", b"ustar")
_TEXTY_CT = ("text/", "application/json", "application/javascript",
             "application/xml", "image/", "video/", "audio/",
             "application/font", "font/")


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    ln = len(b)
    return -sum((c / ln) * math.log2(c / ln) for c in counts if c)


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def flag(o, body: bytes) -> list[str]:
    out: list[str] = []
    name = (o.filename or "").lower()
    det = o.detected_type
    ct = o.content_type
    upath = o.url.split("?", 1)[0]
    if "://" in upath:
        upath = upath.split("://", 1)[1]
        upath = upath[upath.find("/"):] if "/" in upath else "/"
    upath = upath.lower()
    ext_exe = _EXEC_EXT.search(name) or _EXEC_EXT.search(upath)

    if body[:2] == b"MZ" or det == "application/x-dosexec":
        out.append("PE executable body")
    elif body[:4] == b"\x7fELF":
        out.append("ELF executable body")
    elif ext_exe:
        out.append("executable file name")
    if _SCRIPT_EXT.search(name) or _SCRIPT_EXT.search(upath):
        out.append("script file name")
    if body[:8].startswith(_ARCHIVE_MAGIC) or _ARCHIVE_EXT.search(name):
        out.append("archive / disk-image body")

    # content-type says one thing, the bytes say another
    if det and ct and det.split("/")[0] != ct.split("/")[0] \
            and ct not in ("application/octet-stream", ""):
        out.append(f"content-type mismatch (says {ct}, is {det})")
    if ct in ("text/html", "text/plain") and body[:2] == b"MZ":
        out.append("executable served as text")

    # high-entropy non-media body = packed / encrypted / raw payload
    if o.direction == "download" and not any(
            ct.startswith(p) for p in _TEXTY_CT) and len(body) > 1024:
        if _entropy(body[:65536]) >= 7.2 and not det:
            out.append("high-entropy body (packed / encrypted?)")

    if o.direction == "upload":
        out.append("HTTP upload / POST body")
        low = body[:4096].lower()
        if b"password" in low or b"passwd" in low or b"&pwd=" in low:
            out.append("credentials in upload")
        if _entropy(body[:65536]) >= 7.4 and len(body) > 4096:
            out.append("high-entropy upload (staged exfil?)")

    if o.server and not _private(o.server):
        try:
            ipaddress.ip_address((o.url.split("//", 1)[-1].split("/")[0]
                                  .split(":")[0]))
            out.append("fetched from an IP-literal host")
        except ValueError:
            pass

    ua = (o.user_agent or "").strip().lower()
    if o.direction == "download" and (out or ext_exe) and (
            not ua or ua.startswith(("python-requests", "curl/", "wget",
                                     "powershell", "go-http-client",
                                     "microsoft bits", "libwww", "java/"))):
        out.append(f"non-browser user-agent ({ua or 'empty'})")

    if o.truncated:
        out.append("body truncated (capture incomplete)")
    return out


_SEV = {
    "PE executable body": 3, "ELF executable body": 3,
    "executable served as text": 3, "content-type mismatch": 3,
    "credentials in upload": 3, "high-entropy upload": 3,
    "high-entropy body": 2, "executable file name": 2,
    "script file name": 2, "archive / disk-image body": 2,
    "HTTP upload / POST body": 1, "non-browser user-agent": 2,
    "fetched from an IP-literal host": 2, "body truncated": 1,
}


def severity(notable: list[str]) -> str:
    if not notable:
        return "none"
    top = 0
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k):
                top = max(top, v)
    return {0: "low", 1: "low", 2: "medium", 3: "high"}[top]
