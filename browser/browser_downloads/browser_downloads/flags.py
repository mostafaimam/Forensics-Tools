"""Heuristic flags for a normalised download."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_EXEC = re.compile(r"\.(exe|dll|scr|msi|msix|com|bat|cmd|ps1|psm1|vbs|vbe|js|"
                   r"jse|jar|hta|lnk|reg|inf|cpl|sys|scf|application|gadget)$",
                   re.I)
_ARCHIVE = re.compile(r"\.(zip|rar|7z|iso|img|vhd|vhdx|cab|gz|tar|ace|arj)$",
                      re.I)
_DOC_MACRO = re.compile(r"\.(docm|xlsm|pptm|dotm|xlam)$", re.I)
_DOUBLE_EXT = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp3|mp4|zip)\s*\."
    r"(exe|scr|com|bat|cmd|js|vbs|ps1|hta|lnk)$", re.I)
_MIME_EXT = {
    "application/x-msdownload": (".exe", ".dll"), "application/x-msdos-program":
    (".exe",), "application/vnd.microsoft.portable-executable": (".exe",),
    "application/x-dosexec": (".exe",),
    "application/zip": (".zip",), "application/pdf": (".pdf",),
    "application/x-7z-compressed": (".7z",),
    "image/jpeg": (".jpg", ".jpeg"), "image/png": (".png",),
}


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _ext(path: str) -> str:
    p = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return ("." + p.rsplit(".", 1)[-1].lower()) if "." in p else ""


def flag(d) -> list[str]:
    out: list[str] = list(d.notable)
    name = d.filename
    ext = _ext(name)
    host = _host(d.url) or d.zone_host

    if _DOUBLE_EXT.search(name):
        out.append("double extension (disguised executable)")
    elif _EXEC.search(name):
        out.append(f"executable / script download ({ext})")
    elif _DOC_MACRO.search(name):
        out.append("macro-enabled document download")
    elif _ARCHIVE.search(name):
        out.append("archive / disk-image download")

    if d.mime:
        m = d.mime.split(";")[0].strip().lower()
        want = _MIME_EXT.get(m)
        if want and ext and ext not in want:
            out.append(f"MIME / extension mismatch (says {m}, file is {ext})")

    if host and _is_ip(host):
        try:
            if ipaddress.ip_address(host).is_global:
                out.append("downloaded from a raw IP address")
        except ValueError:
            pass

    if d.danger and d.danger not in ("not-dangerous", "user-validated",
                                     "allowlisted-by-policy",
                                     "deep-scanned-safe", "0", ""):
        out.append(f"browser danger flag: {d.danger}")

    if d.state in ("interrupted", "failed", "cancelled",
                   "in-progress / interrupted") and d.received_bytes:
        out.append(f"incomplete download ({d.state})")

    if d.zone_id in ("3", "4") and (_EXEC.search(name) or _ARCHIVE.search(name)
                                    or _DOC_MACRO.search(name)):
        out.append("internet-zone (MOTW) executable / archive on disk")

    # referrer host different from download host (redirected download)
    rh = _host(d.referrer) or _host(d.zone_referrer)
    if rh and host and rh != host and not host.endswith("." + rh) \
            and not rh.endswith("." + host) and (_EXEC.search(name)
                                                 or _ARCHIVE.search(name)):
        out.append(f"referrer host ({rh}) differs from download host ({host})")

    # dedupe, keep order
    seen: set = set()
    return [x for x in out if not (x in seen or seen.add(x))]


_SEV = {
    "double extension": 3, "executable / script download": 2,
    "macro-enabled document": 3, "MIME / extension mismatch": 3,
    "downloaded from a raw IP": 2, "browser danger flag": 3,
    "internet-zone (MOTW) executable": 2,
    "referrer host": 2, "archive / disk-image download": 1,
    "incomplete download": 1, "partial-download file": 1,
    "file marked internet-zone": 1, "file marked internet-zone (MOTW)": 1,
}


def severity(notable) -> str:
    top = 0
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k):
                top = max(top, v)
    return {0: "none", 1: "low", 2: "medium", 3: "high"}[top]
