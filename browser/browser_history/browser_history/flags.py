"""Suspicious-URL heuristics."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^\[[0-9a-f:]+\]$", re.I)
_PUNYCODE = re.compile(r"(^|\.)xn--", re.I)
# base64 in the URL *path* is unusual (payload smuggling); in the query
# string it is normal (OAuth, analytics), so require it to be much longer
_B64_PATH = re.compile(r"[A-Za-z0-9+/_-]{150,}={0,2}")
_B64_ANY = re.compile(r"[A-Za-z0-9+/_-]{500,}={0,2}")

_ANONYMISERS = {
    "hide.me", "hidester.com", "proxysite.com", "kproxy.com", "4everproxy.com",
    "croxyproxy.com", "whoer.net", "1ft.io", "12ft.io",
}
_PASTE = {
    "pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com", "rentry.co",
    "controlc.com", "privatebin.net", "0bin.net", "dpaste.org",
    "justpaste.it", "pastebin.pl",
}
_FILE_SHARE = {
    "anonfiles.com", "bayfiles.com", "mega.nz", "gofile.io", "file.io",
    "transfer.sh", "temp.sh", "0x0.st", "catbox.moe", "litter.catbox.moe",
    "send.exploit.in", "ufile.io", "workupload.com", "dropmefiles.com",
}
_TUNNEL = {
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt",
    "localtunnel.me", "serveo.net", "portmap.io", "pagekite.me",
}
_LOLBAS_URLS = re.compile(
    r"\.(ps1|hta|sct|scr|jse?|vbe?|wsf|bat|cmd|lnk|iso|img|vhdx?)($|\?)", re.I)
_ARCHIVE = re.compile(r"\.(zip|rar|7z|gz|cab|ace|arj)($|\?)", re.I)
_EXEC = re.compile(r"\.(exe|dll|msi|msix|appx|dmg|pkg|deb|rpm|apk)($|\?)", re.I)

_SUSPECT_TLD = {
    "zip", "mov", "top", "xyz", "click", "country", "kim", "work", "party",
    "gq", "cf", "tk", "ml", "ga", "rest", "cyou", "sbs", "monster",
}


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def flag_url(url: str, *, kind: str = "visit") -> list[str]:
    out: list[str] = []
    if not url:
        return out
    u = url.strip()
    low = u.lower()
    scheme = low.split(":", 1)[0]

    if scheme == "file":
        out.append("file-uri")
    if scheme in ("ftp", "smb", "ftps"):
        out.append(f"{scheme}-uri")
    if scheme not in ("http", "https", "file", "ftp", "ftps", "chrome",
                      "edge", "about", "moz-extension", "chrome-extension",
                      "view-source", "data", "blob", "javascript"):
        out.append("unusual-scheme")
    if scheme == "javascript":
        out.append("javascript-uri")
    if scheme == "data":
        out.append("data-uri")

    host = _host(u)
    if _IP_HOST.match(host):
        out.append("ip-literal-host")
    if _PUNYCODE.search(host):
        out.append("punycode-host")
    reg = host.rsplit(".", 1)
    if len(reg) == 2 and reg[1] in _SUSPECT_TLD:
        out.append(f"suspect-tld:.{reg[1]}")

    base = host[4:] if host.startswith("www.") else host
    if base in _ANONYMISERS:
        out.append("anonymiser")
    if base in _PASTE:
        out.append("paste-site")
    if base in _FILE_SHARE:
        out.append("file-sharing-site")
    if any(base == t or base.endswith("." + t) for t in _TUNNEL):
        out.append("tunnel-service")

    path_q = unquote(u)
    if _LOLBAS_URLS.search(path_q):
        out.append("script/installer-download")
    elif _EXEC.search(path_q):
        out.append("executable-download")
    elif _ARCHIVE.search(path_q) and kind == "download":
        out.append("archive-download")

    try:
        parts = urlsplit(u)
        path_only = parts.path
    except ValueError:
        path_only = u
    if _B64_PATH.search(path_only) or _B64_ANY.search(u):
        out.append("encoded-blob-in-url")
    if len(u) > 3000:
        out.append("very-long-url")
    if "@" in (urlsplit(u).netloc or ""):
        out.append("userinfo-in-url")

    return out


_SEVERITY = {
    "javascript-uri": 3, "script/installer-download": 3, "tunnel-service": 3,
    "anonymiser": 3, "ip-literal-host": 3, "punycode-host": 3,
    "encoded-blob-in-url": 2, "executable-download": 2, "paste-site": 2,
    "file-sharing-site": 2, "userinfo-in-url": 2, "file-uri": 2,
    "data-uri": 2, "unusual-scheme": 2, "smb-uri": 3, "ftp-uri": 2,
}


def severity(notable: list[str]) -> str:
    if not notable:
        return "none"
    top = max((_SEVERITY.get(n.split(":")[0], 1) for n in notable), default=1)
    return {3: "high", 2: "medium", 1: "low"}[top]
