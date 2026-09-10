"""Heuristic flags for a normalised WebCache entry."""

from __future__ import annotations

import re

_EXE_DL = re.compile(r"\.(exe|dll|scr|ps1|psm1|bat|cmd|hta|vbs|js|jse|wsf|"
                     r"jar|msi|lnk|iso|img|vhd|vhdx|cab|7z|zip|rar)(\?|$)",
                     re.I)
_IP_HOST = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}([:/]|$)", re.I)
_PUNYCODE = re.compile(r"://[^/]*xn--", re.I)
_ANON = re.compile(
    r"://([^/]*\.)?(pastebin\.com|paste\.ee|ghostbin|hastebin|"
    r"anonfiles|mega\.nz|mega\.io|transfer\.sh|file\.io|gofile\.io|"
    r"tmpfiles\.org|0x0\.st|catbox\.moe|ufile\.io|"
    r"ngrok\.io|ngrok-free\.app|trycloudflare\.com|"
    r"tor2web|onion\.|\.onion|duckdns\.org|no-ip\.|hopto\.org)", re.I)
_HOST = re.compile(r"^[a-z]+://([^/:@]+)", re.I)


def _host(url: str) -> str:
    m = _HOST.match(url)
    return m.group(1).lower() if m else url.split("/")[0].lower()


def flag(e) -> list[str]:
    out: list[str] = []
    url = e.url or ""
    # cookie URLs are stored as bare host/path - give the matchers a scheme
    probe = url if "://" in url else ("http://" + url)

    if e.entry_type == "download" or (e.entry_type == "content"
                                      and _EXE_DL.search(url)):
        if _EXE_DL.search(url) or _EXE_DL.search(e.filename or ""):
            out.append(f"executable / script fetched ({e.filename or url})")
    if _IP_HOST.match(url):
        out.append(f"URL with an IP-literal host ({_host(url)})")
    if _PUNYCODE.search(url):
        out.append(f"punycode host ({_host(url)})")
    if url.lower().startswith("file://"):
        out.append("file:// URL recorded")
    m = _ANON.search(probe)
    if m:
        kind = "cookie for" if e.entry_type == "cookie" else "visit to"
        out.append(f"{kind} a paste / file-sharing / tunnel site "
                   f"({_host(url) if e.entry_type != 'cookie' else url})")
    if e.entry_type == "content" and e.size and e.size > 100 * 1024 * 1024:
        out.append(f"very large cached response ({e.size / 1048576:.0f} MiB)")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "executable / script fetched": "high",
    "URL with an IP-literal host": "medium",
    "punycode host": "medium",
    "file:// URL recorded": "low",
    "visit to a paste": "medium",
    "cookie for a paste": "medium",
    "very large cached response": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
