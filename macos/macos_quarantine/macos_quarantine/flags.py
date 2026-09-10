"""Heuristic flags for a quarantine event."""

from __future__ import annotations

import re

_DANGEROUS = re.compile(
    r"\.(dmg|pkg|mpkg|app|command|tool|scpt|sh|py|pl|rb|jar|zip|"
    r"7z|rar|tar|gz|iso|exe|scr|hta|vbs|js|jse|mobileconfig|"
    r"terminal|workflow)(\?|$)", re.I)
_ARCHIVE = re.compile(r"\.(zip|7z|rar|tar|gz|tgz|dmg)(\?|$)", re.I)
_IP_HOST = re.compile(r"^[a-z]+://(\d{1,3}\.){3}\d{1,3}([:/]|$)", re.I)
_PUNY = re.compile(r"://[^/]*xn--", re.I)
_SCRIPT_AGENT = re.compile(r"\b(curl|wget|python|osascript|ruby|perl|"
                           r"terminal|bash|zsh|sh)\b", re.I)
_ANON = re.compile(r"://([^/]*\.)?(pastebin|paste\.ee|anonfiles|mega\.nz|"
                   r"transfer\.sh|file\.io|gofile|0x0\.st|catbox\.moe|"
                   r"ngrok|trycloudflare|duckdns|no-ip|\.onion)", re.I)


def _host(url: str) -> str:
    m = re.match(r"^[a-z]+://([^/:@]+)", url, re.I)
    return m.group(1).lower() if m else ""


def flag(e) -> list[str]:
    out: list[str] = []
    url = e.data_url or ""

    m = _DANGEROUS.search(url)
    if m:
        out.append(f"executable / installer / script fetched from the "
                   f"internet ({m.group(0).lstrip('.')})")
    elif _ARCHIVE.search(url):
        out.append("archive downloaded (may contain an executable)")
    if _IP_HOST.match(url) or _IP_HOST.match(e.origin_url or ""):
        out.append(f"download from an IP-literal host "
                   f"({_host(url) or _host(e.origin_url)})")
    if _PUNY.search(url) or _PUNY.search(e.origin_url or ""):
        out.append("download from a punycode host")
    if _SCRIPT_AGENT.search(e.agent_name or "") or \
            _SCRIPT_AGENT.search(e.agent_bundle or ""):
        out.append(f"downloaded by a command-line / scripting agent "
                   f"({e.agent_name or e.agent_bundle})")
    if _ANON.search(url) or _ANON.search(e.origin_url or ""):
        out.append("download from a paste / file-sharing / tunnel site")
    if e.event_type == "email attachment" and m:
        out.append("dangerous file arrived as an email attachment")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "executable / installer / script fetched from the internet": "high",
    "archive downloaded": "low",
    "download from an IP-literal host": "medium",
    "download from a punycode host": "medium",
    "downloaded by a command-line / scripting agent": "high",
    "download from a paste / file-sharing / tunnel site": "medium",
    "dangerous file arrived as an email attachment": "high",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
