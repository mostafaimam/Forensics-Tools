"""Light notability heuristics for shortcut / top-site / predictor URLs."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def flag(url: str) -> str:
    if not url:
        return ""
    scheme = url.split(":", 1)[0].lower()
    if scheme == "javascript":
        return "bookmarklet"
    if scheme == "file":
        return "file-url"
    host = _host(url)
    if not host:
        return ""
    if _IPV4.match(host):
        return "ip-literal-host"
    if "xn--" in host:
        return "punycode-host"
    return ""
