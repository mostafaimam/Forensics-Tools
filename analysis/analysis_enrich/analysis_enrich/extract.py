"""Pull candidate indicators out of a timeline row's text."""

from __future__ import annotations

import ipaddress
import re

_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_IPV6 = re.compile(r"(?<![:\w])(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}"
                   r"(?![:\w])")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                     r"(?:[a-zA-Z]{2,24})\b")
_URL = re.compile(r"\b(?:https?|ftp|smb)://[^\s\"'<>|\\]{4,400}")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

_NOISE_DOMAINS = re.compile(
    r"\.(dll|exe|sys|log|dat|db|txt|xml|json|tmp|bin|cfg|ini|lnk)$", re.I)


def indicators(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {"ipv4": set(), "ipv6": set(), "domain": set(),
                                "url": set(), "md5": set(), "sha1": set(),
                                "sha256": set()}
    for m in _URL.finditer(text):
        out["url"].add(m.group(0).rstrip(".,);'\""))
    for m in _IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
            out["ipv4"].add(str(ip))
        except ValueError:
            pass
    for m in _IPV6.finditer(text):
        try:
            ipaddress.ip_address(m.group(0))
            out["ipv6"].add(m.group(0))
        except ValueError:
            pass
    for m in _DOMAIN.finditer(text):
        d = m.group(0).lower()
        if _NOISE_DOMAINS.search(d) or d.replace(".", "").isdigit():
            continue
        out["domain"].add(d)
    for m in _SHA256.finditer(text):
        out["sha256"].add(m.group(0).lower())
    for m in _SHA1.finditer(text):
        out["sha1"].add(m.group(0).lower())
    for m in _MD5.finditer(text):
        h = m.group(0).lower()
        if h not in {x[:32] for x in out["sha256"]} and \
                h not in {x[:32] for x in out["sha1"]}:
            out["md5"].add(h)
    return out
