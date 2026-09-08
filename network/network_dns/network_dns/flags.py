"""Heuristic flags for an aggregated DNS name."""

from __future__ import annotations

import math
import re

_PUBLIC_SUFFIX_HINT = re.compile(
    r"\.(com|net|org|io|co|info|biz|xyz|top|ru|cn|de|uk|nl|fr|br|in|us|"
    r"online|site|club|live|pw|cc|tk|ml|ga|cf|gq)$", re.I)
_HEX_LABEL = re.compile(r"^[0-9a-f]{16,}$", re.I)
_B32_LABEL = re.compile(r"^[a-z2-7]{24,}$", re.I)
_DGA_CHARS = re.compile(r"^[a-z0-9-]+$", re.I)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _labels(name: str) -> list[str]:
    return [x for x in name.rstrip(".").split(".") if x]


def _registrable(name: str) -> str:
    parts = _labels(name)
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def flag(rec) -> list[str]:
    out: list[str] = []
    name = rec.qname
    labels = _labels(name)
    left = labels[0] if labels else ""

    # tunnelling / exfil-shaped labels
    if _HEX_LABEL.match(left) or _B32_LABEL.match(left):
        out.append("encoded left-most label (tunnelling?)")
    if len(name) > 100:
        out.append(f"very long name ({len(name)} chars)")
    if len(labels) >= 6:
        out.append(f"deep subdomain chain ({len(labels)} labels)")
    if left and len(left) >= 20 and _entropy(left) >= 3.6 \
            and _DGA_CHARS.match(left):
        out.append("high-entropy left-most label (DGA / tunnelling?)")

    # record types that carry payload
    if "TXT" in rec.qtypes and rec.txt:
        mx = max(len(t) for t in rec.txt)
        if mx >= 200:
            out.append(f"large TXT response ({mx} bytes)")
    if rec.has_null or "NULL" in rec.qtypes:
        out.append("NULL record (rare; tunnelling)")
    if "ANY" in rec.qtypes:
        out.append("ANY query")
    if {"AXFR", "IXFR"} & rec.qtypes:
        out.append("zone-transfer query")

    # resolution failures
    if rec.nxdomain >= 5:
        out.append(f"repeated NXDOMAIN ({rec.nxdomain})")
    if rec.servfail >= 5:
        out.append(f"repeated SERVFAIL ({rec.servfail})")

    # fast-flux: many A records / churn on a short-lived name
    if len(rec.ips) >= 8 and rec.answer_ttls and min(rec.answer_ttls) <= 300:
        out.append(f"many low-TTL addresses ({len(rec.ips)} IPs, "
                   f"TTL {min(rec.answer_ttls)}s) - fast-flux?")

    # hosts-file override that disagrees with the DNS answer
    _LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost",
                       "ip6-loopback", "broadcasthost"}
    if rec.static_ips and not (
            name in _LOOPBACK_NAMES
            or rec.static_ips <= {"127.0.0.1", "::1"}):
        out.append("hosts-file override")
        real = rec.ips - rec.static_ips
        if real:
            out.append("hosts entry differs from DNS answer")
        if any(ip not in ("127.0.0.1", "::1", "0.0.0.0") for ip in
               rec.static_ips) and _PUBLIC_SUFFIX_HINT.search(name):
            out.append("public name redirected by hosts file")

    # answer points at a private / loopback address for a public name
    for ip in rec.ips:
        if ip.startswith(("127.", "10.", "192.168.", "169.254.")) and \
                _PUBLIC_SUFFIX_HINT.search(name):
            out.append("public name resolves to a private / loopback IP")
            break

    if rec.truncated:
        out.append("truncated response (TCP retry / large payload)")
    return out


_SEV = {
    "encoded left-most label": 3, "high-entropy left-most label": 3,
    "large TXT response": 3, "NULL record": 3, "zone-transfer query": 3,
    "hosts entry differs": 3, "public name redirected by hosts": 3,
    "public name resolves to a private": 3,
    "many low-TTL addresses": 2, "deep subdomain chain": 2,
    "very long name": 2, "repeated NXDOMAIN": 2, "repeated SERVFAIL": 2,
    "ANY query": 2, "hosts-file override": 1,
    "truncated response": 1,
}


def severity(notable) -> str:
    top = 0
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k):
                top = max(top, v)
    return {0: "none", 1: "low", 2: "medium", 3: "high"}[top]
