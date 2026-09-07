"""Suspicious-traffic heuristics over flows, DNS and HTTP."""

from __future__ import annotations

import ipaddress
import math
import re

_PLAINTEXT_SERVICES = {"http", "ftp", "telnet", "smtp", "pop3", "imap",
                       "snmp", "syslog", "redis", "http-alt"}
_SUSPECT_TLD = {"zip", "mov", "top", "xyz", "click", "gq", "cf", "tk", "ml",
                "ga", "sbs", "cyou", "rest", "monster", "country", "work",
                "party", "kim", "loan"}
_TUNNEL_SUFFIX = ("ngrok.io", "ngrok-free.app", "trycloudflare.com",
                  "loca.lt", "serveo.net", "portmap.io", "pagekite.me")
_ANON_HOSTS = ("hide.me", "whoer.net")
_C2_UA = re.compile(r"^$|^-$|python-requests|curl/|Go-http-client|"
                    r"powershell|WinHttp|Microsoft BITS|Wget|libwww|"
                    r"Java/|okhttp|axios", re.I)


def _private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def flag_dns(rec) -> list[str]:
    out = []
    q = (rec.query or "").rstrip(".").lower()
    if not q:
        return out
    labels = q.split(".")
    reg = labels[-1] if labels else ""
    if reg in _SUSPECT_TLD:
        out.append(f"suspect-tld:.{reg}")
    if any(q == t or q.endswith("." + t) for t in _TUNNEL_SUFFIX):
        out.append("tunnel-domain")
    if any(q == a or q.endswith("." + a) for a in _ANON_HOSTS):
        out.append("anonymiser-domain")
    # long label / high-entropy subdomain -> DGA or DNS tunnelling
    longest = max((len(x) for x in labels[:-2]), default=0)
    if longest >= 30:
        out.append("long-dns-label")
    sub = ".".join(labels[:-2])
    if len(sub) >= 25 and _entropy(sub) > 3.6:
        out.append("high-entropy-subdomain")
    if rec.qtype in ("TXT", "NULL") and len(q) > 40:
        out.append("txt-record-tunnelling?")
    if rec.qtype == "ANY":
        out.append("dns-any-query")
    if len(q) > 200:
        out.append("very-long-dns-name")
    return out


def flag_http(rec) -> list[str]:
    out = []
    if rec.authorization and rec.authorization.lower().startswith("basic "):
        out.append("http-basic-auth-cleartext")
    if rec.has_password_field:
        out.append("password-in-http-body")
    if rec.method == "CONNECT":
        out.append("http-connect (proxy tunnel)")
    ua = (rec.user_agent or "").strip()
    if rec.method:                        # requests only
        if not ua or ua == "-":
            out.append("empty-user-agent")
        elif _C2_UA.match(ua):
            out.append("scripted-user-agent")
    host = (rec.host or "").lower()
    if host:
        try:
            ipaddress.ip_address(host.strip("[]").split(":")[0])
            out.append("http-to-ip-literal")
        except ValueError:
            pass
    elif rec.method and not _private(rec.server):
        try:
            ipaddress.ip_address(rec.server)
            out.append("http-to-ip-literal")
        except ValueError:
            pass
    reg = host.rsplit(".", 1)[-1] if "." in host else ""
    if reg in _SUSPECT_TLD:
        out.append(f"suspect-tld:.{reg}")
    if any(host.endswith(t) for t in _TUNNEL_SUFFIX):
        out.append("tunnel-domain")
    low = (rec.target or "").lower()
    if low.endswith((".exe", ".dll", ".ps1", ".hta", ".sct", ".bat", ".scr",
                     ".jar", ".vbs", ".iso")):
        out.append("executable/script download")
    ct = (rec.content_type or "").lower()
    if rec.method in ("GET", "POST") and ("application/octet-stream" in ct
                                          or "application/x-msdownload" in ct):
        out.append("binary-download")
    return out


def flag_flow(f, *, dns_names: set[str], long_secs: float = 3600,
              egress_mb: float = 25) -> list[str]:
    out = []
    server = f.server_ip
    ext = server and not _private(server)
    if f.service in _PLAINTEXT_SERVICES and ext:
        out.append(f"plaintext-{f.service}-to-internet")
    elif f.service in _PLAINTEXT_SERVICES:
        out.append(f"plaintext-{f.service}")
    if f.service in ("smb", "rdp", "vnc", "mssql", "mysql", "postgres",
                     "redis", "elasticsearch", "winrm") and ext:
        out.append(f"{f.service}-to-internet")
    if ext:
        try:
            if server not in dns_names:
                out.append("no-dns-for-dst")
        except TypeError:
            pass
    if f.duration >= long_secs:
        out.append(f"long-lived ({int(f.duration)}s)")
    if f.egress_bytes >= egress_mb * 1024 * 1024:
        out.append(f"large-egress ({f.egress_bytes // (1024 * 1024)} MB)")
    if f.proto == "TCP" and "R" in f.tcp_flags and "S" in f.tcp_flags \
            and "F" not in f.tcp_flags and f.packets <= 4:
        out.append("connection-refused")
    return out


def severity(notable: list[str]) -> str:
    if not notable:
        return "none"
    hi = ("tunnel-domain", "http-basic-auth-cleartext", "password-in-http-body",
          "txt-record-tunnelling?", "high-entropy-subdomain",
          "executable/script download", "http-connect", "large-egress",
          "smb-to-internet", "rdp-to-internet", "http-to-ip-literal",
          "anonymiser-domain")
    med = ("plaintext-", "suspect-tld", "scripted-user-agent", "no-dns-for-dst",
           "long-dns-label", "long-lived", "empty-user-agent", "binary-download",
           "-to-internet")
    for n in notable:
        if any(n.startswith(h) or h in n for h in hi):
            return "high"
    for n in notable:
        if any(n.startswith(m) or m in n for m in med):
            return "medium"
    return "low"
