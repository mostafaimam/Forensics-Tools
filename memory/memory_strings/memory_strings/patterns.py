"""Built-in pattern library for classifying strings."""

from __future__ import annotations

import re

# name -> (compiled regex, "match" | "search")
LIBRARY: dict[str, re.Pattern] = {
    "url": re.compile(r"\b(?:https?|ftp|ftps|smb|ldap)://[^\s\"'<>|]{4,2000}"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                       r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "ipv6": re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    "hostname": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
                           r"+(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|gov|"
                           r"edu|mil|onion|local|dev|app|cloud)\b"),
    "unc_path": re.compile(r"\\\\[A-Za-z0-9._$\-]+\\[^\s\"'|<>*?]{1,400}"),
    "win_path": re.compile(r"\b[A-Za-z]:\\(?:[^\s\"'|<>*?\r\n]{1,400})"),
    "unix_path": re.compile(r"(?:^|[\s\"'=:])/(?:etc|usr|var|opt|home|root|tmp|"
                            r"dev|proc|bin|sbin|lib)/[^\s\"'|<>*?\r\n]{1,400}"),
    "registry": re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\"
                           r"[^\s\"'|<>*?\r\n]{1,400}"),
    "guid": re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                       r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"),
    "powershell": re.compile(r"(?i)powershell(?:\.exe)?\s+[^\r\n]{0,400}|"
                             r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}|"
                             r"IEX\s*\(|Invoke-(?:Expression|WebRequest|Mimikatz)"),
    "cmdline": re.compile(r"(?i)\b(?:cmd\.exe|/c\s|rundll32|regsvr32|mshta|"
                          r"certutil|bitsadmin|wmic|schtasks|net\s+user|"
                          r"net\s+localgroup|whoami|nltest)\b[^\r\n]{0,300}"),
    "base64_blob": re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?"
                              r"PRIVATE KEY-----"),
    "aws_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\."
                      r"[A-Za-z0-9_\-]{10,}\b"),
    "btc": re.compile(r"\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "eth": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "credit_card": re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|"
                              r"3[47]\d{13}|6(?:011|5\d{2})\d{12})\b"),
    "user_agent": re.compile(r"\bMozilla/\d\.\d \([^)]{5,200}\)[^\r\n]{0,200}"),
    "sql": re.compile(r"(?i)\b(?:select\s+.{0,200}\s+from\s+|insert\s+into\s+|"
                      r"union\s+select\s+|drop\s+table\s+)[^\r\n]{0,200}"),
}

_LUHN = ("credit_card",)


def _luhn(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def classify(text: str, categories=None) -> list[tuple[str, str]]:
    """Return [(category, matched-substring)] for *text*."""
    hits = []
    for name, rx in LIBRARY.items():
        if categories and name not in categories:
            continue
        for m in rx.finditer(text):
            s = m.group(0).strip("\"'=:; ")
            if name in _LUHN and not _luhn(s):
                continue
            hits.append((name, s))
    return hits
