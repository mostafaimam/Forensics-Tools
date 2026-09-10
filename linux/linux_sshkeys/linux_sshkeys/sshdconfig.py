"""sshd_config parser + risk review."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Directive:
    keyword: str
    value: str
    source: str
    line: int
    match: str = ""       # the Match condition this sits under, if any

    def row(self) -> dict:
        return {"kind": "config", "keyword": self.keyword, "value": self.value,
                "match": self.match, "source": self.source,
                "line": self.line or ""}


def parse(text: str, source: str) -> list[Directive]:
    out: list[Directive] = []
    match_ctx = ""
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line and " " not in line.split("=", 1)[0]:
            kw, _, val = line.partition("=")
        else:
            parts = line.split(None, 1)
            kw = parts[0]
            val = parts[1].strip() if len(parts) > 1 else ""
        if kw.lower() == "match":
            match_ctx = val
            out.append(Directive("Match", val, source, n))
            continue
        out.append(Directive(kw, val.strip('"'), source, n, match_ctx))
    return out


# keyword (lower) -> (predicate(value) -> bool, message, severity)
def _yes(v):
    return v.strip().lower() in ("yes", "true")


_WEAK_CIPHER = re.compile(r"\b(3des|arcfour|blowfish|cast128|"
                          r"aes\d+-cbc|rijndael)", re.I)
_WEAK_MAC = re.compile(r"\b(hmac-md5|hmac-sha1(?!-)|umac-64)", re.I)
_WEAK_KEX = re.compile(r"\b(diffie-hellman-group1-sha1|"
                       r"diffie-hellman-group14-sha1|gss-)", re.I)


def review(directives: list[Directive]) -> list[dict]:
    """Return a list of {keyword, value, message, severity, source, line}."""
    findings: list[dict] = []

    def add(d: Directive, msg: str, sev: str):
        findings.append({"keyword": d.keyword, "value": d.value,
                         "message": msg, "severity": sev,
                         "match": d.match, "source": d.source, "line": d.line})

    for d in directives:
        k = d.keyword.lower()
        v = d.value.strip()
        vl = v.lower()
        if k == "permitrootlogin" and vl in ("yes", "prohibit-password",
                                             "without-password"):
            sev = "high" if vl == "yes" else "medium"
            add(d, f"root login permitted ({v})", sev)
        elif k == "passwordauthentication" and _yes(v):
            add(d, "password authentication enabled", "medium")
        elif k == "permitemptypasswords" and _yes(v):
            add(d, "empty passwords permitted", "high")
        elif k == "permituserenvironment" and _yes(v):
            add(d, "PermitUserEnvironment yes (environment= in authorized_keys "
                   "can set LD_PRELOAD etc.)", "high")
        elif k == "authorizedkeyscommand" and v and v != "none":
            add(d, f"external AuthorizedKeysCommand ({v})", "medium")
        elif k == "forcecommand" and v and vl != "none":
            add(d, f"ForceCommand set ({v})", "medium")
        elif k == "permittunnel" and vl not in ("", "no"):
            add(d, f"PermitTunnel {v} (layer-3 tunnelling over SSH)", "medium")
        elif k == "gatewayports" and vl not in ("", "no"):
            add(d, f"GatewayPorts {v} (remote forwards bind non-loopback)",
                "medium")
        elif k == "allowtcpforwarding" and vl in ("yes", "all", ""):
            add(d, "AllowTcpForwarding yes (SSH can be used as a proxy)", "low")
        elif k == "usepam" and vl == "no":
            add(d, "UsePAM no (account / session PAM checks skipped)", "medium")
        elif k == "strictmodes" and vl == "no":
            add(d, "StrictModes no (weak key-file permissions accepted)",
                "medium")
        elif k == "loglevel" and vl in ("quiet", "fatal", "error"):
            add(d, f"LogLevel {v} (auth logging reduced)", "medium")
        elif k == "ciphers" and _WEAK_CIPHER.search(v):
            add(d, f"weak cipher(s) offered ({v})", "low")
        elif k == "macs" and _WEAK_MAC.search(v):
            add(d, f"weak MAC(s) offered ({v})", "low")
        elif k in ("kexalgorithms",) and _WEAK_KEX.search(v):
            add(d, f"weak key-exchange offered ({v})", "low")
        elif k == "authorizedkeysfile" and v and \
                v not in (".ssh/authorized_keys",
                          ".ssh/authorized_keys .ssh/authorized_keys2",
                          "%h/.ssh/authorized_keys"):
            add(d, f"non-default AuthorizedKeysFile ({v})", "low")
        elif k == "listenaddress" and v.startswith(("0.0.0.0", "::")):
            pass
    return findings
