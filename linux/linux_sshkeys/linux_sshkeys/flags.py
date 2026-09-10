"""Heuristic flags for SSH key / known_hosts / host-key entries."""

from __future__ import annotations

import re

_FROM = re.compile(r'(?:^|,)from="([^"]*)"')
_COMMAND = re.compile(r'(?:^|,)command="([^"]*)"')
_ENVIRONMENT = re.compile(r'(?:^|,)environment="([^"]*)"')
_WILDCARD_FROM = re.compile(r'(^|,)\*|!\*|0\.0\.0\.0/0|::/0')
_RECON_CMD = re.compile(r"\b(nc|ncat|socat|bash|sh|python|perl|/tmp/|"
                        r"curl|wget|base64)\b", re.I)


def flag_key(k) -> list[str]:
    out: list[str] = []

    if k.kind == "authorized_key":
        opt = k.options or ""
        mfrom = _FROM.search(opt)
        if not mfrom:
            out.append("no from= restriction (usable from any address)")
        elif _WILDCARD_FROM.search(mfrom.group(1)) or mfrom.group(1) in (
                "*", ""):
            out.append(f'wildcard from= ({mfrom.group(1)})')
        mcmd = _COMMAND.search(opt)
        if mcmd:
            c = mcmd.group(1)
            if _RECON_CMD.search(c):
                out.append(f'forced command looks like a shell / tool ({c})')
            else:
                out.append(f'forced command= ({c[:60]})')
        if _ENVIRONMENT.search(opt):
            out.append("environment= option set (can inject LD_PRELOAD etc.)")
        if "no-pty" not in opt and "restrict" not in opt and mcmd:
            out.append("forced command without no-pty / restrict")
        if k.key_type == "ssh-dss":
            out.append("DSA key (ssh-dss) - weak, disabled by default")
        if k.key_type == "ssh-rsa" and k.bits and k.bits < 2048:
            out.append(f"short RSA key ({k.bits} bits)")
        if k.comment and re.search(r"(test|temp|backup|root@|kali|"
                                   r"attacker|[0-9]{1,3}(\.[0-9]{1,3}){3})",
                                   k.comment, re.I):
            out.append(f"notable key comment ({k.comment})")

    elif k.kind == "known_host":
        if k.marker == "@cert-authority":
            out.append("@cert-authority - trusts a CA to vouch for host keys")
        if k.marker == "@revoked":
            out.append("@revoked host-key entry")
        if k.key_type == "ssh-rsa" and k.bits and k.bits < 2048:
            out.append(f"short RSA host key seen ({k.bits} bits)")

    elif k.kind == "host_key":
        if k.key_type == "ssh-dss":
            out.append("DSA host key present")
        if k.key_type == "ssh-rsa" and k.bits and k.bits < 2048:
            out.append(f"short RSA host key ({k.bits} bits)")

    return out


def flag_private(pk, *, world_readable=False, group_readable=False) -> list:
    out = []
    src = pk.source.replace("\\", "/")
    if world_readable:
        out.append("private key is world-readable")
    elif group_readable:
        out.append("private key is group-readable")
    if pk.fmt.startswith("pem") and not pk.encrypted and "host" not in src:
        out.append("unencrypted PEM private key")
    if pk.fmt == "openssh" and not pk.encrypted and \
            re.search(r"/\.ssh/id_", src):
        out.append("unencrypted user private key")
    if pk.fmt == "pem-dsa":
        out.append("DSA private key")
    return out


_SEV = {
    "no from= restriction": "medium",
    "wildcard from=": "high",
    "forced command looks like a shell": "high",
    "forced command=": "low",
    "environment= option set": "high",
    "forced command without no-pty": "low",
    "DSA key (ssh-dss)": "medium",
    "short RSA key": "medium",
    "notable key comment": "low",
    "@cert-authority": "medium",
    "@revoked": "low",
    "short RSA host key": "low",
    "DSA host key present": "low",
    "private key is world-readable": "high",
    "private key is group-readable": "medium",
    "unencrypted PEM private key": "medium",
    "unencrypted user private key": "low",
    "DSA private key": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
