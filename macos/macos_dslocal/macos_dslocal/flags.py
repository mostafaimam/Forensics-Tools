"""Heuristic flags for a dslocal user record."""

from __future__ import annotations

import re

_INTERACTIVE_SHELL = re.compile(r"/(ba|z|k|tc|c|fi)?sh$|/bash$|/dash$")
_HINT_LOOKS_LIKE_PW = re.compile(
    r"^(pass(word)?|pwd|pw)\s*[:=]?\s*\S+|^\S{6,}$")
_APPLE_ADMIN = {"root", "daemon"}


def flag(u) -> list[str]:
    out: list[str] = []
    service = u.name.startswith("_") or (0 <= u.uid < 500
                                         and u.name != "root")

    if "none" in u.auth_mechanisms and _INTERACTIVE_SHELL.search(u.shell):
        out.append("account has no configured password and an interactive "
                   "shell")
    if "DISABLED" in u.auth_mechanisms:
        out.append("account is marked DisabledUser")

    if u.uid == 0 and u.name != "root":
        out.append(f"uid 0 account other than root ({u.name})")

    if u.is_admin and not (u.name.startswith("_") or u.name in _APPLE_ADMIN):
        out.append("member of the 'admin' group")

    if service and _INTERACTIVE_SHELL.search(u.shell) and \
            not u.name.startswith("_"):
        out.append(f"hidden account (uid {u.uid}) with an interactive shell "
                   f"({u.shell})")
    if 0 <= u.uid < 500 and u.name != "root" and not u.name.startswith("_"):
        out.append(f"non-service account below uid 500 ({u.name}, uid "
                   f"{u.uid})")

    if u.hint and _HINT_LOOKS_LIKE_PW.match(u.hint.strip()) and \
            len(u.hint.strip()) >= 6 and " " not in u.hint.strip():
        out.append(f"password hint may contain the password itself "
                   f"('{u.hint}')")

    if u.home and u.uid >= 500 and not u.home.startswith(
            ("/Users/", "/var/", "/private/var/", "/System/")) and \
            u.home not in ("", "/", "/dev/null", "/nonexistent"):
        out.append(f"home directory outside /Users ({u.home})")

    if u.pbkdf2_iterations and u.pbkdf2_iterations < 20000 and u.uid >= 500:
        out.append(f"low PBKDF2 iteration count ({u.pbkdf2_iterations}) - "
                   f"password hash may predate a macOS upgrade")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "account has no configured password and an interactive shell": "high",
    "account is marked DisabledUser": "low",
    "uid 0 account other than root": "high",
    "member of the 'admin' group": "medium",
    "hidden account (uid": "high",
    "non-service account below uid 500": "high",
    "password hint may contain the password itself": "medium",
    "home directory outside /Users": "medium",
    "low PBKDF2 iteration count": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
