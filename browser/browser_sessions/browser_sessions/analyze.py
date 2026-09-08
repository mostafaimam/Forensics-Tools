"""Discover session files, parse them, add flags + findings."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from browser_sessions import chromium as _chromium
from browser_sessions import firefox as _firefox

_CHROMIUM_NAMES = re.compile(
    r"^(Session_\d+|Tabs_\d+|Last Session|Current Session|Last Tabs|"
    r"Current Tabs)$")
_FIREFOX_NAMES = re.compile(r"\.jsonlz4$|^sessionstore\.js(on)?$", re.I)

_AUTH = re.compile(r"(/login|/signin|/sign-in|/auth|/oauth|/sso|accounts\.|"
                   r"/account/login|/session/new|/u/0/)", re.I)


@dataclass
class Result:
    tabs: list = field(default_factory=list)
    files: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _discover(root: str) -> list[str]:
    r = Path(root)
    if r.is_file():
        return [str(r)]
    out: list[str] = []
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if _CHROMIUM_NAMES.match(n) or _FIREFOX_NAMES.search(n):
                out.append(str(Path(dirpath) / n))
    return out


def _flag(t) -> None:
    u = t.current_url or ""
    low = u.lower()
    if t.has_formdata:
        t.notable.append("restored form data preserved in the session")
    if _AUTH.search(u):
        t.notable.append("tab left on a sign-in / auth page")
    if low.startswith("file:"):
        t.notable.append("tab pointing at a local file (file://)")
    try:
        host = urlparse(u).hostname or ""
        if host:
            try:
                if ipaddress.ip_address(host).is_global:
                    t.notable.append("tab to a raw IP address")
            except ValueError:
                pass
    except ValueError:
        pass
    if t.closed:
        t.notable.append("recently-closed tab retained in the session store")


def analyze(paths) -> Result:
    res = Result()
    tabs: list = []
    for path in paths:
        try:
            files = _discover(str(path))
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            continue
        for f in files:
            res.files += 1
            name = Path(f).name
            try:
                if _FIREFOX_NAMES.search(name) or name.startswith(
                        "sessionstore"):
                    tabs += _firefox.parse(f)
                else:
                    tabs += _chromium.parse(f)
            except Exception as e:  # noqa: BLE001
                res.errors.append(f"{f}: {e}")

    for t in tabs:
        _flag(t)

    open_tabs = [t for t in tabs if not t.closed]
    if len(open_tabs) >= 30:
        res.findings.append(f"{len(open_tabs)} tabs open at last close")
    hosts: dict[str, int] = {}
    for t in open_tabs:
        h = (urlparse(t.current_url).hostname or "") if t.current_url else ""
        if h:
            hosts[h] = hosts.get(h, 0) + 1
    for h, n in sorted(hosts.items(), key=lambda kv: -kv[1]):
        if n >= 8:
            res.findings.append(f"{n} tabs on {h}")

    res.tabs = sorted(tabs, key=lambda t: (t.closed, not t.last_accessed,
                                           t.last_accessed or "", t.window,
                                           t.index))
    return res
