"""Discover credential stores, parse them, add per-host findings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from browser_logins import parse as _parse

_NAMES = {"Login Data", "Login Data For Account", "logins.json"}


@dataclass
class Result:
    logins: list = field(default_factory=list)
    stores: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _find(root: str) -> list[str]:
    r = Path(root)
    if r.is_file():
        return [str(r)]
    out: list[str] = []
    for dirpath, dirnames, names in os.walk(r):
        dirnames.sort()
        for n in sorted(names):
            if n in _NAMES:
                out.append(str(Path(dirpath) / n))
    return out


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        try:
            stores = _find(str(path))
        except OSError as e:
            res.errors.append(f"{path}: {e}")
            continue
        for st in stores:
            res.stores += 1
            try:
                if Path(st).name == "logins.json":
                    res.logins += _parse.parse_firefox_logins(st)
                else:
                    res.logins += _parse.parse_login_data(st)
            except Exception as e:  # noqa: BLE001
                res.errors.append(f"{st}: {e}")

    # per-host aggregate
    by_host: dict[str, int] = {}
    for lg in res.logins:
        if lg.host and not lg.blacklisted:
            by_host[lg.host] = by_host.get(lg.host, 0) + 1
    for host, n in sorted(by_host.items(), key=lambda kv: -kv[1]):
        if n >= 5:
            res.findings.append(f"{host}: {n} saved credentials")

    res.logins.sort(key=lambda lg: (not lg.date_last_used,
                                    lg.date_last_used or lg.date_created or "",
                                    lg.host))
    return res
