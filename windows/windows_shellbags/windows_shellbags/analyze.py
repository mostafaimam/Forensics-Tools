"""Discover UsrClass.dat / NTUSER.DAT under a root and walk their shellbags."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from windows_shellbags import bagmru as _bag
from windows_shellbags import flags as _flags


@dataclass
class Result:
    bags: list = field(default_factory=list)
    hives: list = field(default_factory=list)
    errors: list = field(default_factory=list)


_HIVE_GLOBS = [
    "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",
    "Users/*/NTUSER.DAT",
    "Documents and Settings/*/Local Settings/Application Data/Microsoft/"
    "Windows/UsrClass.dat",
    "Documents and Settings/*/NTUSER.DAT",
]


def _user_of(path: str) -> str:
    m = re.search(r"[\\/](?:Users|Documents and Settings)[\\/]([^\\/]+)[\\/]",
                  path)
    return m.group(1) if m else ""


def _discover(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    out: list[Path] = []
    for g in _HIVE_GLOBS:
        out += [p for p in root.glob(g) if p.is_file()]
    # also accept being pointed straight at a hive-holding dir
    for name in ("UsrClass.dat", "NTUSER.DAT"):
        if (root / name).is_file():
            out.append(root / name)
    return sorted(set(out))


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        for hp in _discover(Path(path)):
            r = _bag.from_hive_file(hp)
            res.errors += [f"{hp.name}: {e}" for e in r.errors]
            if not r.bags:
                continue
            res.hives.append(f"{hp} [{r.hive_kind} / {r.root_key}]")
            user = _user_of(str(hp))
            for b in r.bags:
                b.source = str(hp)
                b.notable = _flags.flag(b, account_user=user)
                res.bags.append(b)
    res.bags.sort(key=lambda b: (b.depth, b.path.lower()))
    return res
