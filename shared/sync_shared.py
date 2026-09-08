#!/usr/bin/env python3
"""Copy the canonical shared/*.py helpers into every tool package that uses them.

A tool "opts in" to a helper simply by referencing it (``import tracelib`` /
``import fuzzlib`` or ``tool.tracelib`` / ``tool.fuzzlib``) in any of its
package `.py` files.  Run after editing a canonical copy::

    python shared/sync_shared.py            # sync
    python shared/sync_shared.py --check    # CI: non-zero exit if any copy stale
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ("tracelib.py", "fuzzlib.py")
CATEGORIES = ("acquisition", "mounting", "recovery", "windows", "linux",
              "macos", "memory", "analysis", "utilities", "browser",
              "network", "cloud", "mobile", "apps")


def _packages():
    for cat in CATEGORIES:
        cdir = ROOT / cat
        if not cdir.is_dir():
            continue
        for tool in sorted(p for p in cdir.iterdir() if p.is_dir()):
            pkg = tool / tool.name
            if pkg.is_dir():
                yield pkg


def _uses(pkg: Path, stem: str) -> bool:
    files = list(pkg.glob("*.py"))
    tdir = pkg.parent / "tests"
    if tdir.is_dir():
        files += list(tdir.glob("*.py"))
    for f in files:
        if f.name == f"{stem}.py":
            continue
        txt = f.read_text(encoding="utf-8", errors="ignore")
        if (f"import {stem}" in txt or f"{stem}." in txt
                or f"{stem}," in txt or f", {stem}" in txt):
            return True
    return False


def main(argv) -> int:
    check = "--check" in argv
    canon = {h: (ROOT / "shared" / h).read_text(encoding="utf-8")
             for h in HELPERS}
    stale: list[str] = []
    n_pkgs = {h: 0 for h in HELPERS}
    for pkg in _packages():
        for h in HELPERS:
            stem = h[:-3]
            if not _uses(pkg, stem):
                continue
            n_pkgs[h] += 1
            target = pkg / h
            cur = target.read_text(encoding="utf-8") if target.exists() else None
            if cur == canon[h]:
                continue
            stale.append(str(target.relative_to(ROOT)))
            if not check:
                target.write_text(canon[h], encoding="utf-8")
    counts = ", ".join(f"{h[:-3]} x{n_pkgs[h]}" for h in HELPERS)
    if check:
        if stale:
            print("stale copies:\n  " + "\n  ".join(stale))
            return 1
        print(f"shared helpers in sync ({counts})")
        return 0
    if stale:
        print(f"updated {len(stale)} copy(ies):\n  " + "\n  ".join(stale))
    else:
        print(f"already in sync ({counts})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
