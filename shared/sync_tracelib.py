#!/usr/bin/env python3
"""Copy shared/tracelib.py into every tool package that imports it.

A tool "opts in" simply by having ``import tracelib`` somewhere in its
package.  Run this after editing the canonical copy::

    python shared/sync_tracelib.py            # sync
    python shared/sync_tracelib.py --check    # CI: fail if any copy is stale
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANON = ROOT / "shared" / "tracelib.py"
CATEGORIES = ("acquisition", "mounting", "recovery", "windows", "linux",
              "macos", "memory", "analysis", "utilities", "browser",
              "network", "cloud", "mobile", "apps")


def _targets() -> list[Path]:
    out: list[Path] = []
    for cat in CATEGORIES:
        cdir = ROOT / cat
        if not cdir.is_dir():
            continue
        for tool in sorted(p for p in cdir.iterdir() if p.is_dir()):
            pkg = tool / tool.name
            if not pkg.is_dir():
                continue
            uses = any(
                ("import tracelib" in txt or "tracelib." in txt
                 or "tracelib," in txt or ", tracelib" in txt)
                for f in pkg.glob("*.py") if f.name != "tracelib.py"
                for txt in [f.read_text(encoding="utf-8", errors="ignore")])
            if uses:
                out.append(pkg / "tracelib.py")
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    canon = CANON.read_text(encoding="utf-8")
    targets = _targets()
    stale = []
    for t in targets:
        current = t.read_text(encoding="utf-8") if t.exists() else None
        if current == canon:
            continue
        stale.append(t)
        if not check:
            t.write_text(canon, encoding="utf-8")
    rel = [str(t.relative_to(ROOT)) for t in stale]
    if check:
        if stale:
            print("stale tracelib copies:\n  " + "\n  ".join(rel))
            return 1
        print(f"tracelib in sync across {len(targets)} tool(s)")
        return 0
    if stale:
        print(f"updated {len(stale)} copy(ies):\n  " + "\n  ".join(rel))
    else:
        print(f"tracelib already in sync ({len(targets)} tool(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
