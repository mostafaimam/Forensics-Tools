from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from memory_pslist import __version__
from memory_pslist.loader import MemoryImage, MemoryImageError
from memory_pslist.psscan import scan

_COLUMNS = ["pid", "ppid", "name", "create_time", "exit_time", "exited",
            "confidence", "pool_tag", "phys_offset"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _row(p) -> dict:
    return {"pid": p.pid, "ppid": p.ppid, "name": p.name,
            "create_time": p.create_time, "exit_time": p.exit_time,
            "exited": "yes" if p.exited else "no", "confidence": p.confidence,
            "pool_tag": p.pool_tag, "phys_offset": f"{p.phys_offset:#x}"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="memory_pslist",
        description="Enumerate Windows processes from a RAM dump by pool-tag "
                    "scanning (finds hidden and exited processes; "
                    "profile-independent, so expect some false positives).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  memory_pslist MEMORY.DMP\n"
            "  memory_pslist mem.lime --terminated-only --csv exited.csv\n"
            "  memory_pslist mem.raw --min-confidence medium --json ps.json\n"
        ),
    )
    p.add_argument("image", type=Path, nargs="?")
    p.add_argument("--version", action="version",
                   version=f"memory_pslist {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--running-only", action="store_true")
    p.add_argument("--terminated-only", action="store_true")
    p.add_argument("--name", help="substring filter on the image name")
    p.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   default="low")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _render(rows) -> str:
    out = io.StringIO()
    out.write(f"{'PID':>7} {'PPID':>7}  {'NAME':<20} {'CONF':<7} "
              f"{'CREATE (UTC)':<21} {'EXIT (UTC)':<21}\n")
    out.write("-" * 90 + "\n")
    for r in rows:
        out.write(f"{r['pid']:>7} {r['ppid']:>7}  {r['name'][:20]:<20} "
                  f"{r['confidence']:<7} {r['create_time']:<21} "
                  f"{r['exit_time']:<21}\n")
    return out.getvalue()


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "gui", False):
        from memory_pslist.gui import run_gui
        return run_gui(([str(a.image)] if a.image else []))
    if a.image is None:
        build_parser().error("a RAM dump path is required (or use --gui)")
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    try:
        img = MemoryImage(a.image)
    except MemoryImageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    prog = None if a.quiet else (
        lambda d, t: sys.stderr.write(f"\r  scanning {d}/{t}") or
        sys.stderr.flush())
    procs = scan(img, progress=prog)
    img.close()
    if not a.quiet:
        sys.stderr.write("\r" + " " * 40 + "\r")

    order = {"low": 0, "medium": 1, "high": 2}
    rows = []
    for p in procs:
        if a.running_only and p.exited:
            continue
        if a.terminated_only and not p.exited:
            continue
        if a.name and a.name.lower() not in p.name.lower():
            continue
        if order[p.confidence] < order[a.min_confidence]:
            continue
        rows.append(_row(p))

    if a.csv:
        with a.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=_COLUMNS, dialect="excel")
            w.writeheader()
            for r in rows:
                w.writerow({k: _san(r.get(k, "")) for k in _COLUMNS})
    if a.json:
        a.json.write_text(json.dumps(rows, indent=2))
    if not a.quiet and not (a.csv or a.json):
        print(_render(rows), end="")

    exited = sum(1 for r in rows if r["exited"] == "yes")
    print(f"memory_pslist: {len(rows)} process(es), {exited} exited",
          file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
