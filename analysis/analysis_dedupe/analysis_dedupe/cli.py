from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from analysis_dedupe import __version__
from analysis_dedupe.scan import load_hash_set, scan

_COLUMNS = ["path", "size", "digest", "group", "representative",
            "duplicate_of", "status"]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _size(s: str) -> int:
    s = str(s).strip().lower()
    m = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
    return int(float(s[:-1]) * m[s[-1]]) if s and s[-1] in m else int(s, 0)


def _si(n) -> str:
    f = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if f < 1024 or u == "TiB":
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} B"
        f /= 1024
    return f"{n} B"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_dedupe",
        description="Hash-based deduplication: group files by content, report "
                    "duplicate sets and reclaimable bytes, emit a distinct "
                    "file list, or diff a target set against a baseline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_dedupe scan /cases/evidence --csv files.csv\n"
            "  analysis_dedupe scan /export --distinct-out unique.txt\n"
            "  analysis_dedupe scan /new --against baseline.csv --new-only\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_dedupe {__version__}")
    s = p.add_subparsers(dest="cmd")
    sc = s.add_parser("scan", help="deduplicate a collection")
    sc.add_argument("paths", nargs="+", type=Path)
    sc.add_argument("--algo", choices=["md5", "sha1", "sha256"], default="sha256")
    sc.add_argument("--min-size", type=_size, default=1)
    sc.add_argument("--full", action="store_true",
                    help="hash every file, not just size collisions")
    sc.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    sc.add_argument("--no-recurse", action="store_true")
    sc.add_argument("--follow-symlinks", action="store_true")
    sc.add_argument("--against", type=Path, metavar="HASHSET",
                    help="a CSV/JSON of baseline hashes; classify each file "
                         "new vs baseline-hit")
    sc.add_argument("--new-only", action="store_true",
                    help="with --against: only files not in the baseline")
    sc.add_argument("--dupes-only", action="store_true",
                    help="only files that have a duplicate")
    sc.add_argument("--distinct-out", type=Path,
                    help="write one representative path per unique content")
    sc.add_argument("--csv", type=Path)
    sc.add_argument("--json", type=Path)
    sc.add_argument("-q", "--quiet", action="store_true")
    return p


def _cmd_scan(a) -> int:
    baseline = None
    if a.against:
        if not a.against.exists():
            print(f"not found: {a.against}", file=sys.stderr)
            return 2
        baseline = load_hash_set(str(a.against))
    prog = None if a.quiet else (
        lambda n: sys.stderr.write(f"\r  hashed {n} files") or sys.stderr.flush())
    res = scan([str(p) for p in a.paths], algo=a.algo,
               recurse=not a.no_recurse, follow_symlinks=a.follow_symlinks,
               exclude=a.exclude, min_size=a.min_size, full=a.full,
               baseline=baseline, progress=prog)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 30 + "\r")

    rows = []
    for r in res.files:
        if a.dupes_only and not (r.duplicate_of or (
                r.representative and len(res.groups.get(r.digest, [])) > 1)):
            continue
        if a.new_only and r.status != "new":
            continue
        rows.append({"path": r.path, "size": r.size, "digest": r.digest,
                     "group": r.group if r.group > 0 else "",
                     "representative": "yes" if r.representative else "no",
                     "duplicate_of": r.duplicate_of, "status": r.status})

    if a.csv:
        with a.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=_COLUMNS, dialect="excel")
            w.writeheader()
            for r in rows:
                w.writerow({k: _san(r.get(k, "")) for k in _COLUMNS})
    if a.json:
        a.json.write_text(json.dumps(rows, indent=2))
    if a.distinct_out:
        reps = sorted(r.path for r in res.files
                      if r.representative or not r.digest)
        a.distinct_out.write_text("\n".join(reps) + "\n", encoding="utf-8")

    if not a.quiet and not (a.csv or a.json):
        print(_render_groups(res))

    dup_groups = sum(1 for g in res.groups.values() if len(g) > 1)
    msg = (f"analysis_dedupe: {res.scanned} file(s), {res.unique} unique, "
           f"{dup_groups} duplicate group(s), {_si(res.reclaimable)} reclaimable")
    if baseline is not None:
        new = sum(1 for r in res.files if r.status == "new")
        msg += f", {new} not in baseline"
    print(msg, file=sys.stderr)
    return 0


def _render_groups(res) -> str:
    out = io.StringIO()
    dups = sorted(((g[0].size, d, g) for d, g in res.groups.items()
                   if len(g) > 1), reverse=True)
    for size, digest, g in dups[:200]:
        out.write(f"\n{digest[:16]}…  {_si(size)} x{len(g)}  "
                  f"(wastes {_si(size * (len(g) - 1))})\n")
        for r in g:
            out.write(f"  {'*' if r.representative else ' '} {r.path}\n")
    if len(dups) > 200:
        out.write(f"\n... {len(dups) - 200} more groups (use --csv)\n")
    return out.getvalue()


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd != "scan":
        build_parser().print_help()
        return 2
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2
    return _cmd_scan(a)


if __name__ == "__main__":
    raise SystemExit(main())
