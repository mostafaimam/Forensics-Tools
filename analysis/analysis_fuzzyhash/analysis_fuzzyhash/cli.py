from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_fuzzyhash import __version__, tracelib
from analysis_fuzzyhash import ctph, locality
from analysis_fuzzyhash.pehash import parse_pe
from analysis_fuzzyhash.scan import scan

COLUMNS = ["path", "size", "sha256", "ctph", "locality", "imphash",
           "rich_hash", "is_pe", "cluster", "representative", "best_match",
           "best_score", "error"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_fuzzyhash",
        description="Similarity hashing and clustering: CTPH (ssdeep-style), "
                    "a TLSH-style locality digest, and PE imphash / "
                    "rich-header hash. Clusters a file set so near-"
                    "duplicates and variant families group together.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  analysis_fuzzyhash scan /samples --threshold 70 "
                "--csv fh.csv\n"
                "  analysis_fuzzyhash scan /new --against baseline.txt\n"
                "  analysis_fuzzyhash compare a.bin b.bin\n"
                "  analysis_fuzzyhash hash suspicious.exe\n"))
    s = p.add_subparsers(dest="cmd")
    p.add_argument("--version", action="version",
                   version=f"analysis_fuzzyhash {__version__}")

    sc = s.add_parser("scan", help="hash + cluster a collection")
    sc.add_argument("paths", nargs="+", type=Path)
    sc.add_argument("--threshold", type=int, default=70,
                    help="min CTPH/locality score to cluster (default 70)")
    sc.add_argument("--no-recurse", action="store_true")
    sc.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    sc.add_argument("--against", type=Path, metavar="FILE",
                    help="a file of baseline CTPH digests (one per line)")
    sc.add_argument("--clustered-only", action="store_true")
    sc.add_argument("--csv", type=Path)
    sc.add_argument("--json", type=Path)
    sc.add_argument("-q", "--quiet", action="store_true")

    hs = s.add_parser("hash", help="print the digests for one or more files")
    hs.add_argument("files", nargs="+", type=Path)

    cp = s.add_parser("compare", help="score two files 0-100")
    cp.add_argument("a", type=Path)
    cp.add_argument("b", type=Path)

    g = s.add_parser("gui", help="open the graphical viewer")
    g.add_argument("paths", nargs="*", type=str)
    tracelib.add_arguments(p)
    return p


def _digests(path: Path) -> dict:
    data = path.read_bytes()
    pe = parse_pe(data)
    return {"ctph": ctph.hash_bytes(data),
            "locality": locality.digest(data),
            "imphash": pe["imphash"], "rich_hash": pe["rich_hash"]}


def _cmd_hash(a) -> int:
    for f in a.files:
        if not f.exists():
            print(f"not found: {f}", file=sys.stderr)
            continue
        d = _digests(f)
        print(f"{f}")
        print(f"  ctph      {d['ctph']}")
        print(f"  locality  {d['locality']}")
        if d["imphash"]:
            print(f"  imphash   {d['imphash']}")
        if d["rich_hash"]:
            print(f"  richhash  {d['rich_hash']}")
    return 0


def _cmd_compare(a) -> int:
    for f in (a.a, a.b):
        if not f.exists():
            print(f"not found: {f}", file=sys.stderr)
            return 2
    d1, d2 = _digests(a.a), _digests(a.b)
    cs = ctph.compare(d1["ctph"], d2["ctph"])
    ls = locality.similarity(d1["locality"], d2["locality"])
    imp = "same" if d1["imphash"] and d1["imphash"] == d2["imphash"] \
        else "differ"
    print(f"ctph similarity      {cs}/100")
    print(f"locality similarity  {ls}/100")
    print(f"imphash              {imp}")
    return 0 if max(cs, ls) > 0 else 1


def _cmd_scan(a) -> int:
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2
    ctx = tracelib.context(a, "analysis_fuzzyhash", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for p in a.paths:
        ctx.add_input(str(p))

    baseline = None
    if a.against:
        baseline = [ln.strip() for ln in a.against.read_text().splitlines()
                    if ln.strip() and ":" in ln]

    prog = None
    if not a.quiet:
        def prog(n, total):  # noqa: E306
            sys.stderr.write(f"\r  hashing {n}/{total}")
            sys.stderr.flush()

    res = scan([str(p) for p in a.paths], recurse=not a.no_recurse,
               exclude=a.exclude, threshold=a.threshold, progress=prog,
               baseline=baseline)
    if not a.quiet:
        sys.stderr.write("\r" + " " * 30 + "\r")

    rows = [it.row() for it in res.items
            if not a.clustered_only or it.cluster]
    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx, confidence="high", tz="n/a")
    if not a.quiet and not (a.csv or a.json):
        for cid, members in sorted(res.clusters.items()):
            print(f"\ncluster {cid}  ({len(members)} files)")
            for m in members:
                print(f"  {m}")
        singles = [it for it in res.items if not it.cluster and not it.error]
        if singles and not a.clustered_only:
            print(f"\n{len(singles)} unclustered file(s)")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"analysis_fuzzyhash: {len(res.items)} file(s), "
          f"{len(res.clusters)} cluster(s), {res.errors} error(s)",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "gui":
        from analysis_fuzzyhash.gui import run_gui
        return run_gui(getattr(a, "paths", []))
    if a.cmd == "hash":
        return _cmd_hash(a)
    if a.cmd == "compare":
        return _cmd_compare(a)
    if a.cmd == "scan":
        return _cmd_scan(a)
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
