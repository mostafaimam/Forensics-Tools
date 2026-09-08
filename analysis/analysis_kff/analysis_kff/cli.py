from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_kff import __version__, tracelib
from analysis_kff import importers
from analysis_kff.output import render_table, row_dict, write_csv, write_json
from analysis_kff.scan import Summary, scan_hash_list, scan_paths
from analysis_kff.store import CATEGORIES, KFFStore, default_db


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_kff",
        description="Known File Filter: import hash sets (NSRL RDS text/SQLite, "
                    "Project VIC/CAID JSON, HashKeeper, plain hash lists) into "
                    "a local index, then classify files or hashes as "
                    "known-good / known-bad / notable / unknown.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_kff import NSRLFile.txt --name nsrl-2024 --category known-good\n"
            "  analysis_kff import badhashes.txt --name apt-iocs --category known-bad\n"
            "  analysis_kff scan /mnt/evidence/Users --alerts-only --csv hits.csv\n"
            "  analysis_kff scan /cases --ignore-known --csv triage.csv\n"
            "  analysis_kff lookup 44d88612fea8a8f36de82e1278abb02f\n"
            "  analysis_kff sets\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_kff {__version__}")
    p.add_argument("--db", type=Path, help=f"index location (default {default_db()})")
    sub = p.add_subparsers(dest="cmd")

    im = sub.add_parser("import", help="load a hash set into the index")
    im.add_argument("source", type=Path)
    im.add_argument("--name", required=True, help="a label for this set")
    im.add_argument("--category", required=True, choices=CATEGORIES)
    im.add_argument("--format", default="auto",
                    choices=["auto", "nsrl-text", "nsrl-sqlite", "projectvic",
                             "csv", "hashkeeper", "lines"])
    im.add_argument("--note", default="")
    im.add_argument("--replace", action="store_true",
                    help="drop an existing set with the same name first")

    sub.add_parser("sets", help="list imported hash sets")
    sub.add_parser("stats", help="index summary")
    gp = sub.add_parser("gui", help="open the graphical scanner")
    gp.add_argument("paths", nargs="*", type=str)

    rm = sub.add_parser("remove", help="delete a hash set")
    rm.add_argument("--name", required=True)

    lk = sub.add_parser("lookup", help="classify one or more hashes")
    lk.add_argument("hashes", nargs="+")

    sc = sub.add_parser("scan", help="hash files and classify them")
    sc.add_argument("paths", nargs="+", type=Path)
    sc.add_argument("--algo", action="append",
                    choices=["md5", "sha1", "sha256"], default=[])
    sc.add_argument("--hash-list", type=Path,
                    help="classify precomputed hashes from a CSV/JSON instead "
                         "of hashing files")
    sc.add_argument("--ignore-known", action="store_true",
                    help="hide known-good matches")
    sc.add_argument("--alerts-only", action="store_true",
                    help="show only known-bad / notable matches")
    sc.add_argument("--no-recurse", action="store_true")
    sc.add_argument("--follow-symlinks", action="store_true")
    sc.add_argument("--csv", type=Path)
    sc.add_argument("--json", type=Path)
    sc.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _store(a) -> KFFStore:
    return KFFStore(a.db)


def _cmd_import(a) -> int:
    if not a.source.exists():
        print(f"not found: {a.source}", file=sys.stderr)
        return 2
    store = _store(a)
    if store.set_id(a.name) is not None:
        if not a.replace:
            print(f"set '{a.name}' already exists (use --replace)",
                  file=sys.stderr)
            return 2
        store.remove_set(a.name)
    fmt = a.format
    if fmt == "auto":
        fmt = importers.detect_format(a.source)
        print(f"detected format: {fmt}", file=sys.stderr)
    sid = store.create_set(a.name, a.category, str(a.source), fmt, a.note)
    try:
        n = store.import_records(
            sid, importers.parse(str(a.source), fmt),
            progress=lambda c: sys.stderr.write(f"\r  {c:,} hashes…") or
            sys.stderr.flush())
    except (ValueError, OSError) as e:
        store.remove_set(a.name)
        print(f"\nimport failed: {e}", file=sys.stderr)
        return 2
    print(f"\nimported {n:,} hashes into '{a.name}' ({a.category})",
          file=sys.stderr)
    return 0


def _cmd_sets(a) -> int:
    sets = _store(a).list_sets()
    if not sets:
        print("no hash sets imported", file=sys.stderr)
        return 1
    for s in sets:
        print(f"  {s['name']:<24} {s['category']:<11} {s['hashes']:>12,}  "
              f"{s['format']:<12} {s['imported_utc']}"
              + (f"  {s['note']}" if s['note'] else ""))
    return 0


def _cmd_stats(a) -> int:
    st = _store(a).stats()
    print(f"index    : {st['db']}")
    print(f"sets     : {st['sets']}")
    print(f"hashes   : {st['hashes']:,}")
    for cat, n in sorted(st["by_category"].items()):
        print(f"  {cat:<11}: {n:,}")
    return 0


def _cmd_remove(a) -> int:
    ok = _store(a).remove_set(a.name)
    print(f"removed '{a.name}'" if ok else f"no set '{a.name}'",
          file=sys.stderr)
    return 0 if ok else 1


def _cmd_lookup(a) -> int:
    store = _store(a)
    rc = 0
    for h in a.hashes:
        h = h.strip().lower()
        algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))
        if not algo:
            print(f"  {h}  ? (not a known hash length)")
            continue
        res = store.classify({algo: h})
        tag = res["status"].upper() if res["status"] != "unknown" else "unknown"
        print(f"  {h}  {tag}" + (f"  [{res['set']}]" if res["set"] else ""))
        if res["status"] in ("known-bad", "notable"):
            rc = 1
    return rc


def _cmd_scan(a) -> int:
    ctx = tracelib.context(a, "analysis_kff", __version__)
    try:
        ctx.limits.check_paths([str(p) for p in a.paths])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for _p in a.paths:
        ctx.add_input(str(_p))
    store = _store(a)
    if store.stats()["hashes"] == 0:
        print("the index is empty - import a hash set first", file=sys.stderr)
        return 2
    algos = tuple(a.algo) or ("md5", "sha1", "sha256")
    summary = Summary()
    kept = []

    def keep(r):
        summary.add(r.status)
        if a.alerts_only and r.status not in ("known-bad", "notable"):
            return
        if a.ignore_known and r.status == "known-good":
            return
        kept.append(row_dict(r))

    if a.hash_list:
        for r in scan_hash_list(store, str(a.hash_list)):
            keep(r)
    else:
        prog = None if a.quiet else _progress()
        for r in scan_paths(store, [str(p) for p in a.paths], algos=algos,
                            recurse=not a.no_recurse,
                            follow_symlinks=a.follow_symlinks, progress=prog):
            keep(r)
        if prog:
            sys.stderr.write("\n")

    if a.csv:
        write_csv(kept, a.csv)
    if a.json:
        write_json(kept, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render_table(kept))

    parts = ", ".join(f"{k}={v}" for k, v in sorted(summary.counts.items()))
    print(f"analysis_kff: {summary.total} file(s) - {parts}", file=sys.stderr)
    alerts = summary.counts.get("known-bad", 0) + summary.counts.get("notable", 0)
    ctx.finish(outputs=[a.csv, a.json])

    return 1 if alerts else 0


def _progress():
    state = {"n": 0}

    def cb(n, path):
        state["n"] = n
        if n % 200 == 0:
            sys.stderr.write(f"\r  hashed {n} files…")
            sys.stderr.flush()
    return cb


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if not a.cmd:
        build_parser().print_help()
        return 2
    if a.cmd == "gui":
        from analysis_kff.gui import run_gui
        return run_gui(a.db and str(a.db) or None, getattr(a, "paths", []))
    return {
        "import": _cmd_import, "sets": _cmd_sets, "stats": _cmd_stats,
        "remove": _cmd_remove, "lookup": _cmd_lookup, "scan": _cmd_scan,
    }[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())
