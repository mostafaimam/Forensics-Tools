from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analysis_index import __version__
from analysis_index.indexer import build
from analysis_index.output import hit_rows, render, write_csv, write_json
from analysis_index.query import QueryError, search
from analysis_index.store import Index


def _size(s: str) -> int:
    s = str(s).strip().lower()
    mult = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(s, 0)


def build_parser(search_only: bool = False) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_search" if search_only else "analysis_index",
        description="Full-text index and search over a file collection "
                    "(boolean / phrase / proximity / regex; no FTS extension "
                    "required).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  analysis_index build ./idx /mnt/evidence\n"
            "  analysis_index search ./idx 'invoice AND (paypal OR bitcoin)'\n"
            "  analysis_index search ./idx '\"wire transfer\" -template ext:pdf'\n"
            "  analysis_index search ./idx 'password NEAR/5 admin'\n"
            "  analysis_search ./idx '/[a-z0-9._%+-]+@evil\\.com/'\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"analysis_index {__version__}")
    sub = p.add_subparsers(dest="cmd")

    if not search_only:
        b = sub.add_parser("build", help="index a set of paths")
        b.add_argument("index", type=Path)
        b.add_argument("paths", nargs="+", type=Path)
        b.add_argument("--max-size", type=_size, default=_size("50m"),
                       help="skip files larger than this (default 50m)")
        b.add_argument("--reindex", action="store_true",
                       help="re-index files even if unchanged")
        b.add_argument("--no-recurse", action="store_true")
        b.add_argument("--follow-symlinks", action="store_true")
        b.add_argument("-q", "--quiet", action="store_true")

        st = sub.add_parser("stats", help="index summary")
        st.add_argument("index", type=Path)
        ls = sub.add_parser("list", help="list indexed documents")
        ls.add_argument("index", type=Path)
        ls.add_argument("--csv", type=Path)

        gp = sub.add_parser("gui", help="open the graphical search window")
        gp.add_argument("index", type=Path, nargs="?")

    s = sub.add_parser("search", help="run a query")
    s.add_argument("index", type=Path)
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--no-snippets", action="store_true")
    s.add_argument("--snippet-width", type=int, default=160)
    s.add_argument("--csv", type=Path)
    s.add_argument("--json", type=Path)
    s.add_argument("-q", "--quiet", action="store_true")
    return p


def _cmd_build(a) -> int:
    idx = Index(a.index, create=True)
    idx.set_meta("tool", "analysis_index")
    paths = [str(p) for p in a.paths]

    def prog(n, path):
        if not a.quiet and n % 50 == 0:
            sys.stderr.write(f"\r  indexed {n} files…")
            sys.stderr.flush()

    res = build(idx, paths, max_size=a.max_size, reindex=a.reindex,
                recurse=not a.no_recurse, follow_symlinks=a.follow_symlinks,
                progress=prog)
    idx.close()
    if not a.quiet:
        sys.stderr.write("\r")
    print(f"analysis_index: {res['added']} added, {res['updated']} updated, "
          f"{res['skipped']} unchanged", file=sys.stderr)
    return 0


def _cmd_stats(a) -> int:
    try:
        idx = Index(a.index)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    s = idx.stats()
    idx.close()
    print(f"index         : {s['index']}")
    print(f"documents     : {s['documents']:,}")
    print(f"unique terms  : {s['unique_terms']:,}")
    print(f"total tokens  : {s['total_tokens']:,}")
    for k, v in sorted(s["by_kind"].items()):
        print(f"  {k:<14}: {v:,}")
    return 0


def _cmd_list(a) -> int:
    try:
        idx = Index(a.index)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    docs = list(idx.list_docs())
    idx.close()
    if a.csv:
        import csv as _csv
        with a.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = _csv.DictWriter(fh, fieldnames=["path", "size", "ext", "kind",
                                               "n_tokens", "indexed_utc"])
            w.writeheader()
            w.writerows(docs)
    else:
        for d in docs:
            print(f"  {d['kind']:<10} {d['n_tokens']:>8}  {d['path']}")
    return 0 if docs else 1


def _cmd_search(a) -> int:
    try:
        idx = Index(a.index)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        return 2
    try:
        hits = search(idx, a.query, limit=a.limit,
                      snippet_chars=a.snippet_width,
                      max_snippets=0 if a.no_snippets else 3)
    except QueryError as e:
        print(f"query error: {e}", file=sys.stderr)
        idx.close()
        return 2
    idx.close()
    rows = list(hit_rows(hits))
    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(hits, show_snippets=not a.no_snippets), end="")
    print(f"analysis_index: {len(hits)} matching document(s)", file=sys.stderr)
    return 0 if hits else 1


def _dispatch(a, parser) -> int:
    if not a.cmd:
        parser.print_help()
        return 2
    if a.cmd == "gui":
        from analysis_index.gui import run_gui
        return run_gui(str(a.index) if getattr(a, "index", None) else None)
    return {"build": _cmd_build, "stats": _cmd_stats, "list": _cmd_list,
            "search": _cmd_search}[a.cmd](a)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    return _dispatch(a, parser)


def search_main(argv: list[str] | None = None) -> int:
    """Entry point for the ``analysis_search`` command."""
    parser = build_parser(search_only=True)
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] != "search" and not argv[0].startswith("-"):
        argv = ["search", *argv]
    a = parser.parse_args(argv)
    return _dispatch(a, parser)


if __name__ == "__main__":
    raise SystemExit(main())
