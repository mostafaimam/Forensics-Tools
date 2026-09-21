from __future__ import annotations

import sys
import argparse
from pathlib import Path

from browser_favicons import __version__, tracelib
from browser_favicons.collect import COLUMNS, collect
from browser_favicons.sniff import ext_for


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_favicons",
        description="Read Chromium's Favicons database and Firefox's "
                    "favicons.sqlite: the icon-to-page-URL map, which is "
                    "cached for UI speed rather than user-visible history "
                    "and so often survives a 'clear browsing data' that "
                    "wipes History. --history cross-references page URLs "
                    "against a live History/places.sqlite to flag pages "
                    "whose visit was cleared but whose icon wasn't.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_favicons Favicons\n"
                "  browser_favicons \"User Data/Default\" --history History"
                " --csv icons.csv\n"
                "  browser_favicons Favicons --extract-dir ./icons\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a Favicons/favicons.sqlite file, or a directory "
                   "to search recursively")
    p.add_argument("--version", action="version",
                   version=f"browser_favicons {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--history", metavar="PATH",
                   help="a History / places.sqlite to cross-reference "
                   "page URLs against")
    p.add_argument("--cleared-only", action="store_true",
                   help="only rows whose page URL is missing from "
                   "--history")
    p.add_argument("--extract-dir", type=Path,
                   help="write every cached icon image to this directory")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_favicons.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "browser_favicons", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    res = collect([a.target], history_path=a.history)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    keep_idx = list(range(len(res.rows)))
    if a.cleared_only:
        keep_idx = [i for i in keep_idx
                   if res.rows[i]["cleared_from_history"] is True]
    rows = [res.rows[i] for i in keep_idx]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = " [cleared-from-history]" if r["cleared_from_history"] \
                is True else ""
            print(f"{r['browser']:<9} {r['page_url']}  <- {r['icon_url']}"
                 f"{tag}")

    if a.extract_dir:
        a.extract_dir.mkdir(parents=True, exist_ok=True)
        n = 0
        for out_i, i in enumerate(keep_idx):
            image = res.images.get(i)
            if not image:
                continue
            out = a.extract_dir / f"icon_{out_i:04d}{ext_for(image)}"
            out.write_bytes(image)
            n += 1
        print(f"browser_favicons: extracted {n} icon(s) to {a.extract_dir}",
             file=sys.stderr)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"browser_favicons: {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
