from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from browser_downloads import __version__
from browser_downloads.analyze import analyze
from browser_downloads.output import COLUMNS, render, row, write_csv, write_json

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="browser_downloads",
        description="Every recorded file download, cross-referenced to disk. "
                    "Reads Chromium 'History.downloads' and Firefox "
                    "places.sqlite / downloads.sqlite, and correlates with "
                    ".crdownload / .part leftovers and the NTFS "
                    ":Zone.Identifier (Mark-of-the-Web). Read-only, WAL-safe. "
                    "Pure standard library.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  browser_downloads ./History\n"
                "  browser_downloads /mnt/evidence/Users --csv downloads.csv\n"
                "  browser_downloads ./profile --notable-only --hash\n"
                "  browser_downloads ./History --grep '\\.exe$|\\.iso$'\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="a History / places.sqlite store, or a folder to walk")
    p.add_argument("--version", action="version",
                   version=f"browser_downloads {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--no-fs", action="store_true",
                   help="do not scan the filesystem (history stores only)")
    p.add_argument("--hash", action="store_true",
                   help="SHA-256 the on-disk file for each download (<=512 MB)")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--on-disk", choices=["present", "missing", "partial"],
                   help="filter by whether the saved file is still there")
    p.add_argument("--browser", help="only this browser")
    p.add_argument("--grep", metavar="REGEX",
                   help="match filename / URL / target path")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from browser_downloads.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("a history store or a folder is required")
    for p in a.paths:
        if not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    grep = re.compile(a.grep, re.I) if a.grep else None
    res = analyze([str(p) for p in a.paths], scan_fs=not a.no_fs,
                  do_hash=a.hash)

    rows = []
    for d in res.downloads:
        r = row(d)
        if a.on_disk and r["on_disk"] != a.on_disk:
            continue
        if a.browser and r["browser"].lower() != a.browser.lower():
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(
                f"{r['filename']} {r['url']} {r['target_path']}"):
            continue
        rows.append(r)

    if a.csv:
        write_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render(rows), end="")

    fl = sum(1 for r in rows if r["notable"])
    print(f"browser_downloads: {res.stores} history store(s), "
          f"{res.from_disk} disk artefact(s) -> {len(rows)} download(s), "
          f"{fl} flagged", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
