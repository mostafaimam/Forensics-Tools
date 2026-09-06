from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from macos_plist import __version__
from macos_plist.flatten import flatten, get_path, json_safe
from macos_plist.nskeyedarchiver import is_keyed_archive, unwrap
from macos_plist.output import flat_rows, render, write_csv, write_json
from macos_plist.reader import load_file


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_plist",
        description="Read macOS property lists (binary bplist00 or XML), "
                    "unwrap NSKeyedArchiver graphs, and flatten to CSV / JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  macos_plist com.apple.dock.plist --json dock.json\n"
            "  macos_plist ~/Library/Preferences --csv prefs.csv\n"
            "  macos_plist LastSession.plist --key 'root.NSWindow'\n"
            "  macos_plist state.plist --no-unwrap --json raw.json\n"
        ),
    )
    p.add_argument("inputs", nargs="*", type=Path, metavar="PLIST",
                   help=".plist file(s) or directories to search")
    p.add_argument("--version", action="version",
                   version=f"macos_plist {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--key", metavar="PATH",
                   help="print just the value at this key path (a.b[0].c)")
    p.add_argument("--no-unwrap", action="store_true",
                   help="do not resolve NSKeyedArchiver graphs")
    p.add_argument("--recurse", action="store_true", default=True)
    p.add_argument("--no-recurse", dest="recurse", action="store_false")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _expand(inputs, recurse: bool):
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*") if recurse else p.iterdir()
            for c in sorted(it):
                if c.is_file() and c.suffix.lower() in (".plist", ""):
                    yield c
        else:
            yield p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from macos_plist.gui import run_gui
        return run_gui([str(x) for x in (args.inputs or [])])
    files = list(_expand(args.inputs, args.recurse))
    if not files:
        print("error: no plist files found", file=sys.stderr)
        return 2

    loaded: list[tuple] = []
    errors = 0
    for f in files:
        lp = load_file(f)
        value = lp.value
        if lp.parse_error:
            errors += 1
        elif lp.is_keyed_archive and not args.no_unwrap:
            try:
                value = unwrap(lp.value)
            except Exception as e:  # noqa: BLE001
                lp.warnings.append(f"NSKeyedArchiver unwrap failed: {e}")
        loaded.append((lp, value))

    if args.key:
        for lp, value in loaded:
            got = get_path(value, args.key)
            if got is not None:
                print(f"# {lp.source}")
                print(json.dumps(json_safe(got), indent=2, ensure_ascii=False))
        return 0

    if args.csv:
        write_csv(flat_rows(loaded), args.csv)
    if args.json:
        write_json(loaded, args.json)
    if not args.quiet and not (args.csv or args.json):
        print(render(loaded))

    ka = sum(1 for lp, _v in loaded if lp.is_keyed_archive)
    print(f"macos_plist {__version__}: {len(files)} file(s), {ka} keyed "
          f"archive(s), {errors} parse error(s)", file=sys.stderr)
    return 1 if errors and errors == len(files) else 0


if __name__ == "__main__":
    raise SystemExit(main())
