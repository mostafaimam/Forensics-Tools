from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from windows_jumplist import __version__, tracelib
from windows_jumplist.jumplist import parse_file
from windows_jumplist.lnk import iso
from windows_jumplist.ole import OleError

COLUMNS = [
    "source_file", "app_id", "application", "entry_number", "mru_position",
    "pinned", "last_used_utc", "target_path", "hostname", "interaction_count",
    "lnk_target_modified_utc", "lnk_drive_serial", "lnk_machine_id",
    "lnk_mft_entry",
]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _rows(jl):
    for it in jl.items:
        lnk = it.lnk
        mft = ""
        if lnk:
            for i in lnk.target_items:
                if i.get("mft_entry"):
                    mft = f"{i['mft_entry']}-{i.get('mft_sequence', 0)}"
        yield {
            "source_file": jl.source,
            "app_id": jl.app_id,
            "application": jl.application,
            "entry_number": it.entry_number,
            "mru_position": it.mru_position,
            "pinned": "yes" if it.pinned else "no",
            "last_used_utc": iso(it.last_used),
            "target_path": it.target_path,
            "hostname": it.hostname,
            "interaction_count": it.interaction_count,
            "lnk_target_modified_utc": iso(lnk.target_modified) if lnk else "",
            "lnk_drive_serial": lnk.drive_serial if lnk else "",
            "lnk_machine_id": (lnk.tracker.machine_id
                               if lnk and lnk.tracker else ""),
            "lnk_mft_entry": mft,
        }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_jumplist",
        description="Parse automaticDestinations-ms jump lists: the DestList "
                    "MRU stream plus every embedded LNK.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_jumplist *.automaticDestinations-ms --csv jl.csv\n"
            "  windows_jumplist \"%APPDATA%\\Microsoft\\Windows\\Recent\\"
            "AutomaticDestinations\" --csv all.csv\n"
        ),
    )
    p.add_argument("inputs", nargs="*", type=Path, metavar="FILE")
    p.add_argument("--version", action="version",
                   version=f"windows_jumplist {__version__}")
    p.add_argument("--gui", action="store_true",
                   help="open the graphical viewer")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--pinned-only", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _expand(inputs):
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            yield from sorted(p.rglob("*.automaticDestinations-ms"))
        else:
            yield p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "gui", False):
        from windows_jumplist.gui import run_gui
        return run_gui([str(x) for x in (args.inputs or [])])
    files = list(_expand(args.inputs))
    if not files:
        print("error: no jump-list files found", file=sys.stderr)
        return 2

    ctx = tracelib.context(args, "windows_jumplist", __version__)
    try:
        ctx.limits.check_paths([str(f) for f in files])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    for f in files:
        ctx.add_input(str(f))

    lists = []
    errors = 0
    for f in files:
        try:
            lists.append(parse_file(f))
        except (OleError, OSError, ValueError) as e:
            errors += 1
            print(f"! {f}: {e}", file=sys.stderr)

    rows = []
    for jl in lists:
        for r in _rows(jl):
            if args.pinned_only and r["pinned"] != "yes":
                continue
            rows.append(r)

    if errors:
        ctx.warn("partial", "parse-error",
                 f"{errors} jump-list file(s) failed to parse")
    if args.csv:
        tracelib.write_csv(rows, args.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if args.json:
        tracelib.write_json(rows, args.json, ctx,
                            confidence="high", tz="utc-native")
    if not args.quiet and not (args.csv or args.json):
        print(_render(lists))

    _mpath = ctx.finish(outputs=[args.csv, args.json])
    total_items = sum(len(jl.items) for jl in lists)
    print(f"windows_jumplist {__version__}: {len(lists)} list(s), "
          f"{total_items} item(s), {errors} error(s)", file=sys.stderr)
    return 1 if errors and not lists else 0


def _render(lists, limit: int = 60) -> str:
    out = io.StringIO()
    for jl in lists:
        out.write(f"# {Path(jl.source).name}  "
                  f"[{jl.application or jl.app_id}]  "
                  f"v{jl.destlist_version}, {len(jl.items)} items, "
                  f"{jl.pinned_count} pinned\n")
        for it in jl.items[:limit]:
            pin = " PIN" if it.pinned else "    "
            out.write(f"  {it.mru_position:>3}{pin}  {iso(it.last_used):27}  "
                      f"{it.target_path}\n")
        if len(jl.items) > limit:
            out.write(f"  ... {len(jl.items) - limit} more\n")
        out.write("\n")
    return out.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
