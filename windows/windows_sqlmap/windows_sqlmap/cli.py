from __future__ import annotations

import argparse
import sys
from pathlib import Path

from windows_sqlmap import __version__, tracelib
from windows_sqlmap.analyze import scan
from windows_sqlmap.discover import find, is_sqlite
from windows_sqlmap.maps import builtin_maps, load_map_dir


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_sqlmap",
        description="Locate SQLite databases anywhere under a target (by "
                    "header magic, any extension) and run named extraction "
                    "maps against them - a generic engine for the long tail "
                    "of app databases not covered by a dedicated parser. A "
                    "database matching no map is still listed with its "
                    "table / row-count schema for manual review.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_sqlmap C:/Users --csv hits.csv\n"
                "  windows_sqlmap main.db --map skype_main --json chat.json\n"
                "  windows_sqlmap E:\\ --map-dir ./my_maps --list-maps\n"
                "  windows_sqlmap unknown.db --dump-table Messages\n"))
    p.add_argument("paths", nargs="*", type=Path,
                   help="a folder tree or specific .db file(s)")
    p.add_argument("--version", action="version",
                   version=f"windows_sqlmap {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--map", metavar="NAME",
                   help="only run this named map (built-in or from --map-dir)")
    p.add_argument("--map-dir", action="append", default=[], metavar="DIR",
                   help="load additional *.json maps from DIR; repeatable")
    p.add_argument("--list-maps", action="store_true",
                   help="print the available maps and exit")
    p.add_argument("--dump-table", metavar="TABLE",
                   help="also dump this table raw from every database that "
                        "has it")
    p.add_argument("--unmatched-only", action="store_true",
                   help="only show the schema recon for databases no map "
                        "matched")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _load_maps(a):
    maps = builtin_maps()
    for d in a.map_dir:
        maps.extend(load_map_dir(d))
    if a.map:
        maps = [m for m in maps if m.name == a.map]
    return maps


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    maps = _load_maps(a)
    if a.list_maps:
        for m in maps:
            tabs = ", ".join(m.match_tables)
            print(f"{m.name:<20} [{tabs}]  {m.description}")
        return 0
    if a.gui:
        from windows_sqlmap.gui import run_gui
        return run_gui([str(p) for p in a.paths])
    if not a.paths:
        build_parser().error("give at least one path (or --list-maps / --gui)")
    missing = [p for p in a.paths if not p.exists()]
    for p in missing:
        print(f"not found: {p}", file=sys.stderr)
    if missing:
        return 2
    if a.map and not maps:
        print(f"unknown map: {a.map} (see --list-maps)", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_sqlmap", __version__)
    strpaths = [str(p) for p in a.paths]
    try:
        ctx.limits.check_paths(strpaths)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = find(strpaths)
    for d in dbs:
        ctx.add_input(str(d))
    res = scan(dbs, maps, dump_table=a.dump_table)
    for e in res.errors:
        ctx.error("sqlmap-error", e)

    rows = []
    if not a.unmatched_only:
        for h in res.hits:
            for r in h.rows:
                row = dict(r)
                row["_db"] = h.db
                row["_map"] = h.map_name
                rows.append(row)

    if a.csv or a.json:
        cols = ["_db", "_map"]
        seen = set(cols)
        for r in rows:
            for k in r:
                if k not in seen:
                    seen.add(k)
                    cols.append(k)
        if a.csv:
            tracelib.write_csv(rows, a.csv, cols, ctx,
                               confidence="medium", tz="varies-by-map")
        if a.json:
            tracelib.write_json(rows, a.json, ctx,
                                confidence="medium", tz="varies-by-map")

    if not a.quiet and not (a.csv or a.json):
        for h in res.hits:
            print(f"\n{h.db}")
            print(f"  map: {h.map_name}  ({h.description})  "
                  f"[{len(h.rows)} row(s)]")
            if h.error:
                print(f"  ! {h.error}")
            for r in h.rows[:10]:
                print(f"    {r}")
        for rc in res.recon:
            print(f"\n{rc.db}  (no map matched)")
            for name, count in rc.tables[:30]:
                print(f"    {name:<28} {count if count >= 0 else '?'} row(s)")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"windows_sqlmap: {res.dbs_seen} database(s), {len(res.hits)} "
          f"map hit(s), {len(res.recon)} unmatched", file=sys.stderr)
    for e in res.errors:
        print(f"  ! {e}", file=sys.stderr)
    return 0 if (res.hits or res.recon) else 1


if __name__ == "__main__":
    raise SystemExit(main())
