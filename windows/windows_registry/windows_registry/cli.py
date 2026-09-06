from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_registry import __version__
from windows_registry.hive import HiveError, RegistryHive, to_text
from windows_registry.output import (
    iter_dump_rows,
    render_key,
    render_table,
    write_dump_csv,
    write_json,
    write_plugin_csv,
)
from windows_registry.plugins import PLUGINS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_registry",
        description="Offline Windows registry hive (regf) parser: dump, search, "
                    "run built-in plugins, recover deleted keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_registry dump NTUSER.DAT --csv ntuser.csv\n"
            "  windows_registry key SYSTEM 'ControlSet001\\Services\\Tcpip'\n"
            "  windows_registry search SOFTWARE --value-data mimikatz\n"
            "  windows_registry plugin NTUSER.DAT --plugin userassist,run-keys\n"
            "  windows_registry dump NTUSER.DAT --deleted --csv recovered.csv\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"windows_registry {__version__}")
    p.add_argument("--list-plugins", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("hive", type=Path)

    d = sub.add_parser("dump", parents=[common], help="dump keys and values")
    d.add_argument("--under", metavar="KEYPATH",
                   help="only dump this key subtree")
    d.add_argument("--deleted", action="store_true",
                   help="also recover keys from free cells")
    d.add_argument("--csv", type=Path)
    d.add_argument("--json", type=Path)
    d.add_argument("--max-table", type=int, default=200)
    d.add_argument("-q", "--quiet", action="store_true")

    k = sub.add_parser("key", parents=[common], help="show one key")
    k.add_argument("path")
    k.add_argument("--recursive", action="store_true")

    s = sub.add_parser("search", parents=[common], help="regex search")
    s.add_argument("pattern")
    s.add_argument("--key-name", action="store_true")
    s.add_argument("--value-name", action="store_true")
    s.add_argument("--value-data", action="store_true")
    s.add_argument("--csv", type=Path)
    s.add_argument("-q", "--quiet", action="store_true")

    pl = sub.add_parser("plugin", parents=[common], help="run built-in plugins")
    pl.add_argument("--plugin", type=lambda x: x.split(","), default=None,
                    metavar="ID,ID", help="which plugins (default: all)")
    pl.add_argument("--csv", type=Path, help="write one CSV per plugin (prefix)")
    pl.add_argument("--json", type=Path)
    pl.add_argument("-q", "--quiet", action="store_true")

    g = sub.add_parser("gui", help="open the graphical hive browser")
    g.add_argument("hive", type=Path, nargs="?")
    return p


def _open(path: Path) -> RegistryHive:
    return RegistryHive(path.read_bytes())


def _cmd_dump(a, log) -> int:
    hive = _open(a.hive)
    start = hive.get(a.under) if a.under else hive.root()
    if start is None:
        print(f"key not found: {a.under}", file=sys.stderr)
        return 2
    keys = list(hive.walk(start))
    if a.deleted:
        keys += list(hive.recover_deleted())
    rows = list(iter_dump_rows(hive, keys))
    if a.csv:
        write_dump_csv(rows, a.csv)
    if a.json:
        write_json(rows, a.json)
    if not a.quiet and not (a.csv or a.json):
        print(render_table(rows, a.max_table))
    deleted = sum(1 for k in keys if k.deleted)
    print(f"windows_registry: {len(keys)} keys ({deleted} recovered), "
          f"{len(rows)} rows", file=sys.stderr)
    return 0


def _cmd_key(a, log) -> int:
    hive = _open(a.hive)
    key = hive.get(a.path)
    if key is None:
        print(f"key not found: {a.path}", file=sys.stderr)
        return 2
    if a.recursive:
        for k in hive.walk(key):
            print(render_key(hive, k))
    else:
        print(render_key(hive, key))
    return 0


def _cmd_search(a, log) -> int:
    hive = _open(a.hive)
    try:
        rx = re.compile(a.pattern, re.IGNORECASE)
    except re.error as e:
        print(f"bad regex: {e}", file=sys.stderr)
        return 2
    fields = [a.key_name, a.value_name, a.value_data]
    if not any(fields):
        a.key_name = a.value_name = a.value_data = True
    hits = []
    for k in hive.walk():
        if a.key_name and rx.search(k.name):
            hits.append({"key_path": k.path, "match": "key-name",
                         "detail": k.name})
        for v in k.values():
            if a.value_name and rx.search(v.name):
                hits.append({"key_path": k.path, "match": "value-name",
                             "detail": v.name})
            if a.value_data and rx.search(to_text(v.data)):
                hits.append({"key_path": k.path, "match": "value-data",
                             "detail": f"{v.name} = {to_text(v.data)[:120]}"})
    if a.csv:
        write_plugin_csv(hits, a.csv)
    if not a.quiet:
        for h in hits[:500]:
            print(f"{h['match']:<11} {h['key_path']}  ::  {h['detail']}")
    print(f"windows_registry: {len(hits)} match(es)", file=sys.stderr)
    return 0 if hits else 1


def _cmd_plugin(a, log) -> int:
    hive = _open(a.hive)
    chosen = a.plugin or list(PLUGINS)
    unknown = [c for c in chosen if c not in PLUGINS]
    if unknown:
        print(f"unknown plugin(s): {unknown}", file=sys.stderr)
        return 2
    allrows = {}
    for name in chosen:
        fn, _desc = PLUGINS[name]
        try:
            rows = fn(hive)
        except Exception as e:  # noqa: BLE001
            print(f"! plugin {name} failed: {e}", file=sys.stderr)
            rows = []
        allrows[name] = rows
        if a.csv and rows:
            write_plugin_csv(rows, a.csv.with_name(f"{a.csv.stem}_{name}.csv"))
        if not a.quiet:
            print(f"\n== {name} ==  ({len(rows)} rows)")
            for r in rows[:40]:
                print("  " + "  ".join(f"{k}={v}" for k, v in r.items() if v))
    if a.json:
        write_json([{**{"_plugin": n}, **r} for n, rs in allrows.items()
                    for r in rs], a.json)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_plugins:
        for name, (_fn, desc) in PLUGINS.items():
            print(f"  {name:<16} {desc}")
        return 0
    if not args.cmd:
        build_parser().print_help()
        return 2
    if args.cmd == "gui":
        from windows_registry.gui import run
        return run(str(args.hive) if args.hive else None)
    if not args.hive.exists():
        print(f"hive not found: {args.hive}", file=sys.stderr)
        return 2
    try:
        return {
            "dump": _cmd_dump, "key": _cmd_key,
            "search": _cmd_search, "plugin": _cmd_plugin,
        }[args.cmd](args, None)
    except HiveError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
