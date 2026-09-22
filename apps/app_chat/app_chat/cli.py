from __future__ import annotations

import sys
import argparse
from pathlib import Path

from app_chat import __version__, tracelib
from app_chat.collect import COLUMNS, collect


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="app_chat",
        description="Recover chat messages from a desktop app's local "
                    "cache. Slack and Discord messages are recognised by "
                    "their documented public Web API JSON shape wherever "
                    "they appear in the app's LevelDB (Local Storage/"
                    "IndexedDB) cache - the same from-scratch LevelDB "
                    "reader browser_localstorage uses, so overwritten/"
                    "deleted entries are recovered too. Classic Microsoft "
                    "Teams data is located and carved as raw text, not "
                    "decoded into individual messages. Signal, WhatsApp "
                    "and Telegram Desktop are out of scope for v0.1.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  app_chat \"%APPDATA%\\Slack\"\n"
                "  app_chat ~/AppData/Roaming --app slack,discord --csv "
                "messages.csv\n"))
    p.add_argument("target", nargs="?", type=str,
                   help="a folder to search (an app's own data "
                   "directory, or a broader profile root)")
    p.add_argument("--version", action="version",
                   version=f"app_chat {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--app", help="comma list of slack,discord,teams "
                   "(default: all)")
    p.add_argument("--deleted-only", action="store_true")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from app_chat.gui import run_gui
        return run_gui([a.target] if a.target else [])
    if not a.target:
        build_parser().error("a target path is required (or --gui)")

    tp = Path(a.target)
    if not tp.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2

    apps = [x.strip() for x in a.app.split(",") if x.strip()] if a.app \
        else None

    ctx = tracelib.context(a, "app_chat", __version__)
    try:
        ctx.limits.check_paths([a.target])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    ctx.add_input(a.target)

    res = collect(a.target, apps=apps)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)

    rows = res.rows
    if a.deleted_only:
        rows = [r for r in rows if r["deleted"]]

    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            tag = " [deleted]" if r["deleted"] else ""
            if r["kind"] == "message":
                print(f"{r['app']:<8} {r['timestamp']}  {r['sender']}: "
                     f"{r['text'][:100]}{tag}")
            else:
                print(f"{r['app']:<8} (raw) {r['text'][:100]}{tag}")

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="medium", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="medium", tz="utc-native")

    ctx.finish(outputs=[a.csv, a.json])
    print(f"app_chat: {len(rows)} row(s)", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
