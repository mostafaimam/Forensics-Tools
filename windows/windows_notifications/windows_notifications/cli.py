from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_notifications import __version__, tracelib
from windows_notifications import flags as _flags
from windows_notifications.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["arrival", "expiry", "app", "type", "handler_type", "text", "tag",
           "group", "payload_type", "boot_id", "severity", "source", "notable"]


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    return [q for q in p.rglob("wpndatabase.db") if q.is_file()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_notifications",
        description="Parse wpndatabase.db (the Windows toast / tile "
                    "notification history). Joins Notification to "
                    "NotificationHandler so every notification is attributed "
                    "to an application (AUMID or exe id). One row per "
                    "notification: app, type (toast / tile / badge / raw), "
                    "arrival + expiry times (FILETIME -> UTC), tag / group, "
                    "and the notification text extracted from the payload "
                    "XML. Evidence copied with its WAL files first; "
                    "read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_notifications wpndatabase.db --csv notif.csv\n"
                "  windows_notifications E:\\  (mounted image root)\n"
                "  windows_notifications wpndatabase.db --type raw "
                "--json raw.json\n"
                "  windows_notifications wpndatabase.db --grep 'http|code'\n"))
    p.add_argument("path", type=Path,
                   help="a wpndatabase.db or a mounted root")
    p.add_argument("--version", action="version",
                   version=f"windows_notifications {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", dest="ntype",
                   help="toast / tile / badge / raw")
    p.add_argument("--app", help="regex match on the app id")
    p.add_argument("--grep", metavar="REGEX", help="match the notification "
                   "text")
    p.add_argument("--since", metavar="YYYY-MM-DD")
    p.add_argument("--until", metavar="YYYY-MM-DD")
    p.add_argument("--notable-only", action="store_true")
    p.add_argument("--min-severity", choices=["low", "medium", "high"])
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from windows_notifications.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_notifications", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no wpndatabase.db found under that path", file=sys.stderr)
        return 2

    notes = []
    for db in dbs:
        ctx.add_input(str(db))
        try:
            notes += parse(str(db))
        except Exception as e:                    # noqa: BLE001
            ctx.error("notif-error", f"{db}: {e}")

    app_rx = re.compile(a.app, re.I) if a.app else None
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for n in notes:
        r = n.row()
        r["severity"] = _flags.severity(n.notable)
        if a.ntype and r["type"] != a.ntype:
            continue
        if app_rx and not app_rx.search(r["app"]):
            continue
        if a.since and (not r["arrival"] or r["arrival"][:10] < a.since):
            continue
        if a.until and (not r["arrival"] or r["arrival"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(r["text"]):
            continue
        rows.append(r)

    if a.csv:
        tracelib.write_csv(rows, a.csv, COLUMNS, ctx,
                           confidence="high", tz="utc-native")
    if a.json:
        tracelib.write_json(rows, a.json, ctx,
                            confidence="high", tz="utc-native")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = f"  [{r['severity']}]" if r["severity"] != "none" else ""
            out = f"{r['arrival'] or '(no time)':<28} {r['type']:<6} " \
                  f"{r['app']}{mark}"
            print(out)
            if r["text"]:
                print(f"    {r['text'][:150]}")
            if r["notable"]:
                print("    ! " + ", ".join(r["notable"].split(";")))

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_notifications: {len(notes)} notification(s) -> "
          f"{len(rows)} shown, {fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
