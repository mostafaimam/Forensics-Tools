from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_timeline import __version__, tracelib
from windows_timeline import flags as _flags
from windows_timeline.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["start", "end", "last_modified", "activity_type", "app",
           "display_text", "content_uri", "duration_s", "clipboard_text",
           "is_local_only", "created_in_cloud", "from_operation",
           "activity_id", "severity", "source", "notable"]


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    return [q for q in p.rglob("ActivitiesCache.db") if q.is_file()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_timeline",
        description="Parse the Windows 10/11 Timeline (ActivitiesCache.db). "
                    "One row per activity: type (open-app / open-file / "
                    "in-app / clipboard / copy-paste / notification), the "
                    "resolved application (Win32 path or packaged-app id), "
                    "the display text and content URI from the Payload JSON, "
                    "the start / end / last-modified times (UTC) and the "
                    "duration. ClipboardPayload blobs are decoded to text. "
                    "ActivityOperation rows (often holding removed "
                    "activities) are included and marked. The evidence file "
                    "is copied with its WAL files first; read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_timeline ActivitiesCache.db --csv timeline.csv\n"
                "  windows_timeline E:\\  (mounted image root)\n"
                "  windows_timeline ActivitiesCache.db --type clipboard "
                "--json clip.json\n"
                "  windows_timeline ActivitiesCache.db --notable-only "
                "--min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="an ActivitiesCache.db or a mounted root")
    p.add_argument("--version", action="version",
                   version=f"windows_timeline {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--type", dest="activity_type",
                   help="only this activity type")
    p.add_argument("--app", help="regex match on the resolved app")
    p.add_argument("--grep", metavar="REGEX",
                   help="match app / display text / content URI / clipboard")
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
        from windows_timeline.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_timeline", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no ActivitiesCache.db found under that path", file=sys.stderr)
        return 2

    acts = []
    for db in dbs:
        ctx.add_input(str(db))
        try:
            acts += parse(str(db))
        except Exception as e:                    # noqa: BLE001
            ctx.error("timeline-error", f"{db}: {e}")

    app_rx = re.compile(a.app, re.I) if a.app else None
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for act in acts:
        r = act.row()
        r["severity"] = _flags.severity(act.notable)
        if a.activity_type and r["activity_type"] != a.activity_type:
            continue
        if app_rx and not app_rx.search(r["app"]):
            continue
        key_date = r["start"] or r["last_modified"] or ""
        if a.since and (not key_date or key_date[:10] < a.since):
            continue
        if a.until and (not key_date or key_date[:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["app"], r["display_text"], r["content_uri"],
                r["clipboard_text"]))):
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
            when = r["start"] or r["last_modified"] or "(no time)"
            what = r["display_text"] or r["content_uri"] or r["app"]
            out = f"{when:<21} {r['activity_type']:<18} {what}{mark}"
            print(out)
            if r["clipboard_text"]:
                print(f"    clip: {r['clipboard_text'][:120]}")
            if r["notable"]:
                print("    ! " + ", ".join(r["notable"].split(";")))

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_timeline: {len(acts)} activit(y/ies) -> {len(rows)} "
          f"shown, {fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
