from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_quarantine import __version__, tracelib
from macos_quarantine import flags as _flags
from macos_quarantine.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["timestamp", "agent_name", "agent_bundle", "data_url", "origin_url",
           "origin_title", "sender_name", "sender_address", "event_type",
           "identifier", "severity", "source", "notable"]

_NAMES = ("com.apple.LaunchServices.QuarantineEventsV2",
          "com.apple.LaunchServices.QuarantineEventsV2.db")


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    out = []
    for n in _NAMES:
        out += [q for q in p.rglob(n) if q.is_file()]
    return sorted(set(out))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_quarantine",
        description="Parse com.apple.LaunchServices.QuarantineEventsV2 (the "
                    "macOS download-provenance store). One row per event: "
                    "timestamp (Mac absolute time -> UTC), the downloading "
                    "agent (bundle id + name), the data URL (the downloaded "
                    "file), the origin URL (the page), the sender for email "
                    "attachments, and the event type. Flags executables / "
                    "installers / scripts / archives from the internet, "
                    "IP-literal / punycode hosts, and downloads via a "
                    "command-line agent. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_quarantine QuarantineEventsV2 --csv q.csv\n"
                "  macos_quarantine /mnt/mac  (a mounted macOS volume)\n"
                "  macos_quarantine QuarantineEventsV2 --notable-only "
                "--min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="a QuarantineEventsV2 db or a mounted macOS volume")
    p.add_argument("--version", action="version",
                   version=f"macos_quarantine {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--agent", help="regex match on the agent name / bundle")
    p.add_argument("--grep", metavar="REGEX", help="match the data / origin "
                   "URL")
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
        from macos_quarantine.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_quarantine", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    dbs = _discover(a.path)
    if not dbs:
        print("no QuarantineEventsV2 database found", file=sys.stderr)
        return 2

    events = []
    for db in dbs:
        ctx.add_input(str(db))
        try:
            events += parse(str(db))
        except Exception as e:                    # noqa: BLE001
            ctx.error("quarantine-error", f"{db}: {e}")

    agent_rx = re.compile(a.agent, re.I) if a.agent else None
    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for e in events:
        r = e.row()
        r["severity"] = _flags.severity(e.notable)
        if agent_rx and not agent_rx.search(f"{r['agent_name']} "
                                            f"{r['agent_bundle']}"):
            continue
        if a.since and (not r["timestamp"] or r["timestamp"][:10] < a.since):
            continue
        if a.until and (not r["timestamp"] or r["timestamp"][:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(f"{r['data_url']} {r['origin_url']}"):
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
            print(f"{r['timestamp'] or '(no time)':<21} "
                  f"{r['agent_name'] or '?':<14} {r['data_url']}{mark}")
            if r["origin_url"]:
                print(f"    from: {r['origin_url']}")
            if r["notable"]:
                print("    ! " + ", ".join(r["notable"].split(";")))

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_quarantine: {len(events)} event(s) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
