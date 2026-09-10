from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from macos_bt import __version__, tracelib
from macos_bt import flags as _flags
from macos_bt.parse import parse

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
COLUMNS = ["mac", "name", "is_paired", "is_hid", "device_type",
           "device_minor", "manufacturer", "vendor_id", "product_id",
           "class_of_device", "battery", "last_name_update",
           "last_inquiry_update", "last_services_update", "services",
           "severity", "source", "notable"]

_NAMES = ("com.apple.Bluetooth.plist",)


def _discover(p: Path) -> list[Path]:
    if p.is_file():
        return [p]
    out = []
    for n in _NAMES:
        out += [q for q in p.rglob(n) if q.is_file()]
    out += [q for q in p.rglob("com.apple.Bluetooth.*.plist") if q.is_file()]
    return sorted(set(out))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="macos_bt",
        description="Parse com.apple.Bluetooth.plist: the DeviceCache (every "
                    "device the Mac has seen - name, vendor / product id, "
                    "manufacturer company id, class of device decoded to a "
                    "type, battery, and the LastNameUpdate / "
                    "LastInquiryUpdate / LastServicesUpdate timestamps in "
                    "UTC) joined with PairedDevices and HIDDevices. Flags "
                    "paired input devices (keystroke injection), paired "
                    "audio-input devices, generic names and one-off "
                    "inquiries. Read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  macos_bt com.apple.Bluetooth.plist --csv bt.csv\n"
                "  macos_bt /Volumes/Macintosh\\ HD --paired-only\n"
                "  macos_bt com.apple.Bluetooth.plist --type peripheral "
                "--json hid.json\n"
                "  macos_bt /mnt/mac --notable-only --min-severity high\n"))
    p.add_argument("path", type=Path,
                   help="a com.apple.Bluetooth.plist or a mounted macOS "
                        "volume")
    p.add_argument("--version", action="version",
                   version=f"macos_bt {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--paired-only", action="store_true")
    p.add_argument("--hid-only", action="store_true")
    p.add_argument("--type", dest="device_type",
                   help="computer / phone / audio/video / peripheral / ...")
    p.add_argument("--grep", metavar="REGEX", help="match name / MAC / "
                   "manufacturer")
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
        from macos_bt.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "macos_bt", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    plists = _discover(a.path)
    if not plists:
        print("no com.apple.Bluetooth.plist found", file=sys.stderr)
        return 2

    devs = []
    seen_mac: set = set()
    for pl in plists:
        ctx.add_input(str(pl))
        try:
            for d in parse(pl.read_bytes(), str(pl)):
                if d.mac in seen_mac:
                    continue
                seen_mac.add(d.mac)
                devs.append(d)
        except Exception as e:                    # noqa: BLE001
            ctx.error("bt-error", f"{pl}: {e}")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for d in devs:
        r = d.row()
        r["severity"] = _flags.severity(d.notable)
        if a.paired_only and r["is_paired"] != "yes":
            continue
        if a.hid_only and r["is_hid"] != "yes":
            continue
        if a.device_type and r["device_type"] != a.device_type:
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((r["name"], r["mac"],
                                              r["manufacturer"]))):
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
            tags = " ".join(t for t in (
                "paired" if r["is_paired"] else "",
                "HID" if r["is_hid"] else "") if t)
            dt = f"{r['device_type']}/{r['device_minor']}".rstrip("/")
            print(f"{r['mac']}  {r['name'] or '(no name)':<24} {dt:<20} "
                  f"{r['manufacturer']:<14} {tags}{mark}")
            when = r["last_inquiry_update"] or r["last_name_update"]
            if when:
                print(f"    last seen: {when}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"macos_bt: {len(devs)} device(s) -> {len(rows)} shown, "
          f"{fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
