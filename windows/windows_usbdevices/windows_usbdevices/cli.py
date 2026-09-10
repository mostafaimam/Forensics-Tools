from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from windows_usbdevices import __version__, tracelib
from windows_usbdevices.analyze import analyze

COLUMNS = ["first_connected", "last_arrival", "last_removal", "vendor",
           "product", "revision", "serial", "serial_synthetic",
           "friendly_name", "volume_name", "vid", "pid", "container_id",
           "drive_letters", "volume_guids", "install", "setupapi_first_seen",
           "severity", "notable"]

_SEV = {"none": 0, "low": 1, "medium": 2, "high": 3}
_FSEV = {
    "device reports no unique serial": "medium",
    "connected only once": "low",
    "connected outside business hours": "medium",
    "device installed but never mounted": "low",
    "device is not on the --known-good list": "high",
}


def _severity(notable) -> str:
    top = "none"
    for n in notable:
        for k, v in _FSEV.items():
            if n.startswith(k) and _SEV[v] > _SEV[top]:
                top = v
    return top


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_usbdevices",
        description="Reconstruct removable-device history from the SYSTEM "
                    "and SOFTWARE hives (and setupapi.dev.log): USBSTOR "
                    "device instances with vendor / product / serial / "
                    "friendly name and the per-device install / "
                    "first-install / last-arrival / last-removal timestamps, "
                    "the USB VID / PID / container id, the drive letter(s) / "
                    "volume GUIDs from MountedDevices, and the friendly "
                    "volume name from Windows Portable Devices. One row per "
                    "device. Pure standard library (regf parser vendored); "
                    "read-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  windows_usbdevices E:\\   (mounted image root)\n"
                "  windows_usbdevices SYSTEM --csv usb.csv\n"
                "  windows_usbdevices E:\\ --known-good 'Kingston,SanDisk'\n"
                "  windows_usbdevices E:\\ --notable-only --min-severity "
                "medium\n"))
    p.add_argument("path", type=Path,
                   help="a mounted root, or a SYSTEM / SOFTWARE hive")
    p.add_argument("--version", action="version",
                   version=f"windows_usbdevices {__version__}")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--known-good", metavar="LIST",
                   help="comma-separated vendor / serial substrings; devices "
                        "not matching any are flagged high")
    p.add_argument("--grep", metavar="REGEX",
                   help="match vendor / product / serial / friendly name")
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
        from windows_usbdevices.gui import run_gui
        return run_gui([str(a.path)])
    if not a.path.exists():
        print(f"not found: {a.path}", file=sys.stderr)
        return 2

    ctx = tracelib.context(a, "windows_usbdevices", __version__)
    try:
        ctx.limits.check_paths([str(a.path)])
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3

    kg = {s.strip() for s in a.known_good.split(",")} if a.known_good else None
    res = analyze([str(a.path)], kg)
    for i in res.inputs:
        ctx.add_input(i)
    for e in res.errors:
        ctx.error("usb-error", e)
    if not res.have_system:
        print("no SYSTEM hive found under that path", file=sys.stderr)
        return 2
    if not res.have_software:
        ctx.partial("no-software", "no SOFTWARE hive - friendly volume names "
                    "unavailable")
    if not res.have_setupapi:
        ctx.partial("no-setupapi", "no setupapi.dev.log - relying on the "
                    "registry timestamps only")

    grep = re.compile(a.grep, re.I) if a.grep else None
    rows = []
    for d in res.devices:
        r = d.row()
        r["severity"] = _severity(d.notable)
        fc = r["first_connected"]
        if a.since and (not fc or fc[:10] < a.since):
            continue
        if a.until and (not fc or fc[:10] > a.until):
            continue
        if a.notable_only and not r["notable"]:
            continue
        if a.min_severity and _SEV[r["severity"]] < _SEV[a.min_severity]:
            continue
        if grep and not grep.search(" ".join((
                r["vendor"], r["product"], r["serial"], r["friendly_name"]))):
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
            dl = f" [{r['drive_letters']}]" if r["drive_letters"] else ""
            print(f"{r['first_connected'] or '(no time)':<21} "
                  f"{r['vendor']} {r['product']} ({r['serial']}){dl}{mark}")
            for n in r["notable"].split(";") if r["notable"] else []:
                print(f"    ! {n}")

    ctx.finish(outputs=[a.csv, a.json])
    fl = sum(1 for r in rows if r["notable"])
    print(f"windows_usbdevices: {len(res.devices)} device(s) -> {len(rows)} "
          f"shown, {fl} flagged", file=sys.stderr)
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
