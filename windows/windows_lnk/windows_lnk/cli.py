from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path

from windows_lnk import __version__
from windows_lnk.lnk import LnkError, iso, parse

COLUMNS = [
    "source_file", "target_path", "target_created_utc", "target_accessed_utc",
    "target_modified_utc", "target_size", "file_attributes", "arguments",
    "working_dir", "relative_path", "name", "icon_location", "show_command",
    "drive_type", "drive_serial", "volume_label", "network_share",
    "machine_id", "mac_address", "droid_object_created_utc",
    "known_folder", "shell_item_mft_entry", "flags", "warnings",
]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _row(lnk, source: str) -> dict:
    t = lnk.tracker
    mft = ""
    for i in lnk.target_items:
        if i.get("mft_entry"):
            mft = f"{i['mft_entry']}-{i.get('mft_sequence', 0)}"
    return {
        "source_file": source,
        "target_path": lnk.target_path,
        "target_created_utc": iso(lnk.target_created),
        "target_accessed_utc": iso(lnk.target_accessed),
        "target_modified_utc": iso(lnk.target_modified),
        "target_size": lnk.target_size,
        "file_attributes": " | ".join(lnk.file_attributes),
        "arguments": lnk.arguments,
        "working_dir": lnk.working_dir,
        "relative_path": lnk.relative_path,
        "name": lnk.name,
        "icon_location": lnk.icon_location,
        "show_command": lnk.show_command,
        "drive_type": lnk.drive_type,
        "drive_serial": lnk.drive_serial,
        "volume_label": lnk.volume_label,
        "network_share": lnk.network_share,
        "machine_id": t.machine_id if t else "",
        "mac_address": t.object_mac_address if t else "",
        "droid_object_created_utc": iso(t.object_created_utc) if t else "",
        "known_folder": lnk.known_folder,
        "shell_item_mft_entry": mft,
        "flags": " | ".join(lnk.flag_names),
        "warnings": " ; ".join(lnk.warnings),
    }


def _json_obj(lnk, source: str) -> dict:
    o = _row(lnk, source)
    o["shell_items"] = lnk.target_items
    o["extra_blocks"] = lnk.extra_blocks
    if lnk.tracker:
        o["tracker"] = {
            "machine_id": lnk.tracker.machine_id,
            "droid_volume": lnk.tracker.droid_volume,
            "droid_object": lnk.tracker.droid_object,
            "droid_birth_object": lnk.tracker.droid_birth_object,
        }
    return o


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="windows_lnk",
        description="Parse Windows Shell Link (.lnk) files: target path and MAC "
                    "times, arguments, drive / volume, the creating machine's "
                    "name and MAC address, and $MFT references from shell items.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  windows_lnk *.lnk --csv lnk.csv\n"
            "  windows_lnk \"%APPDATA%\\Microsoft\\Windows\\Recent\" --csv recent.csv\n"
            "  windows_lnk shortcut.lnk --json shortcut.json\n"
        ),
    )
    p.add_argument("inputs", nargs="+", type=Path, metavar="LNK")
    p.add_argument("--gui", action="store_true", help="open the graphical viewer")
    p.add_argument("--version", action="version",
                   version=f"windows_lnk {__version__}")
    p.add_argument("--csv", type=Path)
    p.add_argument("--json", type=Path)
    p.add_argument("--no-recurse", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    return p


def _expand(inputs, recurse: bool):
    for raw in inputs:
        p = Path(raw)
        if p.is_dir():
            it = p.rglob("*.lnk") if recurse else p.glob("*.lnk")
            yield from sorted(it)
        else:
            yield p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.gui:
        from windows_lnk.gui import run
        return run([str(p) for p in args.inputs])
    files = list(_expand(args.inputs, not args.no_recurse))
    if not files:
        print("error: no .lnk files found", file=sys.stderr)
        return 2

    parsed = []
    errors = 0
    for f in files:
        try:
            parsed.append((parse(f.read_bytes(), str(f)), str(f)))
        except (LnkError, OSError) as e:
            errors += 1
            print(f"! {f}: {e}", file=sys.stderr)

    if args.csv:
        with args.csv.open("w", encoding="utf-8-sig", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLUMNS, dialect="excel",
                               extrasaction="ignore")
            w.writeheader()
            for lnk, src in parsed:
                w.writerow({k: _san(v) for k, v in _row(lnk, src).items()})
    if args.json:
        args.json.write_text(
            json.dumps([_json_obj(lnk, src) for lnk, src in parsed],
                       indent=2, default=str), encoding="utf-8")
    if not args.quiet and not (args.csv or args.json):
        print(_render(parsed))

    print(f"windows_lnk {__version__}: {len(parsed)} parsed, {errors} error(s)",
          file=sys.stderr)
    return 1 if errors and not parsed else 0


def _render(parsed, limit: int = 100) -> str:
    out = io.StringIO()
    for lnk, src in parsed[:limit]:
        r = _row(lnk, src)
        out.write(f"# {Path(src).name}\n")
        for k in ("target_path", "target_modified_utc", "arguments",
                  "working_dir", "drive_serial", "volume_label",
                  "machine_id", "mac_address", "known_folder",
                  "shell_item_mft_entry"):
            if r[k]:
                out.write(f"  {k:<24} {r[k]}\n")
        out.write("\n")
    return out.getvalue()


if __name__ == "__main__":
    raise SystemExit(main())
