from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mounting_bitlocker import __version__, tracelib
from mounting_bitlocker.fve import FveError, parse
from mounting_bitlocker.sectors import decrypt_range
from mounting_bitlocker.unlock import UnlockError, unlock_with_recovery_password


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_bitlocker",
        description="Unlock a BitLocker volume with a supplied recovery "
                    "password. 'info' reports the protector inventory with "
                    "no key needed; 'unlock' derives the VMK and FVEK and "
                    "verifies the password; 'decrypt' unwraps the keys and "
                    "decrypts a sector range to a file. Nothing is brute "
                    "forced.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mounting_bitlocker info volume.img\n"
                "  mounting_bitlocker unlock volume.img --recovery-password "
                "'123456-123456-123456-123456-123456-123456-123456-123456'\n"
                "  mounting_bitlocker decrypt volume.img --recovery-password "
                "'...' --offset 0 --length 4096 -o decrypted.bin\n"))
    p.add_argument("--version", action="version",
                   version=f"mounting_bitlocker {__version__}")
    s = p.add_subparsers(dest="cmd")

    info = s.add_parser("info", help="report protectors, no key needed")
    info.add_argument("image", type=Path)
    info.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                      help="byte offset of the FVE metadata block")
    info.add_argument("--json", type=Path)
    info.add_argument("--csv", type=Path)

    unlk = s.add_parser("unlock", help="derive and verify the VMK / FVEK")
    unlk.add_argument("image", type=Path)
    unlk.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    unlk.add_argument("--recovery-password", required=True)
    unlk.add_argument("--iterations", type=int, default=None,
                      help="override the key-stretch iteration count "
                           "(testing only; default is the real 0x100000)")
    unlk.add_argument("--json", type=Path)

    dec = s.add_parser("decrypt", help="unlock, then decrypt a sector range")
    dec.add_argument("image", type=Path)
    dec.add_argument("--offset", type=lambda x: int(x, 0), default=0,
                     help="byte offset of the FVE metadata block")
    dec.add_argument("--recovery-password", required=True)
    dec.add_argument("--iterations", type=int, default=None,
                     help="override the key-stretch iteration count "
                          "(testing only; default is the real 0x100000)")
    dec.add_argument("--data-offset", type=lambda x: int(x, 0), required=True,
                     help="byte offset of the sector range to decrypt "
                          "(sector-aligned)")
    dec.add_argument("--length", type=lambda x: int(x, 0), required=True)
    dec.add_argument("--sector-size", type=int, default=512)
    dec.add_argument("-o", "--out", type=Path, required=True)
    tracelib.add_arguments(p)
    return p


def _cmd_info(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_bitlocker", __version__)
    ctx.add_input(str(a.image))
    data = a.image.read_bytes()[a.offset:]
    try:
        fve = parse(data)
    except FveError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    rows = []
    for p in fve.protectors:
        rows.append({"guid": p.guid, "type": p.protector_type,
                    "last_modified": p.last_modified,
                    "has_salt": bool(p.salt), "has_key": bool(p.wrapped_key)})
    print(f"volume_guid   {fve.volume_guid}")
    print(f"method        {fve.method}")
    print(f"created       {fve.creation_time}")
    print(f"fvek present  {bool(fve.fvek_wrapped)}")
    for r in rows:
        print(f"  protector {r['guid']}  {r['type']}  "
              f"modified {r['last_modified']}")
    if a.csv:
        tracelib.write_csv(rows, a.csv,
                           ["guid", "type", "last_modified", "has_salt",
                            "has_key"], ctx, confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx, confidence="high", tz="n/a")
    ctx.finish(outputs=[a.csv, a.json])
    return 0 if fve.protectors else 1


def _cmd_unlock(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_bitlocker", __version__)
    ctx.add_input(str(a.image))
    data = a.image.read_bytes()[a.offset:]
    try:
        fve = parse(data)
    except FveError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    kwargs = {} if a.iterations is None else {"iterations": a.iterations}
    try:
        u = unlock_with_recovery_password(fve, a.recovery_password, **kwargs)
    except UnlockError as e:
        print(f"unlock failed: {e}", file=sys.stderr)
        return 1
    print(f"unlocked with protector {u.protector_guid}")
    print(f"method  {u.method}")
    print(f"VMK     {u.vmk.hex()}")
    print(f"FVEK    {u.fvek.hex()}")
    if a.json:
        a.json.write_text(json.dumps({
            "protector_guid": u.protector_guid, "method": u.method,
            "vmk_hex": u.vmk.hex(), "fvek_hex": u.fvek.hex()}, indent=2))
    ctx.finish(outputs=[a.json])
    return 0


def _cmd_decrypt(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_bitlocker", __version__)
    ctx.add_input(str(a.image))
    data = a.image.read_bytes()[a.offset:]
    try:
        fve = parse(data)
        kwargs = {} if a.iterations is None else {"iterations": a.iterations}
        u = unlock_with_recovery_password(fve, a.recovery_password, **kwargs)
    except (FveError, UnlockError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    try:
        plain = decrypt_range(u, str(a.image), a.data_offset, a.length,
                              sector_size=a.sector_size)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    a.out.write_bytes(plain)
    ctx.finish(outputs=[a.out])
    print(f"mounting_bitlocker: wrote {len(plain)} decrypted byte(s) to "
          f"{a.out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "info":
        return _cmd_info(a)
    if a.cmd == "unlock":
        return _cmd_unlock(a)
    if a.cmd == "decrypt":
        return _cmd_decrypt(a)
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
