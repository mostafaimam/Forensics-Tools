from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mounting_luks import __version__, tracelib
from mounting_luks.luks1 import LuksError, luks2_info, parse
from mounting_luks.sectors import decrypt_range
from mounting_luks.unlock import UnlockError, unlock


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_luks",
        description="Unlock a LUKS1 volume with a supplied passphrase. "
                    "'info' reports the header (cipher, key slots) with no "
                    "passphrase needed; 'unlock' derives and verifies the "
                    "master key against a key slot; 'decrypt' unlocks then "
                    "decrypts a sector range. LUKS2 headers are detected "
                    "and reported but not unlockable (Argon2 KDF).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mounting_luks info volume.img\n"
                "  mounting_luks unlock volume.img --passphrase 'Hunter2'\n"
                "  mounting_luks decrypt volume.img --passphrase 'Hunter2' "
                "--data-offset 0x100000 --length 4096 -o out.bin\n"))
    p.add_argument("--version", action="version",
                   version=f"mounting_luks {__version__}")
    s = p.add_subparsers(dest="cmd")

    info = s.add_parser("info", help="report the header, no passphrase")
    info.add_argument("image", type=Path)
    info.add_argument("--json", type=Path)
    info.add_argument("--csv", type=Path)

    unlk = s.add_parser("unlock", help="derive and verify the master key")
    unlk.add_argument("image", type=Path)
    unlk.add_argument("--passphrase", required=True)
    unlk.add_argument("--json", type=Path)

    dec = s.add_parser("decrypt", help="unlock, then decrypt a sector range")
    dec.add_argument("image", type=Path)
    dec.add_argument("--passphrase", required=True)
    dec.add_argument("--data-offset", type=lambda x: int(x, 0),
                     help="default: the header's own payload offset")
    dec.add_argument("--length", type=lambda x: int(x, 0), required=True)
    dec.add_argument("--sector-size", type=int, default=512)
    dec.add_argument("-o", "--out", type=Path, required=True)
    tracelib.add_arguments(p)
    return p


def _load_header(image: Path):
    data = image.read_bytes()
    try:
        return parse(data), data
    except LuksError as e:
        if "LUKS2" in str(e):
            print(f"info: {e}", file=sys.stderr)
            print(json.dumps(luks2_info(data), indent=2))
            return None, data
        raise


def _cmd_info(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_luks", __version__)
    ctx.add_input(str(a.image))
    try:
        hdr, _data = _load_header(a.image)
    except LuksError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if hdr is None:
        return 0
    print(f"uuid           {hdr.uuid}")
    print(f"cipher         {hdr.cipher_name}-{hdr.cipher_mode}")
    print(f"hash           {hdr.hash_spec}")
    print(f"key bytes      {hdr.key_bytes}")
    print(f"payload offset {hdr.payload_byte_offset:#x}")
    rows = []
    for s in hdr.slots:
        print(f"  slot {s.index}: {'ACTIVE' if s.active else 'inactive'}  "
              f"iterations={s.iterations}  stripes={s.stripes}")
        rows.append({"slot": s.index, "active": s.active,
                    "iterations": s.iterations, "stripes": s.stripes})
    if a.csv:
        tracelib.write_csv(rows, a.csv, ["slot", "active", "iterations",
                                        "stripes"], ctx,
                           confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx, confidence="high", tz="n/a")
    ctx.finish(outputs=[a.csv, a.json])
    return 0


def _cmd_unlock(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_luks", __version__)
    ctx.add_input(str(a.image))
    try:
        hdr, _data = _load_header(a.image)
        if hdr is None:
            return 1
        u = unlock(hdr, str(a.image), a.passphrase)
    except (LuksError, UnlockError) as e:
        print(f"unlock failed: {e}", file=sys.stderr)
        return 1
    print(f"unlocked via slot {u.slot_index}")
    print(f"master key  {u.master_key.hex()}")
    if a.json:
        a.json.write_text(json.dumps(
            {"slot": u.slot_index, "master_key_hex": u.master_key.hex()},
            indent=2))
    ctx.finish(outputs=[a.json])
    return 0


def _cmd_decrypt(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_luks", __version__)
    ctx.add_input(str(a.image))
    try:
        hdr, _data = _load_header(a.image)
        if hdr is None:
            return 1
        u = unlock(hdr, str(a.image), a.passphrase)
    except (LuksError, UnlockError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    offset = a.data_offset if a.data_offset is not None else \
        hdr.payload_byte_offset
    try:
        plain = decrypt_range(hdr, u.master_key, str(a.image), offset,
                              a.length, sector_size=a.sector_size)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    a.out.write_bytes(plain)
    ctx.finish(outputs=[a.out])
    print(f"mounting_luks: wrote {len(plain)} decrypted byte(s) to {a.out}",
          file=sys.stderr)
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
