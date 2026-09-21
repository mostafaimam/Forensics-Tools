from __future__ import annotations

import sys
import argparse
from pathlib import Path

from mounting_veracrypt import __version__, tracelib
from mounting_veracrypt.header import HeaderError, try_password
from mounting_veracrypt.sectors import decrypt_range


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_veracrypt",
        description="Unlock a VeraCrypt/TrueCrypt volume with a supplied "
                    "password: PBKDF2 header-key derivation, AES-XTS "
                    "header decryption and CRC/magic validation, master "
                    "-key extraction, sector decryption. v0.1 supports "
                    "single-cipher AES-256-XTS volumes only (no Serpent/ "
                    "Twofish/cascades), password-only (no PIM/keyfiles).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  mounting_veracrypt info volume.hc --password 'Hunter2'\n"
                "  mounting_veracrypt decrypt volume.hc --password "
                "'Hunter2' --length 4096 -o out.bin\n"))
    p.add_argument("--version", action="version",
                   version=f"mounting_veracrypt {__version__}")
    s = p.add_subparsers(dest="cmd")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("image", type=Path)
    common.add_argument("--password", required=True)
    common.add_argument("--hash", default="sha512",
                        choices=["sha512", "sha256"])
    common.add_argument("--iterations", type=int, default=500_000,
                        help="PBKDF2 iteration count - NOT stored in the "
                        "volume; must match how it was created (default: "
                        "VeraCrypt's historical default for non-system "
                        "SHA-512 volumes). Override if unlock fails.")

    info = s.add_parser("info", parents=[common],
                        help="decrypt and report the header, no sector "
                        "decryption")
    info.add_argument("--json", type=Path)

    dec = s.add_parser("decrypt", parents=[common],
                       help="unlock, then decrypt a sector range")
    dec.add_argument("--data-offset", type=lambda x: int(x, 0),
                     help="default: the header's own master-key-scope "
                     "offset")
    dec.add_argument("--length", type=lambda x: int(x, 0), required=True)
    dec.add_argument("-o", "--out", type=Path, required=True)
    tracelib.add_arguments(p)
    return p


def _unlock(a):
    return try_password(str(a.image), a.password, hash_name=a.hash,
                        iterations=a.iterations)


def _cmd_info(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_veracrypt", __version__)
    ctx.add_input(str(a.image))
    try:
        hdr = _unlock(a)
    except HeaderError as e:
        print(f"unlock failed: {e}", file=sys.stderr)
        return 1
    print(f"magic               {hdr.magic.decode()}")
    print(f"header version      {hdr.version}")
    print(f"hidden volume       {hdr.is_hidden}")
    print(f"volume size         {hdr.volume_size}")
    print(f"master-key offset   {hdr.master_key_scope_offset:#x}")
    print(f"encrypted area size {hdr.encrypted_area_size}")
    print(f"sector size         {hdr.effective_sector_size}")
    print(f"flags               {hdr.flags:#x}")
    if a.json:
        import json
        a.json.write_text(json.dumps({
            "magic": hdr.magic.decode(), "version": hdr.version,
            "is_hidden": hdr.is_hidden, "volume_size": hdr.volume_size,
            "master_key_scope_offset": hdr.master_key_scope_offset,
            "encrypted_area_size": hdr.encrypted_area_size,
            "sector_size": hdr.effective_sector_size, "flags": hdr.flags,
        }, indent=2))
    ctx.finish(outputs=[a.json])
    return 0


def _cmd_decrypt(a) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "mounting_veracrypt", __version__)
    ctx.add_input(str(a.image))
    try:
        hdr = _unlock(a)
    except HeaderError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    offset = (a.data_offset if a.data_offset is not None
             else hdr.master_key_scope_offset)
    try:
        plain = decrypt_range(hdr, str(a.image), offset, a.length)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    a.out.write_bytes(plain)
    ctx.finish(outputs=[a.out])
    print(f"mounting_veracrypt: wrote {len(plain)} decrypted byte(s) to "
         f"{a.out}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    a = p.parse_args(argv)
    if a.cmd == "info":
        return _cmd_info(a)
    if a.cmd == "decrypt":
        return _cmd_decrypt(a)
    p.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
