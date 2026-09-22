from __future__ import annotations

import sys
import argparse
from pathlib import Path

from mounting_fvde import __version__, tracelib
from mounting_fvde.collect import COLUMNS, collect
from mounting_fvde.unlock import UnlockError, decrypt_and_verify, \
    derive_vek, xts_keys_from_vek


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mounting_fvde",
        description="Best-effort legacy CoreStorage FileVault2 volume "
                    "unlock. The crypto (PBKDF2, RFC 3394 key unwrap, "
                    "AES-XTS-128) is exact and standard; the surrounding "
                    "EncryptedRoot.plist.wipekey byte layout is "
                    "reverse-engineered-only and NOT independently "
                    "verified - see the README's Confidence & "
                    "Validation section before relying on this. APFS "
                    "-container FileVault is out of scope for v0.1.")
    p.add_argument("--version", action="version",
                   version=f"mounting_fvde {__version__}")
    p.add_argument("--gui", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    info = sub.add_parser("info", help="list candidate key-wrap blobs "
                          "found in a plist or image file")
    info.add_argument("target", type=Path)
    info.add_argument("--csv", type=Path)
    info.add_argument("--json", type=Path)

    unlock = sub.add_parser("unlock", help="derive the volume encryption "
                            "key from examiner-supplied parameters")
    unlock.add_argument("--password", required=True)
    unlock.add_argument("--salt-hex", required=True)
    unlock.add_argument("--iterations", type=int, required=True)
    unlock.add_argument("--wrapped-hex", required=True)

    decrypt = sub.add_parser("decrypt", help="unlock, then AES-XTS "
                             "-decrypt a block and verify via HFS+ magic")
    decrypt.add_argument("image", type=Path)
    decrypt.add_argument("--password", required=True)
    decrypt.add_argument("--salt-hex", required=True)
    decrypt.add_argument("--iterations", type=int, required=True)
    decrypt.add_argument("--wrapped-hex", required=True)
    decrypt.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    decrypt.add_argument("--length", type=lambda x: int(x, 0),
                         default=4096)
    decrypt.add_argument("-o", "--out", type=Path, required=True)

    for sp in (info, unlock, decrypt):
        tracelib.add_arguments(sp)
    return p


def _run_info(a, ctx) -> int:
    if not a.target.exists():
        print(f"not found: {a.target}", file=sys.stderr)
        return 2
    ctx.add_input(str(a.target))
    res = collect(str(a.target))
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    for r in res.rows:
        print(f"offset={r['plist_offset']:<8} {r['path']:<30} "
             f"len={r['length']:<4} {r['hex_prefix']}")
    if a.csv:
        tracelib.write_csv(res.rows, a.csv, COLUMNS, ctx,
                           confidence="low", tz="n/a")
    if a.json:
        tracelib.write_json(res.rows, a.json, ctx,
                            confidence="low", tz="n/a")
    ctx.finish(outputs=[a.csv, a.json])
    return 0 if res.rows else 1


def _run_unlock(a, ctx) -> int:
    try:
        vek = derive_vek(a.password, bytes.fromhex(a.salt_hex),
                         a.iterations, bytes.fromhex(a.wrapped_hex))
    except UnlockError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"vek={vek.hex()}")
    return 0


def _run_decrypt(a, ctx) -> int:
    if not a.image.exists():
        print(f"not found: {a.image}", file=sys.stderr)
        return 2
    ctx.add_input(str(a.image))
    try:
        vek = derive_vek(a.password, bytes.fromhex(a.salt_hex),
                         a.iterations, bytes.fromhex(a.wrapped_hex))
        key1, key2 = xts_keys_from_vek(vek)
        with open(a.image, "rb") as fh:
            fh.seek(a.offset)
            ciphertext = fh.read(a.length)
        plaintext = decrypt_and_verify(key1, key2, ciphertext,
                                       sector_index=a.offset // 512)
    except UnlockError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    a.out.write_bytes(plaintext)
    ctx.finish(outputs=[a.out])
    print(f"decrypted {len(plaintext)} byte(s) to {a.out} - HFS+ magic "
         f"verified", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.gui:
        from mounting_fvde.gui import run_gui
        return run_gui()
    if not a.cmd:
        build_parser().error("a subcommand (info/unlock/decrypt) or "
                            "--gui is required")

    ctx = tracelib.context(a, "mounting_fvde", __version__)
    try:
        if a.cmd == "info":
            return _run_info(a, ctx)
        if a.cmd == "unlock":
            return _run_unlock(a, ctx)
        if a.cmd == "decrypt":
            return _run_decrypt(a, ctx)
    except tracelib.LimitExceeded as e:
        print(f"resource limit: {e}", file=sys.stderr)
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
