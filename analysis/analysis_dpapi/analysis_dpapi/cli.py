from __future__ import annotations

import argparse
import binascii
import hashlib
import sys
from pathlib import Path

from analysis_dpapi import __version__, tracelib
from analysis_dpapi.blob import decrypt_blob, parse_blob
from analysis_dpapi.collect import classify, run
from analysis_dpapi.masterkey import decrypt_masterkey, parse_file


def _hexarg(s):
    return binascii.unhexlify(s.replace(" ", "")) if s else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analysis_dpapi",
        description="Decrypt Windows DPAPI master keys and data blobs with a "
                    "supplied secret (password + SID, or a SHA-1 password "
                    "hash). IR-scoped: nothing is brute forced.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  analysis_dpapi masterkey 0123abcd-... --sid S-1-5-21-... "
                "--password 'Hunter2'\n"
                "  analysis_dpapi blob cookie.blob --mk-file MK --sid S-... "
                "--password P\n"
                "  analysis_dpapi scan 'Protect/S-1-5-21-...' --blobs Vault "
                "--sid S-... --password P --json out.json\n"))
    p.add_argument("--version", action="version",
                   version=f"analysis_dpapi {__version__}")
    s = p.add_subparsers(dest="cmd")

    mk = s.add_parser("masterkey", help="decrypt a master-key file")
    mk.add_argument("file", type=Path)
    mk.add_argument("--sid", required=True)
    g = mk.add_mutually_exclusive_group(required=True)
    g.add_argument("--password")
    g.add_argument("--sha1", help="pre-computed SHA-1 of the UTF-16 password")
    mk.add_argument("--json", type=Path)

    bl = s.add_parser("blob", help="decrypt a DPAPI data blob")
    bl.add_argument("file", type=Path)
    bl.add_argument("--masterkey", help="64-byte master key as hex")
    bl.add_argument("--mk-file", type=Path,
                    help="a master-key file to decrypt first")
    bl.add_argument("--sid")
    bl.add_argument("--password")
    bl.add_argument("--sha1")
    bl.add_argument("--entropy", help="optional entropy as hex")
    bl.add_argument("--json", type=Path)

    scn = s.add_parser("scan", help="Protect dir + blob folder")
    scn.add_argument("protect", type=Path, help="a Protect\\<SID> directory")
    scn.add_argument("--blobs", type=Path, action="append", default=[],
                     metavar="PATH")
    scn.add_argument("--sid", required=True)
    scn.add_argument("--password")
    scn.add_argument("--sha1")
    scn.add_argument("--entropy")
    scn.add_argument("--csv", type=Path)
    scn.add_argument("--json", type=Path)
    scn.add_argument("-q", "--quiet", action="store_true")
    tracelib.add_arguments(p)
    return p


def _pwdhash(a):
    if getattr(a, "sha1", None):
        return _hexarg(a.sha1)
    return None


def _cmd_masterkey(a) -> int:
    if not a.file.exists():
        print(f"not found: {a.file}", file=sys.stderr)
        return 2
    mkf = parse_file(a.file.read_bytes())
    if not mkf.masterkey:
        print("no master-key blob in file", file=sys.stderr)
        return 1
    try:
        key, scheme = decrypt_masterkey(mkf.masterkey, a.sid,
                                        password=a.password,
                                        pwdhash=_pwdhash(a))
    except ValueError as e:
        print(f"decryption failed: {e}", file=sys.stderr)
        return 1
    out = {"guid": mkf.guid, "scheme": scheme, "masterkey": key.hex()}
    if a.json:
        a.json.write_text(__import__("json").dumps(out, indent=2))
    else:
        print(f"guid      {mkf.guid}")
        print(f"scheme    {scheme}")
        print(f"masterkey {key.hex()}")
    return 0


def _resolve_mk(a) -> bytes | None:
    if a.masterkey:
        return _hexarg(a.masterkey)
    if a.mk_file and a.mk_file.exists() and a.sid and (a.password or a.sha1):
        mkf = parse_file(a.mk_file.read_bytes())
        if mkf.masterkey:
            key, _ = decrypt_masterkey(mkf.masterkey, a.sid,
                                       password=a.password,
                                       pwdhash=_pwdhash(a))
            return key
    return None


def _cmd_blob(a) -> int:
    if not a.file.exists():
        print(f"not found: {a.file}", file=sys.stderr)
        return 2
    try:
        key = _resolve_mk(a)
    except ValueError as e:
        print(f"master-key decryption failed: {e}", file=sys.stderr)
        return 1
    if key is None:
        print("supply --masterkey HEX, or --mk-file + --sid + --password",
              file=sys.stderr)
        return 2
    raw = a.file.read_bytes()
    b, _ = parse_blob(raw, 0)
    try:
        d = decrypt_blob(b, key, entropy=_hexarg(a.entropy))
    except ValueError as e:
        print(f"blob decryption failed: {e}", file=sys.stderr)
        return 1
    kind = classify(d.plaintext)
    out = {"mk_guid": d.mk_guid, "description": d.description, "kind": kind,
           "signature_verified": d.signature_verified,
           "plaintext_hex": d.plaintext.hex(),
           "plaintext_utf8": d.plaintext.decode("utf-8", "replace"),
           "plaintext_utf16": d.plaintext.decode("utf-16-le", "replace")
           .rstrip("\x00")}
    if a.json:
        a.json.write_text(__import__("json").dumps(out, indent=2))
    else:
        print(f"master key   {d.mk_guid}")
        print(f"description  {d.description}")
        print(f"kind         {kind}")
        print(f"signature    {'verified' if d.signature_verified else 'NOT verified'}")
        print(f"hex          {d.plaintext.hex()}")
        print(f"utf-8        {out['plaintext_utf8']!r}")
        if "\x00" in d.plaintext.decode("latin-1"):
            print(f"utf-16le     {out['plaintext_utf16']!r}")
    return 0


def _cmd_scan(a) -> int:
    if not a.protect.exists():
        print(f"not found: {a.protect}", file=sys.stderr)
        return 2
    ctx = tracelib.context(a, "analysis_dpapi", __version__)
    ctx.add_input(str(a.protect))
    for bp in a.blobs:
        ctx.add_input(str(bp))
    res = run(str(a.protect), [str(x) for x in a.blobs], sid=a.sid,
              password=a.password, pwdhash=_pwdhash(a),
              entropy=_hexarg(a.entropy))
    for e in res.errors:
        ctx.error("dpapi-error", e)

    rows = []
    for mk in res.masterkeys:
        rows.append({"type": "masterkey", "guid": mk.guid,
                     "decrypted": mk.decrypted, "detail": mk.scheme or mk.error,
                     "preview": mk.key_hex[:32], "file": mk.file})
    for b in res.blobs:
        rows.append({"type": "blob", "guid": b.mk_guid,
                     "decrypted": b.decrypted,
                     "detail": (b.kind + ("" if b.signature_verified
                                          else " (sig unverified)"))
                     if b.decrypted else b.error,
                     "preview": b.preview, "file": b.file})
    if a.csv:
        tracelib.write_csv(rows, a.csv,
                           ["type", "guid", "decrypted", "detail", "preview",
                            "file"], ctx, confidence="high", tz="n/a")
    if a.json:
        tracelib.write_json(rows, a.json, ctx, confidence="high", tz="n/a")
    if not a.quiet and not (a.csv or a.json):
        for r in rows:
            mark = "OK " if r["decrypted"] else "-- "
            print(f"{mark}{r['type']:<9} {r['guid']}  {r['detail']}")
            if r["decrypted"] and r["preview"]:
                print(f"     {r['preview']}")

    ok_mk = sum(1 for m in res.masterkeys if m.decrypted)
    ok_bl = sum(1 for b in res.blobs if b.decrypted)
    ctx.finish(outputs=[a.csv, a.json])
    print(f"analysis_dpapi: {ok_mk}/{len(res.masterkeys)} master key(s), "
          f"{ok_bl}/{len(res.blobs)} blob(s) decrypted", file=sys.stderr)
    return 0 if (ok_mk or ok_bl) else 1


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    if a.cmd == "masterkey":
        return _cmd_masterkey(a)
    if a.cmd == "blob":
        return _cmd_blob(a)
    if a.cmd == "scan":
        return _cmd_scan(a)
    build_parser().print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
