"""Walk a Protect dir + blob folder; decrypt master keys then blobs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from analysis_dpapi.blob import decrypt_blob, parse_blob
from analysis_dpapi.masterkey import decrypt_masterkey, parse_file

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_BLOB_MAGIC = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")


def classify(plaintext: bytes) -> str:
    if plaintext[:4] == b"DPAPI":
        return "browser os_crypt AES key"
    if b"\x00" in plaintext and len(plaintext) < 512:
        try:
            t = plaintext.decode("utf-16-le").rstrip("\x00")
            if t.isprintable():
                return "unicode string (password / token?)"
        except UnicodeDecodeError:
            pass
    if plaintext[:2] == b"MZ":
        return "PE payload"
    if all(32 <= c < 127 or c in (9, 10, 13) for c in plaintext[:64]):
        return "text / ascii"
    return "binary"


@dataclass
class MkResult:
    guid: str
    file: str
    decrypted: bool
    key_hex: str = ""
    scheme: str = ""
    error: str = ""


@dataclass
class BlobResult:
    file: str
    mk_guid: str
    decrypted: bool
    kind: str = ""
    description: str = ""
    signature_verified: bool = False
    preview: str = ""
    error: str = ""


@dataclass
class Result:
    masterkeys: list = field(default_factory=list)
    blobs: list = field(default_factory=list)
    keys_by_guid: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)


def _preview(pt: bytes) -> str:
    try:
        u = pt.decode("utf-16-le").rstrip("\x00")
        if u.isprintable() and len(u) > 2:
            return u[:200]
    except UnicodeDecodeError:
        pass
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in pt[:120])
    return txt


def run(protect_dir=None, blob_paths=(), *, sid=None, password=None,
        pwdhash=None, entropy=None) -> Result:
    res = Result()

    if protect_dir:
        for f in Path(protect_dir).rglob("*"):
            if not f.is_file() or not _GUID_RE.match(f.name):
                continue
            try:
                mkf = parse_file(f.read_bytes())
            except Exception as e:  # noqa: BLE001
                res.errors.append(f"{f}: {e}")
                continue
            mk = MkResult(guid=mkf.guid, file=str(f), decrypted=False)
            if mkf.masterkey and (password is not None or pwdhash is not None):
                try:
                    key, scheme = decrypt_masterkey(
                        mkf.masterkey, sid or "", password=password,
                        pwdhash=pwdhash)
                    mk.decrypted = True
                    mk.key_hex = key.hex()
                    mk.scheme = scheme
                    res.keys_by_guid[mkf.guid.lower()] = key
                except ValueError as e:
                    mk.error = str(e)
            elif not mkf.masterkey:
                mk.error = "no master-key blob in file"
            res.masterkeys.append(mk)

    for bp in blob_paths:
        p = Path(bp)
        for f in ([p] if p.is_file() else
                  [x for x in p.rglob("*") if x.is_file()]):
            try:
                raw = f.read_bytes()
            except OSError as e:
                res.errors.append(f"{f}: {e}")
                continue
            idx = raw.find(_BLOB_MAGIC[:4] + _BLOB_MAGIC[4:8])
            starts = []
            i = raw.find(_BLOB_MAGIC)
            while i != -1:
                starts.append(i)
                i = raw.find(_BLOB_MAGIC, i + 1)
            if not starts and raw[:4] == b"\x01\x00\x00\x00":
                starts = [0]
            for s in starts or [0]:
                try:
                    b, _end = parse_blob(raw, s)
                except Exception as e:  # noqa: BLE001
                    res.errors.append(f"{f}@{s}: {e}")
                    continue
                br = BlobResult(file=f"{f}" + (f"@{s:#x}" if s else ""),
                                mk_guid=b.mk_guid, decrypted=False,
                                description=b.description)
                key = res.keys_by_guid.get(b.mk_guid.lower())
                if key is None:
                    br.error = "no master key for " + b.mk_guid
                else:
                    try:
                        d = decrypt_blob(b, key, entropy=entropy)
                        br.decrypted = True
                        br.signature_verified = d.signature_verified
                        br.kind = classify(d.plaintext)
                        br.preview = _preview(d.plaintext)
                    except ValueError as e:
                        br.error = str(e)
                res.blobs.append(br)
    return res
