"""Per-file encryption / password-protection detection."""

from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path

from analysis_encryption.entropy import sampled_entropy

# verdicts
ENCRYPTED = "encrypted"          # content is ciphertext
PROTECTED = "password-protected"  # opens with a password (structure readable)
HIGH_ENTROPY = "high-entropy"    # looks encrypted but no positive signature
CLEAR = "clear"

_COMPRESSED_SIGS = (
    b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x04\x22\x4d\x18",  # gzip bz2 xz lz4
    b"\x28\xb5\x2f\xfd",                                        # zstd
)
_MEDIA_SIGS = (b"\xff\xd8\xff", b"\x89PNG", b"GIF8", b"RIFF", b"\x00\x00\x00 ftyp",
               b"OggS", b"ID3", b"\xff\xfb", b"fLaC", b"%PDF")
_TC_EXT = {".tc", ".hc", ".vc"}


@dataclass
class Finding:
    path: str
    size: int
    verdict: str = CLEAR
    scheme: str = ""
    detail: str = ""
    entropy: float = 0.0
    evidence: str = ""


def _read(path: Path, n: int) -> bytes:
    try:
        with path.open("rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _tail(path: Path, n: int, size: int) -> bytes:
    try:
        with path.open("rb") as fh:
            fh.seek(max(0, size - n))
            return fh.read(n)
    except OSError:
        return b""


# ---------------------------------------------------------------- schemes
def _pgp(head: bytes) -> Finding | None:
    if head[:27] == b"-----BEGIN PGP MESSAGE-----":
        return Finding("", 0, ENCRYPTED, "pgp", "ASCII-armored OpenPGP message")
    if len(head) < 6:
        return None
    b0 = head[0]
    if not (b0 & 0x80):
        return None
    newfmt = bool(b0 & 0x40)
    tag = (b0 & 0x3F) if newfmt else ((b0 >> 2) & 0x0F)
    if tag not in (1, 3):                     # PKESK / SKESK only
        return None
    # first body byte after the length octet(s) is the packet version (3 or 4)
    if newfmt:
        ln = head[1]
        body0 = head[2] if ln < 192 else head[3]
    else:
        lentype = b0 & 0x03
        body0 = head[{0: 2, 1: 3, 2: 5}.get(lentype, 2)]
    if body0 not in (2, 3, 4):
        return None
    names = {1: "public-key session key", 3: "symmetric-key session key"}
    return Finding("", 0, ENCRYPTED, "pgp",
                   f"OpenPGP {names[tag]} packet (v{body0})")


def _age(head: bytes) -> Finding | None:
    if head[:21] == b"age-encryption.org/v1":
        return Finding("", 0, ENCRYPTED, "age", "age v1 header")
    return None


def _openssl(head: bytes) -> Finding | None:
    if head[:8] == b"Salted__":
        return Finding("", 0, ENCRYPTED, "openssl", "OpenSSL 'Salted__' prefix")
    return None


def _luks(head: bytes) -> Finding | None:
    if head[:6] == b"LUKS\xba\xbe":
        ver = struct.unpack_from(">H", head, 6)[0]
        return Finding("", 0, ENCRYPTED, "luks", f"LUKS{ver} volume header")
    return None


def _bitlocker(head: bytes) -> Finding | None:
    if head[3:11] == b"-FVE-FS-" or head[:11] == b"\xeb\x58\x90-FVE-FS-":
        return Finding("", 0, ENCRYPTED, "bitlocker", "-FVE-FS- boot signature")
    if head[:8] == b"\xeb\x52\x90-FVE" or b"-FVE-FS-" in head[:16]:
        return Finding("", 0, ENCRYPTED, "bitlocker", "FVE signature")
    return None


def _keepass(head: bytes) -> Finding | None:
    if head[:4] in (b"\x03\xd9\xa2\x9a", b"\x03\xd9\xa2\x9b", b"\x03\xd9\xa2\x65"):
        return Finding("", 0, ENCRYPTED, "keepass", "KeePass KDBX database")
    return None


def _sqlcipher(path: Path, head: bytes, size: int, ent: float) -> Finding | None:
    if head[:16] == b"SQLite format 3\x00":
        return None
    if path.suffix.lower() in (".db", ".sqlite", ".sqlite3", ".kych") and \
            size >= 4096 and size % 512 == 0 and ent > 7.9:
        return Finding("", 0, ENCRYPTED, "sqlcipher",
                       "SQLite extension but no 'SQLite format 3' header, "
                       "page-aligned, high entropy")
    return None


def _pdf(head: bytes, path: Path, size: int) -> Finding | None:
    if head[:5] != b"%PDF-":
        return None
    tail = _tail(path, 4096, size)
    if b"/Encrypt" in tail or b"/Encrypt" in head:
        m = re.search(rb"/V\s+(\d+).{0,40}?/R\s+(\d+)", tail + head, re.S)
        vr = f" (V={m.group(1).decode()} R={m.group(2).decode()})" if m else ""
        return Finding("", 0, PROTECTED, "pdf",
                       f"/Encrypt dictionary present{vr}")
    return None


def _dmg(path: Path, size: int) -> Finding | None:
    tail = _tail(path, 512, size)
    if b"encrcdsa" in tail or _read(path, 8) == b"encrcdsa":
        return Finding("", 0, ENCRYPTED, "dmg", "encrypted Apple disk image "
                       "(encrcdsa)")
    return None


def _zip(path: Path) -> Finding | None:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError):
        return None
    infos = zf.infolist()
    if not infos:
        return None
    enc = [i for i in infos if i.flag_bits & 0x1]
    if not enc:
        # OOXML encrypted packages are actually CFB, not zip - handled elsewhere
        return None
    aes = False
    for i in enc:
        try:
            extra = i.extra
            if b"\x01\x99" in extra:              # 0x9901 AES extra field id
                aes = True
        except Exception:  # noqa: BLE001
            pass
    scheme = "zip-aes" if aes else "zip"
    frac = f"{len(enc)}/{len(infos)} entries"
    return Finding("", 0, PROTECTED, scheme,
                   f"ZIP encryption bit set ({frac})")


def _rar(head: bytes) -> Finding | None:
    if head[:7] == b"Rar!\x1a\x07\x01":            # RAR5
        # scan first block for an encryption service header (type 4)
        if b"\x04\x01\x80" in head[8:64] or b"CryptVer" in head:
            return Finding("", 0, ENCRYPTED, "rar5", "RAR5 encryption header")
        return Finding("", 0, PROTECTED, "rar5",
                       "RAR5 archive (entries may be encrypted)")
    if head[:7] == b"Rar!\x1a\x07\x00":            # RAR4
        if len(head) > 10 and (head[10] & 0x80):
            return Finding("", 0, ENCRYPTED, "rar4",
                           "RAR4 headers-encrypted flag")
        return Finding("", 0, PROTECTED, "rar4", "RAR4 archive")
    return None


def _sevenz(path: Path, head: bytes) -> Finding | None:
    if head[:6] != b"7z\xbc\xaf\x27\x1c":
        return None
    # the 'end header' can itself be AES-encrypted; if so 7z shows a header
    # with an encoded/encrypted property. A cheap tell: the next-header CRC
    # region points to data that does not look like a plain header.
    return Finding("", 0, PROTECTED, "7z",
                   "7-Zip archive - header/contents may be AES-encrypted "
                   "(password needed to list)")


def _cfb_office(path: Path, head: bytes) -> Finding | None:
    if head[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return None
    blob = _read(path, 1 << 20)
    # OOXML agile/standard encryption
    if b"E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c\x00k\x00a\x00g\x00e" \
            in blob or b"EncryptedPackage" in blob:
        agile = b"http://schemas.microsoft.com/office/2006/keyEncryptor" in blob
        return Finding("", 0, PROTECTED, "office",
                       "OLE 'EncryptedPackage' stream "
                       + ("(agile)" if agile else "(standard/RC4)"))
    # legacy .doc/.xls FIB encrypted flag
    if b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t" in blob:
        i = blob.find(b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t")
        if i > 0 and len(blob) > i + 0x200:
            # FIB flags word - fEncrypted is bit 8 of the byte at FIB+0x0B
            pass
    return None


# ---------------------------------------------------------------- dispatch
_SIG_CHECKS = (_pgp, _age, _openssl, _luks, _bitlocker, _keepass)


def analyse(path: str, *, min_entropy: float = 7.90) -> Finding:
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError:
        return Finding(str(p), 0, CLEAR, "", "unstat-able")
    head = _read(p, 8192)
    f = Finding(str(p), size)

    for check in _SIG_CHECKS:
        hit = check(head)
        if hit:
            hit.path, hit.size = str(p), size
            return _with_entropy(hit, p, size)

    for hit in (_cfb_office(p, head), _pdf(head, p, size), _zip(p), _rar(head),
                _sevenz(p, head), _dmg(p, size)):
        if hit:
            hit.path, hit.size = str(p), size
            return _with_entropy(hit, p, size)

    ent, samples = sampled_entropy(p, size)
    f.entropy = round(ent, 3)
    f.evidence = f"entropy samples {samples}"

    sq = _sqlcipher(p, head, size, ent)
    if sq:
        sq.path, sq.size, sq.entropy = str(p), size, f.entropy
        sq.evidence = f.evidence
        return sq

    if _looks_compressed_or_media(head):
        f.verdict = CLEAR
        f.detail = "recognised compressed / media container"
        return f

    if size >= 4096 and ent >= min_entropy:
        looks_tc = size % 512 == 0
        f.verdict = HIGH_ENTROPY
        f.scheme = "veracrypt-like" if (looks_tc and p.suffix.lower() in _TC_EXT
                                        or looks_tc and size >= (1 << 20)) \
            else "unknown"
        f.detail = ("no signature; uniformly high entropy"
                    + (", 512-byte aligned (TrueCrypt/VeraCrypt pattern)"
                       if looks_tc else ""))
        return f

    f.verdict = CLEAR
    return f


def _with_entropy(f: Finding, p: Path, size: int) -> Finding:
    ent, samples = sampled_entropy(p, size)
    f.entropy = round(ent, 3)
    if not f.evidence:
        f.evidence = f"entropy {f.entropy}"
    return f


def _looks_compressed_or_media(head: bytes) -> bool:
    return (any(head.startswith(s) for s in _COMPRESSED_SIGS)
            or any(s in head[:16] for s in _MEDIA_SIGS)
            or head[:2] == b"PK")
