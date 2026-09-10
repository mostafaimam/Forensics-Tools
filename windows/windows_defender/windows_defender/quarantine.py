r"""Microsoft Defender quarantine store parser.

The ``Quarantine`` folder holds three sub-trees:

* ``Entries\{GUID}``  - one metadata record per detection
* ``ResourceData\<XX>\<SHA?>``  - the quarantined file(s), RC4-wrapped
* ``Resource\<XX>\<...>``  - an index of resources

Every file is obfuscated with RC4 under a single fixed key that Microsoft
has shipped unchanged for years and that is documented in public malware
-analysis literature.  Applying it is de-obfuscation, not decryption:
there is no secret and nothing is brute-forced.

Entry layout (after RC4):

    header   0x3C bytes   -> two little-endian u32 sizes at 0x28 / 0x2C
    section1 <size1>      -> Id, ScanId (GUIDs), FILETIME @0x20,
                             ThreatId u64 @0x28, detection name (cstr) @0x30
    section2 <size2>      -> u32 count, count x u32 offsets, then per
                             resource: UTF-16LE path (cstr), u32 field
                             count, then TLV fields (type 4 = FILETIME,
                             type 3 = u32, others = bytes/utf16)
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Fixed Defender quarantine RC4 key (0x100 bytes) - public obfuscation key.
_KEY = bytes((
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C,
    0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9,
    0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF,
    0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
    0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
    0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64,
    0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA,
    0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
    0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40,
    0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
    0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19, 0x18, 0x18,
    0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
    0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D,
    0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85,
    0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
    0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
    0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8,
    0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D,
    0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B,
    0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
    0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD,
    0xBF, 0xF3, 0x82, 0x53,
))

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def rc4(data: bytes, key: bytes = _KEY) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = data[k] ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _filetime(v: int) -> str:
    if not v or v > 0x7FFF_FFFF_FFFF_FFFF:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


def _cstr_utf16(buf: bytes, off: int) -> tuple[str, int]:
    end = off
    while end + 1 < len(buf) and buf[end:end + 2] != b"\x00\x00":
        end += 2
    return buf[off:end].decode("utf-16-le", "replace"), end + 2


def _cstr(buf: bytes, off: int) -> tuple[str, int]:
    end = buf.find(b"\x00", off)
    if end < 0:
        end = len(buf)
    return buf[off:end].decode("utf-8", "replace"), end + 1


@dataclass
class Resource:
    path: str = ""
    kind: str = ""
    detection_time: str = ""
    sha1: str = ""
    fields: dict = field(default_factory=dict)


@dataclass
class QuarantineEntry:
    guid: str = ""
    scan_id: str = ""
    threat: str = ""
    threat_id: int = 0
    timestamp: str = ""
    resources: list = field(default_factory=list)
    source: str = ""
    parse_error: str = ""

    def rows(self) -> list[dict]:
        base = {
            "kind": "quarantine", "time": self.timestamp,
            "threat": self.threat, "threat_id": self.threat_id,
            "scan_id": self.scan_id, "entry_guid": self.guid,
            "source": self.source,
        }
        if not self.resources:
            return [dict(base, path="", detail=self.parse_error)]
        out = []
        for r in self.resources:
            out.append(dict(base, path=r.path,
                            detail=f"{r.kind} {r.sha1}".strip()))
        return out


def _parse_section1(buf: bytes) -> dict:
    d: dict = {}
    if len(buf) >= 16:
        d["guid"] = str(uuid.UUID(bytes_le=buf[0:16]))
    if len(buf) >= 32:
        d["scan_id"] = str(uuid.UUID(bytes_le=buf[16:32]))
    if len(buf) >= 0x28:
        d["timestamp"] = _filetime(struct.unpack_from("<Q", buf, 0x20)[0])
    if len(buf) >= 0x30:
        d["threat_id"] = struct.unpack_from("<Q", buf, 0x28)[0]
    if len(buf) > 0x30:
        name, _ = _cstr(buf, 0x30)
        d["threat"] = name
    return d


def _parse_section2(buf: bytes) -> list[Resource]:
    res: list[Resource] = []
    if len(buf) < 4:
        return res
    count = struct.unpack_from("<I", buf, 0)[0]
    if count > 4096:
        return res
    offs = []
    for i in range(count):
        p = 4 + i * 4
        if p + 4 > len(buf):
            break
        offs.append(struct.unpack_from("<I", buf, p)[0])
    for o in offs:
        if o >= len(buf):
            continue
        try:
            r = _parse_resource(buf, o)
        except (struct.error, IndexError, ValueError):
            continue
        if r:
            res.append(r)
    return res


def _parse_resource(buf: bytes, off: int) -> Resource | None:
    path, p = _cstr_utf16(buf, off)
    r = Resource(path=path)
    if p + 4 > len(buf):
        return r
    nfields = struct.unpack_from("<I", buf, p)[0]
    p += 4
    for _ in range(min(nfields, 64)):
        if p + 4 > len(buf):
            break
        size, ftype = struct.unpack_from("<HH", buf, p)
        p += 4
        val = buf[p:p + size]
        p += size
        p = (p + 3) & ~3  # 4-byte align
        if ftype == 0x06 and size <= 64:
            r.kind = val.decode("utf-16-le", "replace").strip("\x00")
        elif ftype == 0x04 and size == 8:
            r.detection_time = _filetime(struct.unpack("<Q", val)[0])
        elif ftype == 0x03 and size == 4:
            r.fields["u32"] = struct.unpack("<I", val)[0]
        elif size == 20:
            r.sha1 = val.hex()
        else:
            r.fields[f"t{ftype}"] = val.hex()[:64]
    return r


def parse_entry(raw: bytes, source: str = "") -> QuarantineEntry:
    e = QuarantineEntry(source=source)
    if len(raw) < 0x3C:
        e.parse_error = "entry too small"
        return e
    header = rc4(raw[:0x3C])
    size1, size2 = struct.unpack_from("<II", header, 0x28)
    pos = 0x3C
    sec1 = rc4(raw[pos:pos + size1]) if size1 and pos + size1 <= len(raw) else b""
    pos += size1
    sec2 = rc4(raw[pos:pos + size2]) if size2 and pos + size2 <= len(raw) else b""
    d = _parse_section1(sec1)
    e.guid = d.get("guid", "")
    e.scan_id = d.get("scan_id", "")
    e.threat = d.get("threat", "")
    e.threat_id = d.get("threat_id", 0)
    e.timestamp = d.get("timestamp", "")
    e.resources = _parse_section2(sec2)
    if not e.threat and not e.resources:
        e.parse_error = "no fields recovered"
    return e


def read_entries(qdir: Path) -> list[QuarantineEntry]:
    out: list[QuarantineEntry] = []
    ent = qdir / "Entries"
    if not ent.is_dir():
        # maybe qdir already *is* Entries
        ent = qdir if qdir.name.lower() == "entries" else ent
    if not ent.is_dir():
        return out
    for f in sorted(ent.iterdir()):
        if not f.is_file():
            continue
        try:
            out.append(parse_entry(f.read_bytes(), str(f)))
        except (OSError, struct.error) as exc:
            e = QuarantineEntry(source=str(f))
            e.parse_error = str(exc)
            out.append(e)
    return out


def extract_resource(res_path: Path, dest: Path) -> int:
    """RC4-unwrap a ResourceData file; strip the 0x28 metadata prefix."""
    raw = res_path.read_bytes()
    dec = rc4(raw)
    # ResourceData: u32 magic 0x03000000, u32 size, ... payload after 0x28
    body = dec[0x28:] if len(dec) > 0x28 else dec
    dest.write_bytes(body)
    return len(body)


def extract_all(qdir: Path, dest: Path) -> list[tuple[str, int]]:
    """Unwrap every ResourceData file under a Quarantine dir into *dest*."""
    rd = qdir / "ResourceData"
    if not rd.is_dir():
        rd = qdir if qdir.name.lower() == "resourcedata" else rd
    if not rd.is_dir():
        return []
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for f in sorted(rd.rglob("*")):
        if not f.is_file():
            continue
        target = dest / f"{f.parent.name}_{f.name}.bin"
        try:
            n = extract_resource(f, target)
            out.append((str(target), n))
        except OSError:
            continue
    return out
