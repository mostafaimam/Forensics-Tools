"""Signature catalogue for carving.

A signature is:  id, description, extension, list of header byte-strings,
optional footer, a size cap, an optional structural validator key
(:mod:`recovery_carve.validators`), and ``header_at`` for formats whose magic is
not at byte 0 of the file (e.g. MP4 ``ftyp`` at offset 4).
"""

from __future__ import annotations

from dataclasses import dataclass, field

MB = 1024 * 1024


@dataclass(frozen=True)
class Signature:
    id: str
    description: str
    ext: str
    headers: tuple[bytes, ...]
    footers: tuple[bytes, ...] = ()
    max_size: int = 20 * MB
    validator: str | None = None
    header_at: int = 0            # header offset within the object
    footer_inclusive: bool = True
    category: str = "file"

    def carve_start(self, hit_offset: int) -> int:
        return hit_offset - self.header_at


_SIGS: list[Signature] = [
    Signature("jpg", "JPEG image", "jpg",
              (b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xee",
               b"\xff\xd8\xff\xdb", b"\xff\xd8\xff\xe2", b"\xff\xd8\xff\xe8"),
              footers=(b"\xff\xd9",), max_size=50 * MB, validator="jpg",
              category="image"),
    Signature("png", "PNG image", "png", (b"\x89PNG\r\n\x1a\n",),
              footers=(b"IEND\xaeB`\x82",), max_size=50 * MB, validator="png",
              category="image"),
    Signature("gif", "GIF image", "gif", (b"GIF87a", b"GIF89a"),
              footers=(b"\x00\x3b",), max_size=20 * MB, validator="gif",
              category="image"),
    Signature("bmp", "Bitmap image", "bmp", (b"BM",), max_size=64 * MB,
              validator="bmp", category="image"),
    Signature("tif", "TIFF image", "tif", (b"II*\x00", b"MM\x00*"),
              max_size=100 * MB, category="image"),
    Signature("pdf", "PDF document", "pdf", (b"%PDF-",),
              footers=(b"%%EOF",), max_size=200 * MB, validator="pdf",
              category="document"),
    Signature("zip", "ZIP / OOXML / JAR / APK", "zip", (b"PK\x03\x04",),
              footers=(b"PK\x05\x06",), max_size=1024 * MB, validator="zip",
              category="archive"),
    Signature("gz", "GZIP stream", "gz", (b"\x1f\x8b\x08",),
              max_size=512 * MB, validator="gz", category="archive"),
    Signature("rar", "RAR archive", "rar",
              (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"),
              max_size=1024 * MB, category="archive"),
    Signature("7z", "7-Zip archive", "7z", (b"7z\xbc\xaf\x27\x1c",),
              max_size=1024 * MB, category="archive"),
    Signature("sqlite", "SQLite 3 database", "sqlite",
              (b"SQLite format 3\x00",), max_size=512 * MB, validator="sqlite",
              category="database"),
    Signature("evtx", "Windows event log", "evtx", (b"ElfFile\x00",),
              max_size=256 * MB, validator="evtx", category="log"),
    Signature("regf", "Windows registry hive", "hve", (b"regf",),
              max_size=512 * MB, validator="regf", category="registry"),
    Signature("pst", "Outlook PST/OST store", "pst", (b"!BDN",),
              max_size=1024 * MB, category="email"),
    Signature("lnk", "Windows shell link", "lnk",
              (b"\x4c\x00\x00\x00\x01\x14\x02\x00",), max_size=1 * MB,
              category="artifact"),
    Signature("mft", "NTFS MFT entry", "mft", (b"FILE0", b"FILE*"),
              max_size=4096, category="artifact"),
    Signature("mp4", "MP4 / QuickTime", "mp4", (b"ftyp",), header_at=4,
              max_size=1024 * MB, category="video"),
    Signature("ole", "OLE2 / legacy Office", "ole",
              (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",), max_size=256 * MB,
              category="document"),
    Signature("elf", "ELF executable", "elf", (b"\x7fELF",),
              max_size=256 * MB, category="executable"),
    Signature("pe", "PE / MZ executable", "exe", (b"MZ",),
              max_size=256 * MB, category="executable"),
]

BY_ID = {s.id: s for s in _SIGS}


def all_signatures() -> list[Signature]:
    return list(_SIGS)


def select(ids: list[str] | None, categories: list[str] | None) -> list[Signature]:
    if not ids and not categories:
        return list(_SIGS)
    idset = {i.lower() for i in (ids or [])}
    catset = {c.lower() for c in (categories or [])}
    unknown = idset - set(BY_ID)
    if unknown:
        raise ValueError(f"unknown signature id(s): {sorted(unknown)}")
    return [s for s in _SIGS
            if s.id in idset or s.category in catset]
