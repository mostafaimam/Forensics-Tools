"""Parse the ADB backup (.ab) text header."""

from __future__ import annotations

from dataclasses import dataclass

_MAGIC = b"ANDROID BACKUP"


class AbFormatError(ValueError):
    pass


@dataclass
class AbHeader:
    version: int
    compressed: bool
    encryption: str      # "none" | "AES-256"
    header_len: int      # byte offset where the payload begins


def _read_line(data: bytes, pos: int) -> tuple[bytes, int]:
    nl = data.find(b"\n", pos)
    if nl == -1:
        raise AbFormatError("truncated .ab header")
    return data[pos:nl], nl + 1


def parse_header(data: bytes) -> AbHeader:
    pos = 0
    magic, pos = _read_line(data, pos)
    if magic != _MAGIC:
        raise AbFormatError(f"not an Android backup file (magic "
                            f"{magic!r})")
    version_line, pos = _read_line(data, pos)
    try:
        version = int(version_line)
    except ValueError as e:
        raise AbFormatError(f"bad version line {version_line!r}") from e
    compressed_line, pos = _read_line(data, pos)
    if compressed_line not in (b"0", b"1"):
        raise AbFormatError(f"bad compression flag {compressed_line!r}")
    compressed = compressed_line == b"1"
    encryption_line, pos = _read_line(data, pos)
    encryption = encryption_line.decode("ascii", "replace")
    if encryption not in ("none", "AES-256"):
        raise AbFormatError(f"unrecognised encryption algorithm "
                            f"{encryption!r}")
    if encryption != "none":
        # skip the 5 additional key-wrapping header lines: user_salt,
        # checksum_salt, pbkdf2_rounds, user_iv, user_key_blob
        for _ in range(5):
            _, pos = _read_line(data, pos)
    return AbHeader(version, compressed, encryption, pos)
