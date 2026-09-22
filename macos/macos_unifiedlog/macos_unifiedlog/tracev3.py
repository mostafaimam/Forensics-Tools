"""Top-level tracev3 chunk walking, ChunkSet decompression, and string
carving. See the package docstring for the confidence split."""

from __future__ import annotations

import string
from dataclasses import dataclass

from macos_unifiedlog.lz4block import Lz4Error, decompress_block

CHUNK_TAG_NAMES = {
    0x1000: "header",
    0x600B: "catalog",
    0x6100: "chunkset",
    0x6001: "firehose",
    0x6002: "oversize",
    0x6003: "statedump",
    0x6004: "simpledump",
}

_BV4_COMPRESSED = b"bv41"
_BV4_UNCOMPRESSED = b"bv4-"
_HEADER_SIZE = 16  # tag(4) + subtag(4) + length(8)
_MAGIC_SEARCH_WINDOW = 32
_MAGIC_HEADER_CANDIDATES = (4, 8, 12)  # bytes to skip after the magic


class TraceV3Error(ValueError):
    pass


@dataclass
class Chunk:
    tag: int
    tag_name: str
    sub_tag: int
    offset: int
    length: int
    payload: bytes


def iter_chunks(data: bytes, base_offset: int = 0):
    pos = 0
    n = len(data)
    while pos + _HEADER_SIZE <= n:
        tag = int.from_bytes(data[pos:pos + 4], "little")
        sub_tag = int.from_bytes(data[pos + 4:pos + 8], "little")
        length = int.from_bytes(data[pos + 8:pos + 16], "little")
        payload_start = pos + _HEADER_SIZE
        if length < 0 or payload_start + length > n:
            break
        payload = data[payload_start:payload_start + length]
        yield Chunk(tag, CHUNK_TAG_NAMES.get(tag, f"0x{tag:04x}"), sub_tag,
                    base_offset + pos, length, payload)
        pos = payload_start + length
        pos = (pos + 7) & ~7  # 8-byte chunk alignment


def _looks_like_chunk_sequence(data: bytes) -> bool:
    if len(data) < _HEADER_SIZE:
        return False
    seen_any_recognized = False
    consumed = 0
    for c in iter_chunks(data):
        if c.tag in CHUNK_TAG_NAMES:
            seen_any_recognized = True
        consumed = c.offset + _HEADER_SIZE + c.length
        if consumed >= len(data) - 7:  # reached (near) the end cleanly
            break
    return seen_any_recognized and consumed > 0


def decompress_chunkset(payload: bytes) -> bytes | None:
    """Best-effort: try a small set of candidate framings for Apple's
    bv4 wrapper and keep whichever decompresses to a byte sequence that
    self-verifies as a plausible nested-chunk stream. Returns None if
    nothing tried self-verifies - reported as "could not decompress",
    never a silent guess."""
    limit = min(len(payload), _MAGIC_SEARCH_WINDOW)
    for kind, magic in (("compressed", _BV4_COMPRESSED),
                        ("raw", _BV4_UNCOMPRESSED)):
        idx = payload.find(magic, 0, limit)
        if idx == -1:
            continue
        for skip in _MAGIC_HEADER_CANDIDATES:
            start = idx + skip
            if start > len(payload):
                continue
            body = payload[start:]
            if kind == "raw":
                candidate = body
            else:
                try:
                    candidate = decompress_block(body)
                except Lz4Error:
                    continue
            if _looks_like_chunk_sequence(candidate):
                return candidate
    return None


_PRINTABLE = set(string.printable) - set("\x0b\x0c")


def _looks_utf16(data: bytes) -> bool:
    """Real UTF-16LE text in the ASCII range has a NUL in roughly every
    other byte; ASCII/binary data reinterpreted 2-bytes-at-a-time
    produces mostly CJK-range garbage instead (confirmed empirically -
    running the UTF-16LE pass unconditionally over ASCII test data
    produced exactly that noise). Gate on an actual NUL-density signal
    rather than always attempting both encodings blind."""
    if not data:
        return False
    return (data.count(0) / len(data)) > 0.2


def carve_strings(data: bytes, min_length: int = 6) -> list[str]:
    out = []
    encodings = ("ascii", "utf-16-le") if _looks_utf16(data) else ("ascii",)
    for enc in encodings:
        current = []
        i = 0
        step = 1 if enc == "ascii" else 2
        while i + step <= len(data):
            if enc == "ascii":
                ch = chr(data[i]) if data[i] < 128 else None
            else:
                unit = int.from_bytes(data[i:i + 2], "little")
                ch = chr(unit) if 0x20 <= unit < 0xD800 else \
                    ("\t" if unit in (9, 10, 13) else None)
            if ch is not None and (ch in _PRINTABLE or ch.isprintable()):
                current.append(ch)
            else:
                if len(current) >= min_length:
                    out.append("".join(current))
                current = []
            i += step
        if len(current) >= min_length:
            out.append("".join(current))
    return out
