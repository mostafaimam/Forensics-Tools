"""Find candidate CoreStorage key-wrap blobs inside a plist or image.

Discovery only - deciding which candidate is the real salt/wrapped-key
pair is left to the examiner (see the package docstring for why).
"""

from __future__ import annotations

import plistlib
from dataclasses import dataclass

_BPLIST_MAGIC = b"bplist00"
_MIN_BLOB, _MAX_BLOB = 32, 256


def _find_bplist_end(data: bytes, start: int,
                     max_scan: int = 1 << 20) -> int | None:
    """A bplist00's 32-byte trailer must sit at the literal end of the
    buffer handed to plistlib, so an embedded plist followed by more
    binary data (the real-world case here) needs its true end located
    first. Scan candidate end positions and keep the one whose trailer
    fields are self-consistent (offset-table position + size lands
    exactly at that candidate end) - cheap arithmetic per candidate,
    no repeated full parsing."""
    limit = min(len(data), start + max_scan)
    for end in range(start + 40, limit + 1):
        trailer = data[end - 32:end]
        offset_int_size = trailer[6]
        object_ref_size = trailer[7]
        if offset_int_size == 0 or object_ref_size == 0:
            continue
        num_objects = int.from_bytes(trailer[8:16], "big")
        top_object = int.from_bytes(trailer[16:24], "big")
        # relative to the plist's OWN start, not an absolute position
        offset_table_offset = int.from_bytes(trailer[24:32], "big")
        if not (0 <= offset_table_offset < end - start) or \
                top_object >= max(num_objects, 1):
            continue
        if start + offset_table_offset + num_objects * offset_int_size \
                + 32 == end:
            return end
    return None


def find_embedded_plists(data: bytes) -> list[tuple[int, dict]]:
    out = []
    start = 0
    while True:
        idx = data.find(_BPLIST_MAGIC, start)
        if idx == -1:
            break
        end = _find_bplist_end(data, idx)
        candidates = [end] if end is not None else []
        candidates.append(len(data))  # fallback: plist is the tail
        for cand_end in candidates:
            try:
                value = plistlib.loads(bytes(data[idx:cand_end]))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(value, dict):
                out.append((idx, value))
            break
        start = idx + len(_BPLIST_MAGIC)
    return out


@dataclass
class Candidate:
    plist_offset: int
    path: str
    length: int
    hex_prefix: str
    blob: bytes


def _walk_blobs(value, path=""):
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            found.extend(_walk_blobs(v, f"{path}.{k}" if path else str(k)))
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            found.extend(_walk_blobs(v, f"{path}[{i}]"))
    elif isinstance(value, (bytes, bytearray)) and \
            _MIN_BLOB <= len(value) <= _MAX_BLOB:
        found.append((path, bytes(value)))
    return found


def find_candidates(data: bytes) -> list[Candidate]:
    out = []
    for offset, plist in find_embedded_plists(data):
        for path, blob in _walk_blobs(plist):
            out.append(Candidate(offset, path, len(blob),
                                 blob[:16].hex(), blob))
    return out
