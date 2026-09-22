"""Scan for VSS identifier GUID hits and nearby candidate fields.

See the package docstring for why this stops at candidate-field
discovery rather than full block-remapping / snapshot mounting.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

# {3808876B-C176-4E48-B7AE-04046E6CC752} in on-disk mixed-endian GUID
# byte order (the standard Windows GUID encoding: first three fields
# little-endian, last two big-endian).
_VSS_GUID = uuid.UUID("3808876B-C176-4E48-B7AE-04046E6CC752")
_VSS_MAGIC = _VSS_GUID.bytes_le

_MIN_PLAUSIBLE = datetime(2001, 1, 1, tzinfo=timezone.utc)
_MAX_PLAUSIBLE = datetime(2035, 1, 1, tzinfo=timezone.utc)
_SCAN_WINDOW = 512


def filetime_to_utc(value: int) -> datetime | None:
    if value <= 0:
        return None
    try:
        return datetime.fromtimestamp(
            (value - 116444736000000000) / 10_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _plausible_filetimes(chunk: bytes, base_offset: int):
    out = []
    for i in range(0, len(chunk) - 8):
        value = int.from_bytes(chunk[i:i + 8], "little")
        dt = filetime_to_utc(value)
        if dt is not None and _MIN_PLAUSIBLE <= dt <= _MAX_PLAUSIBLE:
            out.append({"offset": base_offset + i,
                       "utc": dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                       "raw": value})
    return out


def _candidate_guids(chunk: bytes, base_offset: int):
    out = []
    for i in range(0, len(chunk) - 16, 4):
        span = chunk[i:i + 16]
        if span == _VSS_MAGIC or span.count(span[0:1]) == 16:
            continue  # skip the identifier itself and runs of one byte
        try:
            g = uuid.UUID(bytes_le=span)
        except ValueError:
            continue
        # a plausible GUID has a valid RFC 4122 variant/version nibble
        if g.variant == uuid.RFC_4122 and 1 <= g.version <= 5:
            out.append({"offset": base_offset + i, "guid": str(g)})
    return out


@dataclass
class VssHit:
    offset: int
    header_hex: str
    candidate_filetimes: list[dict]
    candidate_guids: list[dict]


def scan(data: bytes) -> list[VssHit]:
    hits = []
    start = 0
    while True:
        idx = data.find(_VSS_MAGIC, start)
        if idx == -1:
            break
        window = data[idx:idx + _SCAN_WINDOW]
        hits.append(VssHit(
            offset=idx,
            header_hex=window[:64].hex(),
            candidate_filetimes=_plausible_filetimes(window, idx),
            candidate_guids=_candidate_guids(window, idx),
        ))
        start = idx + len(_VSS_MAGIC)
    return hits
