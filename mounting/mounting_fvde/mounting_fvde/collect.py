"""Tie candidate discovery together for the `info` subcommand."""

from __future__ import annotations

from dataclasses import dataclass, field

from mounting_fvde.corestorage import find_candidates

COLUMNS = ["plist_offset", "path", "length", "hex_prefix"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(path: str) -> Result:
    res = Result()
    with open(path, "rb") as fh:
        data = fh.read()
    for c in find_candidates(data):
        res.rows.append({"plist_offset": c.plist_offset, "path": c.path,
                        "length": c.length, "hex_prefix": c.hex_prefix})
    if not res.rows:
        res.warnings.append(
            "no embedded plist with a plausible key-wrap-shaped blob "
            "found (32-256 bytes) - this may not be a CoreStorage "
            "EncryptedRoot.plist.wipekey, or the blob is outside the "
            "size range this tool looks for")
    return res
