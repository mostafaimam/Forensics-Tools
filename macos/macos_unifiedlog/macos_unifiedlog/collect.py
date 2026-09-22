"""Tie chunk walking, ChunkSet decompression, and string carving
together into flat rows."""

from __future__ import annotations

from dataclasses import dataclass, field

from macos_unifiedlog.tracev3 import (carve_strings, decompress_chunkset,
                                      iter_chunks)

COLUMNS = ["kind", "tag_name", "offset", "length", "value", "source"]

_STRING_CARVE_TAGS = {"firehose", "oversize", "statedump", "simpledump"}


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(path: str, *, max_strings_per_chunk: int = 200) -> Result:
    res = Result()
    with open(path, "rb") as fh:
        data = fh.read()

    chunk_count = 0
    for c in iter_chunks(data):
        chunk_count += 1
        res.rows.append({"kind": "chunk", "tag_name": c.tag_name,
                        "offset": c.offset, "length": c.length,
                        "value": f"tag=0x{c.tag:04x} sub_tag=0x"
                                f"{c.sub_tag:04x}", "source": path})

        if c.tag_name == "chunkset":
            decompressed = decompress_chunkset(c.payload)
            if decompressed is None:
                res.warnings.append(
                    f"chunkset at offset {c.offset}: could not "
                    f"decompress with this project's best-effort bv4 "
                    f"framing - skipped")
                continue
            for nc in iter_chunks(decompressed, base_offset=c.offset):
                chunk_count += 1
                res.rows.append({"kind": "chunk", "tag_name": nc.tag_name,
                                "offset": nc.offset, "length": nc.length,
                                "value": f"(nested) tag=0x{nc.tag:04x}",
                                "source": path})
                if nc.tag_name in _STRING_CARVE_TAGS:
                    for s in carve_strings(nc.payload)[
                            :max_strings_per_chunk]:
                        res.rows.append({"kind": "string",
                                        "tag_name": nc.tag_name,
                                        "offset": nc.offset,
                                        "length": len(s), "value": s,
                                        "source": path})
        elif c.tag_name in _STRING_CARVE_TAGS:
            for s in carve_strings(c.payload)[:max_strings_per_chunk]:
                res.rows.append({"kind": "string", "tag_name": c.tag_name,
                                "offset": c.offset, "length": len(s),
                                "value": s, "source": path})

    if chunk_count == 0:
        res.warnings.append(
            "no valid tracev3 chunk framing found at all - this may "
            "not be a .tracev3 file, or its top-level structure "
            "differs from what this project expects")
    return res
