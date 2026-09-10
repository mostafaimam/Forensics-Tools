"""Decode an ESE data-definition record into ``{column_id: raw_bytes}``."""

from __future__ import annotations

import struct
from dataclasses import dataclass

# tagged-data value flags (Vista+ extended tagged format)
TAGGED_FLAG_LONG_VALUE = 0x01       # data is a 4-byte long-value id (separated)
TAGGED_FLAG_COMPRESSED = 0x02
TAGGED_FLAG_STORED = 0x04
TAGGED_FLAG_MULTI_VALUE = 0x08
TAGGED_FLAG_MULTI_VALUE_SIZE = 0x10


@dataclass
class TaggedValue:
    raw: bytes
    flags: int = 0

    @property
    def is_separated_lv(self) -> bool:
        return bool(self.flags & TAGGED_FLAG_LONG_VALUE)

    @property
    def is_compressed(self) -> bool:
        return bool(self.flags & TAGGED_FLAG_COMPRESSED)


def parse_record(data: bytes, fixed_cols, var_cols, *, new_tagged: bool):
    """fixed_cols / var_cols: lists of (id, length) sorted by id.

    Returns dict[column_id] -> value:
      * fixed / variable -> ``bytes``
      * tagged           -> :class:`TaggedValue`
    """
    out: dict[int, object] = {}
    if len(data) < 4:
        return out
    last_fixed = data[0]
    last_var = data[1]
    var_size_off = struct.unpack_from("<H", data, 2)[0]

    # ---- fixed ------------------------------------------------------------
    pos = 4
    n_fixed = last_fixed
    bitmap_off = var_size_off - ((n_fixed + 7) // 8) if var_size_off else None
    # more robust: bitmap sits right after the fixed data
    fixed_total = 0
    for cid, length in fixed_cols:
        if cid > last_fixed:
            break
        fixed_total += length
    bitmap_off = 4 + fixed_total
    null_bitmap = data[bitmap_off:bitmap_off + (n_fixed + 7) // 8]

    for cid, length in fixed_cols:
        if cid > last_fixed:
            break
        end = pos + length
        raw = data[pos:end]
        pos = end
        idx = cid - 1
        is_null = (idx // 8 < len(null_bitmap)
                   and (null_bitmap[idx // 8] >> (idx % 8)) & 1)
        if not is_null and raw:
            out[cid] = raw

    # ---- variable -------------------------------------------------------
    n_var = last_var - 127 if last_var >= 128 else 0
    if n_var > 0 and var_size_off:
        arr_off = var_size_off
        data_off = arr_off + 2 * n_var
        prev_end = 0
        var_ids = [cid for cid, _ in var_cols if 128 <= cid <= last_var]
        for i in range(n_var):
            if arr_off + 2 * i + 2 > len(data):
                break
            word = struct.unpack_from("<H", data, arr_off + 2 * i)[0]
            empty = bool(word & 0x8000)
            cur_end = word & 0x7FFF
            cid = 128 + i
            if not empty and cur_end >= prev_end:
                raw = data[data_off + prev_end:data_off + cur_end]
                if raw:
                    out[cid] = raw
            prev_end = cur_end
        tagged_start = data_off + prev_end
    else:
        # no variable data: tagged data begins where the var-size array would
        tagged_start = var_size_off if var_size_off else len(data)

    # ---- tagged -------------------------------------------------------
    if tagged_start and tagged_start < len(data):
        _parse_tagged(data[tagged_start:], out, new_tagged)
    return out


def _parse_tagged(area: bytes, out: dict, new_tagged: bool):
    if len(area) < 4:
        return
    first_off = struct.unpack_from("<H", area, 2)[0] & 0x1FFF
    n = first_off // 4
    if n == 0 or n > 4096:
        return
    entries = []
    for i in range(n):
        p = i * 4
        if p + 4 > len(area):
            break
        cid = struct.unpack_from("<H", area, p)[0]
        raw_off = struct.unpack_from("<H", area, p + 2)[0]
        has_flags_byte = bool(raw_off & 0x4000) if new_tagged else False
        off = raw_off & 0x1FFF
        entries.append((cid, off, has_flags_byte))

    for i, (cid, off, has_flags) in enumerate(entries):
        end = entries[i + 1][1] if i + 1 < len(entries) else len(area)
        chunk = area[off:end]
        flags = 0
        if new_tagged:
            if has_flags and chunk:
                flags = chunk[0]
                chunk = chunk[1:]
        out[cid] = TaggedValue(raw=chunk, flags=flags)


def sevenbit_decompress(data: bytes) -> bytes:
    """ESE 7-bit text compression (leading byte 0x18)."""
    if not data or data[0] != 0x18:
        return data
    bits = 0
    nbits = 0
    out = bytearray()
    for byte in data[1:]:
        bits |= byte << nbits
        nbits += 8
        while nbits >= 7:
            out.append((bits & 0x7F) | 0x00)
            bits >>= 7
            nbits -= 7
    return bytes(out).decode("ascii", "replace").encode("utf-16-le")
