r"""MAM container handling for Windows 10 / 11 Prefetch.

Windows 8.1 and earlier store the ``SCCA`` prefetch structure uncompressed.
Windows 10 and 11 wrap it in an 8-byte ``MAM`` header followed by an
XPRESS-Huffman compressed payload::

    0  3   "MAM"
    3  1   compression algorithm  (0x04 = XPRESS Huffman)
    4  4   uncompressed size      (u32 LE)
    8  ..  compressed payload
"""

from __future__ import annotations

import os
import struct

from trace_prefetch.xpress_huffman import XpressError, decompress

MAM_SIGNATURE = b"MAM"
_ALG_XPRESS_HUFFMAN = 0x04
SCCA_SIGNATURE = b"SCCA"


class PrefetchFormatError(ValueError):
    pass


def is_mam(data: bytes) -> bool:
    return data[:3] == MAM_SIGNATURE


def is_scca(data: bytes) -> bool:
    return len(data) >= 8 and data[4:8] == SCCA_SIGNATURE


def unwrap(data: bytes, *, prefer_native: bool = True) -> tuple[bytes, dict]:
    """Return ``(scca_bytes, info)``.

    Accepts a raw ``.pf`` file: an uncompressed ``SCCA`` structure is returned
    unchanged; a ``MAM`` container is decompressed first.
    """
    info: dict = {"compressed": False, "decompressor": None,
                  "uncompressed_size": None}

    if is_scca(data):
        return data, info

    if not is_mam(data):
        raise PrefetchFormatError(
            "not a Prefetch file (no 'MAM' or 'SCCA' signature)"
        )

    if len(data) < 8:
        raise PrefetchFormatError("truncated MAM header")
    algorithm = data[3]
    (uncompressed_size,) = struct.unpack_from("<I", data, 4)
    info["compressed"] = True
    info["uncompressed_size"] = uncompressed_size
    if algorithm != _ALG_XPRESS_HUFFMAN:
        raise PrefetchFormatError(
            f"unsupported MAM compression algorithm {algorithm:#04x}"
        )

    payload = data[8:]
    scca = _decompress(payload, uncompressed_size, prefer_native, info)

    if not is_scca(scca):
        raise PrefetchFormatError(
            "decompressed data is not an SCCA structure"
        )
    return scca, info


def _decompress(payload, size, prefer_native, info):
    if os.environ.get("TRACE_PREFETCH_NO_NATIVE"):
        prefer_native = False
    if prefer_native:
        try:
            from trace_prefetch import win_native

            if win_native.available():
                out = win_native.rtl_decompress(payload, size)
                info["decompressor"] = "ntdll"
                return out
        except OSError:
            pass  # fall through to the pure-Python path
    try:
        out = decompress(payload, size)
    except XpressError as e:
        raise PrefetchFormatError(f"XPRESS-Huffman decompression failed: {e}")
    info["decompressor"] = "python"
    return out
