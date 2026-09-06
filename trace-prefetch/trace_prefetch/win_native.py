"""Optional Windows fast paths via ``ntdll`` RTL compression.

Only used on Windows and only as an accelerator / cross-check; every code path
has a pure-Python equivalent so the tool works identically off-host.
"""

from __future__ import annotations

import ctypes
import os

_XPRESS_HUFFMAN = 0x0004
_ENGINE_MAXIMUM = 0x0100


def available() -> bool:
    return os.name == "nt"


def rtl_decompress(compressed: bytes, uncompressed_size: int) -> bytes:
    """XPRESS-Huffman decompress via ``RtlDecompressBufferEx``."""
    if os.name != "nt":
        raise RuntimeError("rtl_decompress is Windows-only")
    ntdll = ctypes.WinDLL("ntdll")

    workspace_size = ctypes.c_ulong(0)
    frag = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(_XPRESS_HUFFMAN),
        ctypes.byref(workspace_size),
        ctypes.byref(frag),
    )
    if status != 0:
        raise OSError(f"RtlGetCompressionWorkSpaceSize failed: {status:#x}")

    out = ctypes.create_string_buffer(uncompressed_size)
    final = ctypes.c_ulong(0)
    workspace = ctypes.create_string_buffer(workspace_size.value)
    status = ntdll.RtlDecompressBufferEx(
        ctypes.c_ushort(_XPRESS_HUFFMAN),
        out, ctypes.c_ulong(uncompressed_size),
        compressed, ctypes.c_ulong(len(compressed)),
        ctypes.byref(final),
        workspace,
    )
    if status != 0:
        raise OSError(f"RtlDecompressBufferEx failed: {status:#x}")
    return out.raw[:final.value]


def rtl_compress(data: bytes) -> bytes:
    """XPRESS-Huffman compress via ``RtlCompressBuffer`` (test helper)."""
    if os.name != "nt":
        raise RuntimeError("rtl_compress is Windows-only")
    ntdll = ctypes.WinDLL("ntdll")
    fmt = ctypes.c_ushort(_XPRESS_HUFFMAN | _ENGINE_MAXIMUM)

    workspace_size = ctypes.c_ulong(0)
    frag = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        fmt, ctypes.byref(workspace_size), ctypes.byref(frag)
    )
    if status != 0:
        raise OSError(f"RtlGetCompressionWorkSpaceSize failed: {status:#x}")

    out = ctypes.create_string_buffer(len(data) + 4096)
    final = ctypes.c_ulong(0)
    workspace = ctypes.create_string_buffer(workspace_size.value)
    status = ntdll.RtlCompressBuffer(
        fmt, data, ctypes.c_ulong(len(data)),
        out, ctypes.c_ulong(len(out)),
        ctypes.c_ulong(4096),
        ctypes.byref(final), workspace,
    )
    if status != 0:
        raise OSError(f"RtlCompressBuffer failed: {status:#x}")
    return out.raw[:final.value]
