"""Build byte-accurate synthetic SCCA / MAM prefetch files for testing."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def to_filetime(dt: datetime | None) -> int:
    if dt is None:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


def _u16z(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\x00\x00"


def make_scca_v30(
    executable: str,
    run_times: list[datetime],
    run_count: int,
    referenced_files: list[str],
    device_path: str = "\\VOLUME{01d8a1a0-00000000}",
    serial: int = 0x1A2B3C4D,
    created: datetime | None = None,
    variant: str = "b",
    version: int = 30,
) -> bytes:
    fileinfo_size = 220 if variant == "a" else 212
    rc_off = 124 if variant == "a" else 116
    fileinfo_start = 84
    metrics_off = fileinfo_start + fileinfo_size

    fn_blob = b"".join(_u16z(p) for p in referenced_files)
    fn_off = metrics_off  # zero metrics + zero trace chains
    fn_size = len(fn_blob)

    vol_off = fn_off + fn_size
    vol_off = (vol_off + 7) & ~7  # 8-byte align
    pad_before_vol = vol_off - (fn_off + fn_size)

    dev_blob = _u16z(device_path)
    vol_entry = bytearray(96)
    struct.pack_into("<II", vol_entry, 0, 96, len(device_path))
    struct.pack_into("<Q", vol_entry, 8, to_filetime(created))
    struct.pack_into("<I", vol_entry, 16, serial)
    vol_blob = bytes(vol_entry) + dev_blob
    vol_size = len(vol_blob)

    total = vol_off + vol_size

    buf = bytearray(total)
    struct.pack_into("<I", buf, 0, version)
    buf[4:8] = b"SCCA"
    struct.pack_into("<I", buf, 12, total)
    buf[16:16 + len(_u16z(executable))] = _u16z(executable)
    struct.pack_into("<I", buf, 76, 0xABCDEF01)
    struct.pack_into("<I", buf, 80, 0)

    fi = fileinfo_start
    struct.pack_into("<I", buf, fi + 0, metrics_off)
    struct.pack_into("<I", buf, fi + 4, 0)
    struct.pack_into("<I", buf, fi + 8, metrics_off)
    struct.pack_into("<I", buf, fi + 12, 0)
    struct.pack_into("<I", buf, fi + 16, fn_off)
    struct.pack_into("<I", buf, fi + 20, fn_size)
    struct.pack_into("<I", buf, fi + 24, vol_off)
    struct.pack_into("<I", buf, fi + 28, 1)
    struct.pack_into("<I", buf, fi + 32, vol_size)
    for i in range(8):
        dt = run_times[i] if i < len(run_times) else None
        struct.pack_into("<Q", buf, fi + 44 + i * 8, to_filetime(dt))
    struct.pack_into("<I", buf, fi + rc_off, run_count)

    buf[fn_off:fn_off + fn_size] = fn_blob
    buf[vol_off:vol_off + vol_size] = vol_blob
    return bytes(buf)


def wrap_mam(scca: bytes) -> bytes:
    """Compress an SCCA blob into a Windows-10-style MAM container (needs ntdll)."""
    from trace_prefetch.win_native import rtl_compress

    payload = rtl_compress(scca)
    return b"MAM\x04" + struct.pack("<I", len(scca)) + payload
