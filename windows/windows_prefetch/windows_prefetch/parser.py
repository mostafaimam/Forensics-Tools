r"""Parser for the ``SCCA`` Windows Prefetch structure (versions 17-31).

Header (84 bytes, all versions)::

    0   u32   format version   17=XP  23=Vista/7  26=8.1  30=10  31=11
    4   4     "SCCA"
    8   u32   unknown
    12  u32   file size
    16  60    executable name  (UTF-16LE, NUL-terminated)
    76  u32   prefetch hash
    80  u32   flags

File information section starts at 84.  Offsets 16..35 within it (filename
string range, volume information range) are identical across every version;
only the run-time array and run-count location move.
"""

from __future__ import annotations

import struct

from windows_prefetch.mam import PrefetchFormatError, unwrap
from windows_prefetch.models import PrefetchFile, VolumeInfo, filetime_to_utc

_FILEINFO_START = 84
_SUPPORTED = {17, 23, 26, 30, 31}

# run-time array offset (within file-info), count, and run-count offset
_LAYOUT = {
    17: {"rt_off": 36, "rt_count": 1, "rc_off": 60, "vol_entry": 40},
    23: {"rt_off": 44, "rt_count": 1, "rc_off": 68, "vol_entry": 104},
    26: {"rt_off": 44, "rt_count": 8, "rc_off": 124, "vol_entry": 104},
    # version 30 has two sub-layouts, resolved at run time from the size
    "30a": {"rt_off": 44, "rt_count": 8, "rc_off": 124, "vol_entry": 96},
    "30b": {"rt_off": 44, "rt_count": 8, "rc_off": 116, "vol_entry": 96},
    31: {"rt_off": 44, "rt_count": 8, "rc_off": 116, "vol_entry": 96},
}


def _utf16z(buf: bytes) -> str:
    end = len(buf)
    for i in range(0, len(buf) - 1, 2):
        if buf[i] == 0 and buf[i + 1] == 0:
            end = i
            break
    return buf[:end].decode("utf-16-le", "replace")


def _split_utf16_list(buf: bytes) -> list[str]:
    try:
        text = buf.decode("utf-16-le", "replace")
    except Exception:
        return []
    return [s for s in text.split("\x00") if s]


def parse_bytes(data: bytes, source: str = "<bytes>") -> PrefetchFile:
    pf = PrefetchFile(source=source)
    try:
        scca, info = unwrap(data)
    except PrefetchFormatError as e:
        pf.parse_error = str(e)
        return pf
    pf.is_compressed = info["compressed"]
    pf.decompressor = info["decompressor"] or ""

    if len(scca) < _FILEINFO_START:
        pf.parse_error = f"SCCA structure truncated ({len(scca)} bytes)"
        return pf

    version = struct.unpack_from("<I", scca, 0)[0]
    pf.format_version = version
    if version not in _SUPPORTED:
        pf.parse_error = f"unsupported Prefetch version {version}"
        return pf

    pf.executable = _utf16z(scca[16:76])
    pf.prefetch_hash = f"{struct.unpack_from('<I', scca, 76)[0]:08X}"

    fi = _FILEINFO_START
    try:
        (fn_off, fn_size) = struct.unpack_from("<II", scca, fi + 16)
        (vol_off, vol_count, vol_size) = struct.unpack_from("<III", scca, fi + 24)
    except struct.error:
        pf.parse_error = "file information section truncated"
        return pf

    layout = _resolve_layout(version, scca, fi)

    # run times
    rt_base = fi + layout["rt_off"]
    for i in range(layout["rt_count"]):
        try:
            (ticks,) = struct.unpack_from("<Q", scca, rt_base + i * 8)
        except struct.error:
            break
        dt = filetime_to_utc(ticks)
        if dt is not None:
            pf.run_times.append(dt)

    # run count
    try:
        (pf.run_count,) = struct.unpack_from("<I", scca, fi + layout["rc_off"])
    except struct.error:
        pf.warnings.append("run count field out of range")

    # referenced file names
    if 0 < fn_size and fn_off + fn_size <= len(scca):
        pf.referenced_files = _split_utf16_list(scca[fn_off:fn_off + fn_size])
    elif fn_size:
        pf.warnings.append("filename strings range outside file")

    # volumes
    _parse_volumes(pf, scca, vol_off, vol_count, layout["vol_entry"])
    return pf


def _resolve_layout(version: int, scca: bytes, fi: int) -> dict:
    if version == 30:
        try:
            (metrics_off,) = struct.unpack_from("<I", scca, fi + 0)
        except struct.error:
            metrics_off = 0
        fileinfo_size = metrics_off - _FILEINFO_START
        return _LAYOUT["30a"] if fileinfo_size >= 220 else _LAYOUT["30b"]
    return _LAYOUT[version]


def _parse_volumes(pf: PrefetchFile, scca: bytes, vol_off: int,
                   vol_count: int, entry_size: int) -> None:
    if vol_count <= 0 or vol_off <= 0:
        return
    if vol_count > 64:
        pf.warnings.append(f"implausible volume count {vol_count}; clamped")
        vol_count = 64
    for i in range(vol_count):
        base = vol_off + i * entry_size
        if base + 20 > len(scca):
            pf.warnings.append("volume information truncated")
            break
        dp_off, dp_len = struct.unpack_from("<II", scca, base)
        (ticks,) = struct.unpack_from("<Q", scca, base + 8)
        (serial,) = struct.unpack_from("<I", scca, base + 16)
        vol = VolumeInfo(serial_number=serial, creation_time=filetime_to_utc(ticks))
        s = vol_off + dp_off
        e = s + dp_len * 2
        if 0 < dp_len and e <= len(scca):
            vol.device_path = _utf16z(scca[s:e + 2])
        pf.volumes.append(vol)


def parse_file(path) -> PrefetchFile:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        pf = PrefetchFile(source=str(path))
        pf.parse_error = f"cannot read: {e}"
        return pf
    return parse_bytes(data, source=str(path))
