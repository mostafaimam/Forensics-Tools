r"""Parser for Vista+ ``$I`` Recycle Bin metadata files.

Layout::

    offset  size  field
    0       8     version         (u64 LE)  1 = pre-Windows 10, 2 = Windows 10+
    8       8     original size   (u64 LE)  logical size of the deleted file
    16      8     deleted time    (u64 LE)  FILETIME, UTC
    -- version 1 --
    24      520   original path   (260 UTF-16LE code units, NUL-terminated)
    -- version 2 --
    24      4     path length     (u32 LE)  code units incl. the NUL terminator
    28      2*N   original path   (UTF-16LE, NUL-terminated)
"""

from __future__ import annotations

import struct

from trace_recycle.models import RecycleRecord, filetime_to_utc

_V1_PATH_BYTES = 520
_MAX_SANE_PATH_CHARS = 32768  # guard against a corrupt length field


def _decode_utf16(raw: bytes, warnings: list[str]) -> str:
    # Trim at the first NUL code unit, then decode leniently.
    end = len(raw)
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            end = i
            break
    try:
        return raw[:end].decode("utf-16-le")
    except UnicodeDecodeError:
        warnings.append("path contained undecodable UTF-16; used replacement chars")
        return raw[:end].decode("utf-16-le", "replace")


def parse_i_bytes(data: bytes, source: str = "<bytes>") -> RecycleRecord:
    rec = RecycleRecord(source=source, source_kind="$I", format_version="?")

    if len(data) < 24:
        rec.parse_error = f"file too small ({len(data)} bytes; need >= 24)"
        return rec

    version, size, ft = struct.unpack_from("<QQQ", data, 0)
    rec.original_size = size
    rec.deleted_utc = filetime_to_utc(ft)
    if rec.deleted_utc is None and ft != 0:
        rec.warnings.append(f"unrepresentable FILETIME value {ft}")

    if version == 1:
        rec.format_version = "1"
        body = data[24:24 + _V1_PATH_BYTES]
        if len(body) < 2:
            rec.parse_error = "version 1 file truncated before path"
            return rec
        if len(body) < _V1_PATH_BYTES:
            rec.warnings.append(
                f"version 1 path field truncated ({len(body)}/{_V1_PATH_BYTES} bytes)"
            )
        rec.original_path = _decode_utf16(body, rec.warnings)
    elif version == 2:
        rec.format_version = "2"
        if len(data) < 28:
            rec.parse_error = "version 2 file truncated before path length"
            return rec
        (nchars,) = struct.unpack_from("<I", data, 24)
        if nchars == 0:
            rec.warnings.append("path length is zero")
            rec.original_path = ""
        else:
            if nchars > _MAX_SANE_PATH_CHARS:
                rec.warnings.append(
                    f"implausible path length {nchars}; clamped"
                )
                nchars = _MAX_SANE_PATH_CHARS
            want = nchars * 2
            body = data[28:28 + want]
            if len(body) < want:
                rec.warnings.append(
                    f"path field truncated ({len(body)}/{want} bytes)"
                )
            rec.original_path = _decode_utf16(body, rec.warnings)
    else:
        rec.format_version = str(version)
        rec.parse_error = f"unknown $I version {version}"
        return rec

    rec.drive = _drive_of(rec.original_path)
    return rec


def _drive_of(path: str) -> str:
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return path[0].upper() + ":"
    return ""


def parse_i_file(path) -> RecycleRecord:
    import os

    from trace_recycle.models import RecycleRecord as _R

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        r = _R(source=str(path), source_kind="$I", format_version="?")
        r.parse_error = f"cannot read: {e}"
        return r
    rec = parse_i_bytes(data, source=str(path))
    rec.recycle_id = _recycle_id(os.path.basename(str(path)))
    return rec


def _recycle_id(name: str) -> str:
    """``$IAbC123.txt`` -> ``AbC123.txt`` (the token shared with ``$RAbC123.txt``).

    The random token *and* any extension are common to the $I / $R pair.
    """
    if name[:2].lower() in ("$i", "$r"):
        return name[2:]
    return name
