r"""Parser for the legacy ``INFO2`` (and ``INFO``) Recycle Bin index used by
Windows NT 4 / 2000 / XP / 2003.

File header (16 bytes)::

    0x00  u32  version           4 (NT4) / 5 (IE5+/2000+)
    0x04  u32  number of files   (often unused / 0)
    0x08  u32  unused
    0x0C  u32  record size       usually 0x320 (800); INFO / NT4 uses 0x118 (280)

Each record (``record size`` bytes)::

    0x000  char[260]  original path, ANSI/OEM   (byte 0 zeroed when the entry
                                                 has been removed from the bin)
    0x104  u32        record index (the N in ``Dc<N>``)
    0x108  u32        drive number (0 = A:, 2 = C:, ...)
    0x10C  u64        deleted time, FILETIME UTC
    0x114  u32        physical file size (cluster-rounded)
    0x118  wchar[260] original path, UTF-16LE   (only when record size >= 0x320)
"""

from __future__ import annotations

import struct

from trace_recycle.models import RecycleRecord, filetime_to_utc

_HEADER = 16
_REC_DEFAULT = 0x320
_REC_LEGACY = 0x118


def _decode_ansi(raw: bytes) -> str:
    end = raw.find(b"\x00")
    if end == -1:
        end = len(raw)
    chunk = raw[:end]
    for enc in ("mbcs", "cp1252", "latin-1"):
        try:
            return chunk.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return chunk.decode("latin-1", "replace")


def _decode_utf16(raw: bytes) -> str:
    end = len(raw)
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            end = i
            break
    try:
        return raw[:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return raw[:end].decode("utf-16-le", "replace")


def _drive_letter(num: int) -> str:
    if 0 <= num < 26:
        return chr(ord("A") + num) + ":"
    return ""


def parse_info2_bytes(data: bytes, source: str = "<bytes>") -> list[RecycleRecord]:
    if len(data) < _HEADER:
        err = RecycleRecord(source=source, source_kind="INFO2", format_version="?")
        err.parse_error = f"file too small ({len(data)} bytes)"
        return [err]

    version, _count, _unused, rec_size = struct.unpack_from("<IIII", data, 0)
    if rec_size not in (_REC_DEFAULT, _REC_LEGACY):
        # Trust a sane-looking value, else fall back to the common default.
        if not (0x100 <= rec_size <= 0x400):
            rec_size = _REC_DEFAULT
    has_unicode = rec_size >= _REC_DEFAULT
    kind = "INFO2" if has_unicode else "INFO"
    fmt = f"{kind}-v{version}"

    out: list[RecycleRecord] = []
    body = data[_HEADER:]
    n_full, tail = divmod(len(body), rec_size)

    for i in range(n_full):
        raw = body[i * rec_size:(i + 1) * rec_size]
        rec = RecycleRecord(source=source, source_kind=kind, format_version=fmt)

        ansi_name = raw[0:260]
        rec.active = ansi_name[0] != 0
        (index,) = struct.unpack_from("<I", raw, 0x104)
        (drive_num,) = struct.unpack_from("<I", raw, 0x108)
        (ft,) = struct.unpack_from("<Q", raw, 0x10C)
        (size,) = struct.unpack_from("<I", raw, 0x114)

        rec.index = index
        rec.recycle_id = str(index)
        rec.drive = _drive_letter(drive_num)
        rec.original_size = size
        rec.deleted_utc = filetime_to_utc(ft)
        if rec.deleted_utc is None and ft != 0:
            rec.warnings.append(f"unrepresentable FILETIME value {ft}")

        ansi_path = _decode_ansi(ansi_name)
        uni_path = _decode_utf16(raw[0x118:0x118 + 520]) if has_unicode else ""

        if uni_path:
            rec.original_path = uni_path
            if ansi_path and not rec.active:
                rec.warnings.append("entry removed from bin (ANSI name cleared)")
        elif ansi_path:
            rec.original_path = ansi_path
        else:
            rec.warnings.append("no recoverable path in record")

        if not rec.drive:
            rec.drive = _drive_of(rec.original_path)
        out.append(rec)

    if tail:
        trailing = RecycleRecord(source=source, source_kind=kind, format_version=fmt)
        trailing.parse_error = (
            f"{tail} trailing bytes after {n_full} records "
            f"(record size {rec_size}) - file may be truncated"
        )
        out.append(trailing)

    if not out:
        empty = RecycleRecord(source=source, source_kind=kind, format_version=fmt)
        empty.parse_error = "no records found"
        out.append(empty)
    return out


def _drive_of(path: str) -> str:
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return path[0].upper() + ":"
    return ""


def parse_info2_file(path) -> list[RecycleRecord]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        err = RecycleRecord(source=str(path), source_kind="INFO2", format_version="?")
        err.parse_error = f"cannot read: {e}"
        return [err]
    return parse_info2_bytes(data, source=str(path))
