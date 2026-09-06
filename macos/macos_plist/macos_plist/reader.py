"""Load a property list (binary ``bplist00`` or XML) with forensic framing."""

from __future__ import annotations

import plistlib
from dataclasses import dataclass, field
from datetime import datetime, timezone


class PlistError(ValueError):
    pass


@dataclass
class LoadedPlist:
    source: str
    fmt: str                    # "binary" | "xml" | "unknown"
    value: object = None
    is_keyed_archive: bool = False
    parse_error: str = ""
    warnings: list = field(default_factory=list)


def detect_format(data: bytes) -> str:
    if data[:8] == b"bplist00":
        return "binary"
    head = data[:512].lstrip()
    if head.startswith(b"<?xml") or head.startswith(b"<plist") or \
            head.startswith(b"<!DOCTYPE plist"):
        return "xml"
    return "unknown"


def _is_keyed_archive(value) -> bool:
    return (isinstance(value, dict)
            and "$archiver" in value and "$objects" in value
            and "$top" in value)


def load_bytes(data: bytes, source: str = "<bytes>") -> LoadedPlist:
    fmt = detect_format(data)
    lp = LoadedPlist(source=source, fmt=fmt)
    try:
        try:
            lp.value = plistlib.loads(data, aware_datetime=True)
        except TypeError:                       # older Python without the kwarg
            lp.value = plistlib.loads(data)
    except Exception as e:  # noqa: BLE001 - plistlib raises many things
        lp.parse_error = f"{type(e).__name__}: {e}"
        return lp
    lp.is_keyed_archive = _is_keyed_archive(lp.value)
    return lp


def load_file(path) -> LoadedPlist:
    from pathlib import Path

    p = Path(path)
    try:
        data = p.read_bytes()
    except OSError as e:
        lp = LoadedPlist(source=str(p), fmt="unknown")
        lp.parse_error = f"cannot read: {e}"
        return lp
    return load_bytes(data, source=str(p))


# ---- Apple time helpers -------------------------------------------------
_COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def cocoa_to_utc(seconds: float) -> datetime | None:
    try:
        return datetime.fromtimestamp(
            _COCOA_EPOCH.timestamp() + seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def looks_like_cocoa_time(x: float) -> bool:
    # Cocoa timestamps for the last ~20 years fall roughly in this band.
    return isinstance(x, float) and 1.0e8 < x < 1.0e9
