"""Pluggable read backends for opening source files.

* :class:`LiveReader` - normal filesystem access, with a Windows
  backup-semantics fallback for files held open by another process
  (registry hives, EVTX, browser databases, ...).
* :class:`VssReader` - Windows only; creates a temporary Volume Shadow Copy
  so genuinely locked volume metadata (``$MFT``, ``$UsnJrnl:$J``, in-use
  hives) can be read consistently, then cleans the snapshot up.

An ``ImageReader`` (raw dd / E01) is planned and slots in behind the same
:class:`Reader` interface.
"""

from trace_collect.readers.base import CollectedStream, Reader, ReadError
from trace_collect.readers.live import LiveReader

__all__ = ["Reader", "CollectedStream", "ReadError", "LiveReader", "get_reader"]


def get_reader(kind: str, **kw):
    kind = kind.lower()
    if kind == "live":
        return LiveReader(**kw)
    if kind == "vss":
        from trace_collect.readers.vss import VssReader

        return VssReader(**kw)
    raise ValueError(f"unknown reader backend: {kind!r}")
