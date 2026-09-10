"""Adapt the vendored NTFS engine to the recovery_fs backend interface."""

from __future__ import annotations

from recovery_fs.engine import Backend, FsEntry
from recovery_fs.ntfs import NtfsVolume


def _iso(v) -> str:
    if not v:
        return ""
    s = str(v)
    return s if s.endswith("Z") or "+" in s else s + "Z"


class NtfsAdapter(Backend):
    fs_name = "ntfs"

    def __init__(self, stream, offset: int = 0):
        self.vol = NtfsVolume(stream, offset)

    def entries(self, *, include_deleted=True):
        for e in self.vol.iter_entries(include_unused=include_deleted):
            if e.number < 16:
                continue          # $MFT .. $Extend system files
            path = self.vol.full_path(e)
            si = e.si
            fn = e.fn
            fe = FsEntry(
                path=path or e.name, name=e.name, is_dir=e.is_directory,
                size=e.size, allocated=e.in_use, inode=e.number, fs="ntfs",
                created=_iso(getattr(si, "created", "")
                             or getattr(fn, "created", "")),
                modified=_iso(getattr(si, "modified", "")
                              or getattr(fn, "modified", "")),
                accessed=_iso(getattr(si, "accessed", "")
                              or getattr(fn, "accessed", "")),
                changed=_iso(getattr(si, "mft_modified", "")
                             or getattr(si, "changed", "")))
            fe.extra["_entry"] = e
            yield fe

    def read(self, entry: FsEntry) -> bytes:
        e = entry.extra.get("_entry")
        if e is None:
            return b""
        return self.vol.read_file(e)
