"""Open an NTFS volume image and walk the MFT: list entries, resolve full
paths, and extract file content (including deleted-but-intact files)."""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator

from recovery_metadata.ntfs.attributes import (
    FileName,
    StandardInformation,
    best_file_name,
    parse_file_name,
    parse_standard_information,
)
from recovery_metadata.ntfs.boot import BootSector, parse_boot_sector
from recovery_metadata.ntfs.record import (
    ATTR_DATA,
    ATTR_FILE_NAME,
    ATTR_STANDARD_INFORMATION,
    MftRecord,
    RecordError,
    parse_record,
)
from recovery_metadata.ntfs.runlist import Run, decode_runlist

ROOT_ENTRY = 5


@dataclass
class Entry:
    number: int
    in_use: bool
    is_directory: bool
    name: str
    parent_entry: int
    size: int
    resident_data: bool
    has_data: bool
    si: StandardInformation | None
    fn: FileName | None
    fixup_ok: bool
    _record: MftRecord = field(repr=False, default=None)

    @property
    def deleted(self) -> bool:
        return not self.in_use


class NtfsVolume:
    def __init__(self, stream: io.BufferedReader, offset: int = 0) -> None:
        self._s = stream
        self._base = offset
        self._s.seek(offset)
        self.boot: BootSector = parse_boot_sector(self._s.read(512))
        self._mft_runs: list[Run] = []
        self._record_size = self.boot.bytes_per_mft_record
        self._sector = self.boot.bytes_per_sector
        self._load_mft_self()
        self._path_cache: dict[int, str] = {ROOT_ENTRY: ""}

    # -- raw IO --------------------------------------------------------
    def _read_abs(self, offset: int, length: int) -> bytes:
        self._s.seek(self._base + offset)
        return self._s.read(length)

    def _read_clusters(self, runs: list[Run], size: int) -> bytes:
        cs = self.boot.cluster_size
        out = bytearray()
        for run in runs:
            want = run.clusters * cs
            if run.lcn is None:
                out += b"\x00" * want
            else:
                out += self._read_abs(run.lcn * cs, want)
            if len(out) >= size:
                break
        return bytes(out[:size]) if size else bytes(out)

    # -- MFT bootstrap ----------------------------------------------
    def _load_mft_self(self) -> None:
        raw = self._read_abs(self.boot.mft_offset, self._record_size)
        rec = parse_record(raw, 0, self._sector)
        for attr in rec.by_type(ATTR_DATA):
            if attr.name == "" and attr.non_resident:
                self._mft_runs = decode_runlist(attr.runlist_raw)
                return
        raise RecordError("$MFT record has no non-resident unnamed $DATA")

    @property
    def mft_size(self) -> int:
        return sum(r.clusters for r in self._mft_runs) * self.boot.cluster_size

    def record_count(self) -> int:
        return self.mft_size // self._record_size

    def read_record_raw(self, number: int) -> bytes:
        pos = number * self._record_size
        cs = self.boot.cluster_size
        out = bytearray()
        consumed = 0
        for run in self._mft_runs:
            span = run.clusters * cs
            if pos < consumed + span:
                local = pos - consumed
                if run.lcn is None:
                    return b"\x00" * self._record_size
                return self._read_abs(run.lcn * cs + local, self._record_size)
            consumed += span
        raise IndexError(f"record {number} beyond $MFT")

    def get_record(self, number: int) -> MftRecord:
        return parse_record(self.read_record_raw(number), number, self._sector)

    # -- entry enumeration ----------------------------------------
    def _to_entry(self, rec: MftRecord) -> Entry:
        si = None
        for a in rec.by_type(ATTR_STANDARD_INFORMATION):
            if not a.non_resident:
                si = parse_standard_information(a.content)
                break
        names = [parse_file_name(a.content) for a in rec.by_type(ATTR_FILE_NAME)
                 if not a.non_resident]
        names = [n for n in names if n]
        fn = best_file_name(names)

        data_attrs = [a for a in rec.by_type(ATTR_DATA) if a.name == ""]
        has_data = bool(data_attrs)
        resident = bool(data_attrs and not data_attrs[0].non_resident)
        size = 0
        if data_attrs:
            d = data_attrs[0]
            size = len(d.content) if not d.non_resident else d.real_size
        elif fn:
            size = fn.logical_size

        return Entry(
            number=rec.number,
            in_use=rec.in_use,
            is_directory=rec.is_directory,
            name=fn.name if fn else f"<no-name-{rec.number}>",
            parent_entry=fn.parent_entry if fn else -1,
            size=size,
            resident_data=resident,
            has_data=has_data,
            si=si,
            fn=fn,
            fixup_ok=rec.raw_ok,
            _record=rec,
        )

    def iter_entries(self, include_unused: bool = True) -> Iterator[Entry]:
        for number in range(self.record_count()):
            try:
                rec = self.get_record(number)
            except (RecordError, IndexError):
                continue
            if not rec.in_use and not include_unused:
                continue
            try:
                yield self._to_entry(rec)
            except Exception:
                continue

    # -- path resolution ----------------------------------------
    def full_path(self, entry: Entry, _depth: int = 0) -> str:
        if entry.number == ROOT_ENTRY:
            return ""
        if entry.number in self._path_cache:
            return self._path_cache[entry.number]
        if _depth > 256 or entry.parent_entry < 0:
            return entry.name
        if entry.parent_entry == ROOT_ENTRY:
            path = entry.name
        else:
            try:
                parent = self._to_entry(self.get_record(entry.parent_entry))
                parent_path = self.full_path(parent, _depth + 1)
                path = f"{parent_path}/{entry.name}" if parent_path else entry.name
            except (RecordError, IndexError):
                path = f"?/{entry.name}"
        self._path_cache[entry.number] = path
        return path

    # -- extraction --------------------------------------------
    def read_file(self, entry: Entry) -> bytes:
        rec = entry._record or self.get_record(entry.number)
        for attr in rec.by_type(ATTR_DATA):
            if attr.name != "":
                continue
            if not attr.non_resident:
                return attr.content
            runs = decode_runlist(attr.runlist_raw)
            return self._read_clusters(runs, attr.real_size)
        return b""
