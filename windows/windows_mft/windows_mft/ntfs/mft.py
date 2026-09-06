"""Iterate the $MFT: build per-entry records, resolve full paths, list data
streams / ADS, and flag timestamp anomalies (timestomping)."""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator

from windows_mft.ntfs.attributes import (
    FileName,
    StandardInformation,
    NS_DOS,
    parse_file_name,
    parse_standard_information,
)
from windows_mft.ntfs.boot import BootSector, parse_boot_sector
from windows_mft.ntfs.record import (
    ATTR_DATA,
    ATTR_FILE_NAME,
    ATTR_STANDARD_INFORMATION,
    MftRecord,
    RecordError,
    parse_record,
)
from windows_mft.ntfs.runlist import decode_runlist

ROOT_ENTRY = 5
_SYSTEM_MAX = 15


@dataclass
class DataStream:
    name: str            # "" = default unnamed stream
    resident: bool
    size: int

    @property
    def is_ads(self) -> bool:
        return self.name != ""


@dataclass
class TimestompFlags:
    si_before_fn: bool = False          # $SI creation earlier than $FN creation
    si_sub_second_zero: bool = False    # all four $SI stamps have .0000000 frac
    si_all_equal: bool = False          # all four $SI stamps identical
    fn_after_si_modified: bool = False  # $FN modified newer than $SI modified
    nanoseconds_truncated: bool = False # $SI stamps look second-aligned

    @property
    def strong(self) -> bool:
        return self.si_before_fn or self.fn_after_si_modified

    @property
    def any(self) -> bool:
        # a strong signal, or the classic "all four $SI equal AND
        # second-aligned" pattern that timestamp-editing tools produce
        return self.strong or (self.si_all_equal and self.si_sub_second_zero)

    def reasons(self) -> list[str]:
        out = []
        if self.si_before_fn:
            out.append("$SI created < $FN created")
        if self.fn_after_si_modified:
            out.append("$FN modified newer than $SI modified")
        if self.si_all_equal and self.si_sub_second_zero:
            out.append("all four $SI timestamps identical and second-aligned")
        elif self.si_all_equal:
            out.append("all four $SI timestamps identical")
        elif self.si_sub_second_zero:
            out.append("$SI timestamps have zero sub-second precision")
        return out


@dataclass
class Entry:
    number: int
    sequence: int
    in_use: bool
    is_directory: bool
    base_reference: int
    fixup_ok: bool
    name: str
    all_names: list[FileName]
    parent_entry: int
    si: StandardInformation | None
    fn: FileName | None
    streams: list[DataStream]
    logical_size: int
    hard_links: int
    timestomp: TimestompFlags
    _record: MftRecord = field(repr=False, default=None)

    @property
    def deleted(self) -> bool:
        return not self.in_use

    @property
    def ads_names(self) -> list[str]:
        return [s.name for s in self.streams if s.is_ads]

    @property
    def has_ads(self) -> bool:
        return bool(self.ads_names)

    @property
    def extension(self) -> str:
        dot = self.name.rfind(".")
        return self.name[dot + 1:].lower() if dot > 0 else ""


def _all_equal(dts) -> bool:
    vals = [d for d in dts if d is not None]
    return len(vals) >= 2 and len(set(vals)) == 1


def _second_aligned(dt: datetime | None) -> bool:
    return dt is not None and dt.microsecond == 0


def analyse_timestomp(si: StandardInformation | None,
                      fn: FileName | None) -> TimestompFlags:
    f = TimestompFlags()
    if si is None:
        return f
    si_stamps = [si.created, si.modified, si.mft_modified, si.accessed]
    if _all_equal(si_stamps):
        f.si_all_equal = True
    if all(_second_aligned(s) for s in si_stamps if s is not None) and \
            any(s is not None for s in si_stamps):
        f.si_sub_second_zero = True
    if fn is not None:
        if si.created and fn.created and si.created < fn.created:
            f.si_before_fn = True
        if si.modified and fn.modified and fn.modified > si.modified:
            f.fn_after_si_modified = True
    return f


class Mft:
    def __init__(self, stream: io.BufferedReader, offset: int = 0) -> None:
        self._s = stream
        self._base = offset
        self._s.seek(offset)
        self.boot: BootSector = parse_boot_sector(self._s.read(512))
        self._rec_size = self.boot.bytes_per_mft_record
        self._sector = self.boot.bytes_per_sector
        self._mft_runs = self._bootstrap()
        self._path_cache: dict[int, str] = {ROOT_ENTRY: ""}

    # -- io ----------------------------------------------------------
    def _read_abs(self, offset: int, length: int) -> bytes:
        self._s.seek(self._base + offset)
        return self._s.read(length)

    def _bootstrap(self):
        raw = self._read_abs(self.boot.mft_offset, self._rec_size)
        rec = parse_record(raw, 0, self._sector)
        for a in rec.by_type(ATTR_DATA):
            if a.name == "" and a.non_resident:
                return decode_runlist(a.runlist_raw)
        raise RecordError("$MFT record 0 has no non-resident $DATA")

    def record_count(self) -> int:
        cs = self.boot.cluster_size
        return sum(r.clusters for r in self._mft_runs) * cs // self._rec_size

    def read_record_raw(self, number: int) -> bytes:
        pos = number * self._rec_size
        cs = self.boot.cluster_size
        consumed = 0
        for run in self._mft_runs:
            span = run.clusters * cs
            if pos < consumed + span:
                if run.lcn is None:
                    return b"\x00" * self._rec_size
                return self._read_abs(run.lcn * cs + (pos - consumed),
                                      self._rec_size)
            consumed += span
        raise IndexError(number)

    def get_record(self, number: int) -> MftRecord:
        return parse_record(self.read_record_raw(number), number, self._sector)

    # -- entries -----------------------------------------------------
    def _entry(self, rec: MftRecord) -> Entry:
        si = None
        for a in rec.by_type(ATTR_STANDARD_INFORMATION):
            if not a.non_resident:
                si = parse_standard_information(a.content)
                break
        names = [parse_file_name(a.content)
                 for a in rec.by_type(ATTR_FILE_NAME) if not a.non_resident]
        names = [n for n in names if n]
        primary = None
        for n in names:
            if n.namespace != NS_DOS:
                primary = n
                break
        primary = primary or (names[0] if names else None)

        streams = []
        for a in rec.by_type(ATTR_DATA):
            size = len(a.content) if not a.non_resident else a.real_size
            streams.append(DataStream(a.name, not a.non_resident, size))
        logical = 0
        for s in streams:
            if s.name == "":
                logical = s.size
        if not logical and primary:
            logical = primary.logical_size

        return Entry(
            number=rec.number,
            sequence=rec.sequence,
            in_use=rec.in_use,
            is_directory=rec.is_directory,
            base_reference=rec.base_reference,
            fixup_ok=rec.raw_ok,
            name=primary.name if primary else f"<entry-{rec.number}>",
            all_names=names,
            parent_entry=primary.parent_entry if primary else -1,
            si=si,
            fn=primary,
            streams=streams,
            logical_size=logical,
            hard_links=len(names),
            timestomp=analyse_timestomp(si, primary),
            _record=rec,
        )

    def iter_entries(self, include_deleted: bool = True,
                     include_system: bool = True) -> Iterator[Entry]:
        for number in range(self.record_count()):
            try:
                rec = self.get_record(number)
            except (RecordError, IndexError):
                continue
            if not include_deleted and not rec.in_use:
                continue
            if not include_system and number <= _SYSTEM_MAX:
                continue
            try:
                yield self._entry(rec)
            except Exception:
                continue

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
                parent = self._entry(self.get_record(entry.parent_entry))
                pp = self.full_path(parent, _depth + 1)
                path = f"{pp}/{entry.name}" if pp else entry.name
            except (RecordError, IndexError):
                path = f"?/{entry.name}"
        self._path_cache[entry.number] = path
        return path

    def read_stream(self, entry: Entry, name: str = "") -> bytes:
        rec = entry._record or self.get_record(entry.number)
        for a in rec.by_type(ATTR_DATA):
            if a.name != name:
                continue
            if not a.non_resident:
                return a.content
            return self._read_clusters(decode_runlist(a.runlist_raw), a.real_size)
        return b""

    def _read_clusters(self, runs, size):
        cs = self.boot.cluster_size
        out = bytearray()
        for r in runs:
            want = r.clusters * cs
            out += (b"\x00" * want) if r.lcn is None \
                else self._read_abs(r.lcn * cs, want)
            if len(out) >= size:
                break
        return bytes(out[:size])


class RawMft(Mft):
    """A bare, extracted ``$MFT`` file (no boot sector, no volume).

    Non-resident stream content cannot be read (there is no volume), but every
    resident attribute - which is all $MFT metadata analysis needs - works.
    """

    def __init__(self, stream, record_size: int = 1024,
                 sector_size: int = 512) -> None:
        self._s = stream
        self._base = 0
        head = stream.read(64)
        if head[:4] not in (b"FILE", b"BAAD"):
            raise ValueError("does not start with an MFT 'FILE' record")
        self._rec_size = _detect_record_size(head) or record_size
        self._sector = sector_size
        stream.seek(0, io.SEEK_END)
        self._size = stream.tell()
        stream.seek(0)
        self._path_cache = {ROOT_ENTRY: ""}
        self.boot = None

    def record_count(self) -> int:
        return self._size // self._rec_size

    def read_record_raw(self, number: int) -> bytes:
        self._s.seek(number * self._rec_size)
        return self._s.read(self._rec_size)

    def read_stream(self, entry: Entry, name: str = "") -> bytes:
        rec = entry._record or self.get_record(entry.number)
        for a in rec.by_type(ATTR_DATA):
            if a.name == name and not a.non_resident:
                return a.content
        return b""


def _detect_record_size(head: bytes) -> int | None:
    import struct
    try:
        alloc = struct.unpack_from("<I", head, 28)[0]
    except struct.error:
        return None
    return alloc if alloc in (1024, 2048, 4096) else None


def open_mft(source, offset: int = 0):
    """Open *source* as an NTFS volume image (with optional ``offset``), or,
    if it has no boot sector, as a bare extracted ``$MFT`` file."""
    from windows_mft.ntfs.boot import NotNtfsError

    fh = open(source, "rb", buffering=1024 * 1024)
    try:
        return Mft(fh, offset)
    except NotNtfsError:
        fh.seek(0)
        return RawMft(fh)
