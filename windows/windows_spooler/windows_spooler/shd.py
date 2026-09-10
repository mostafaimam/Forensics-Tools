"""Parse a print-spooler ``.shd`` shadow (job header) file.

The SHD layout has shifted across Windows versions, but two things are
stable enough to rely on: (1) it begins with a table of u32 byte-offsets
into the file, each pointing at a NUL-terminated UTF-16LE string
(printer, machine, user, document, datatype, print processor, parameters,
driver), and (2) a ``SYSTEMTIME`` for the submit time appears as a run of
eight little-endian u16s with sane calendar values.  This parser reads the
offset table, resolves and classifies the strings, and locates the
SYSTEMTIME - rather than hard-coding one version's struct.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime

_USER = re.compile(r"^[^\\/:*?\"<>|]{1,64}$")
_DATATYPES = {"RAW", "EMF", "TEXT", "XPS_PASS", "XPS2GDI", "NT EMF 1.008",
              "NT EMF 1.007", "NT EMF 1.006"}
_PROCESSORS = {"winprint", "hpcpp180", "PrintProc", "BJLANGE3"}


@dataclass
class ShdJob:
    source: str
    signature: str = ""
    job_id: int = 0
    printer: str = ""
    machine: str = ""
    user: str = ""
    notify_name: str = ""
    document: str = ""
    datatype: str = ""
    processor: str = ""
    parameters: str = ""
    driver: str = ""
    spool_file: str = ""
    submit_time: str = ""
    priority: int = 0
    total_bytes: int = 0
    strings: list = field(default_factory=list)
    parse_error: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "submit_time": self.submit_time, "job_id": self.job_id,
            "user": self.user, "machine": self.machine,
            "document": self.document, "printer": self.printer,
            "driver": self.driver, "datatype": self.datatype,
            "processor": self.processor, "priority": self.priority,
            "total_bytes": self.total_bytes, "spool_file": self.spool_file,
            "source": self.source, "notable": ";".join(self.notable),
        }


def _wstr(data: bytes, off: int, limit: int = 1024) -> str:
    if off <= 0 or off + 2 > len(data) or off % 2:
        return ""
    end = off
    while end + 1 < len(data) and end - off < limit * 2:
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    try:
        s = data[off:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return ""
    return s if s.isprintable() else ""


def _find_systemtime(data: bytes) -> str:
    best = ""
    for p in range(0, min(len(data) - 16, 0x400), 2):
        y, mo, dow, d, h, mi, s, ms = struct.unpack_from("<8H", data, p)
        if not (2000 <= y <= 2035 and 1 <= mo <= 12 and 1 <= d <= 31
                and dow <= 6 and h <= 23 and mi <= 59 and s <= 60
                and ms <= 999):
            continue
        try:
            best = datetime(y, mo, d, h, mi, min(s, 59)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            return best
        except ValueError:
            continue
    return best


def _classify(strings: list[tuple[int, str]], job: ShdJob):
    for _off, s in strings:
        st = s.strip()
        if not st:
            continue
        if st in _DATATYPES or st.upper().startswith("NT EMF"):
            job.datatype = job.datatype or st
        elif st in _PROCESSORS or st.lower() == "winprint":
            job.processor = job.processor or st
        elif st.startswith("\\\\"):
            job.machine = job.machine or st
        elif re.search(r"\.(spl|shd)$", st, re.I):
            job.spool_file = job.spool_file or st
        elif re.search(r"(driver|\.dll|unidrv|pscript|class driver|"
                       r"PCL|PostScript|XPS)", st, re.I) and not job.driver:
            job.driver = st
    # remaining candidates for printer / document / user
    leftovers = [s for _o, s in strings if s.strip() and s not in (
        job.datatype, job.processor, job.machine, job.spool_file,
        job.driver)]
    # printer often contains the driver/port; document is free text;
    # user is a bare token
    for s in leftovers:
        if not job.user and _USER.match(s) and "\\" not in s and \
                " " not in s and not s.lower().endswith(
                    (".pdf", ".docx", ".doc", ".txt", ".xps")):
            job.user = s
    if not job.document:
        docish = [s for s in leftovers if s != job.user]
        if docish:
            job.document = max(docish, key=len)
    if not job.printer:
        for s in leftovers:
            if s not in (job.user, job.document):
                job.printer = s
                break


# classic SHD offset-table slots (byte offset in header -> field name)
_SLOTS = [
    (0x18, "printer"), (0x1C, "machine"), (0x20, "user"),
    (0x24, "notify_name"), (0x28, "document"), (0x2C, "datatype"),
    (0x30, "processor"), (0x34, "parameters"), (0x38, "driver"),
]


def parse_shd(data: bytes, source: str) -> ShdJob:
    job = ShdJob(source=source)
    if len(data) < 0x40:
        job.parse_error = "shorter than a minimal SHD header"
        return job
    job.signature = data[:4].hex()
    job.job_id = struct.unpack_from("<I", data, 0x08)[0]
    if job.job_id > 0xFFFFFF:
        job.job_id = struct.unpack_from("<I", data, 0x04)[0]
    pr = struct.unpack_from("<I", data, 0x0C)[0]
    job.priority = pr if pr <= 99 else 0

    # 1) try the classic fixed offset table
    hits = 0
    for pos, fld in _SLOTS:
        if pos + 4 > len(data):
            continue
        (val,) = struct.unpack_from("<I", data, pos)
        if 0x20 <= val < len(data):
            s = _wstr(data, val)
            if s:
                setattr(job, fld, s)
                hits += 1

    # 2) offset table: every u32 in the first 0x100 bytes -> a string
    seen: dict[int, str] = {}
    for p in range(0x0C, 0x100, 4):
        (val,) = struct.unpack_from("<I", data, p)
        if 0x20 <= val < len(data):
            s = _wstr(data, val)
            if s and len(s) >= 1:
                seen.setdefault(val, s)
    strings = sorted(seen.items())
    job.strings = [s for _o, s in strings]
    if hits < 3:
        _classify(strings, job)
    job.submit_time = _find_systemtime(data)

    # total bytes / size field: a u32 in the header that looks like a size
    for p in (0x10, 0x14, 0x18, 0x1C, 0x38, 0x3C):
        (v,) = struct.unpack_from("<I", data, p)
        if 0 < v < 0x40000000 and v not in seen:
            job.total_bytes = job.total_bytes or v
    return job
