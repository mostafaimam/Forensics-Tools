"""Carve BITS job / file records out of a qmgr database.

Works on both the legacy ``qmgr0.dat`` / ``qmgr1.dat`` queue files and the
modern ESE ``qmgr.db`` - in both the job and file structures are stored the
same way, so this scans the raw bytes rather than relying on a container
format or a file-header magic (which differs across builds).

A **file entry** is three length-prefixed UTF-16LE strings in a row:

    u32 char-count, dest  (local path,  ``X:\\...`` or ``\\\\...``)
    u32 char-count, url   (``http(s)://`` / ``ftp://``)
    u32 char-count, tmp   (BITxxxx.tmp scratch file)   [optional]

followed by two u64 byte counts (download size / bytes transferred,
``0xFFFFFFFFFFFFFFFF`` = unknown).  Job metadata (name, description, owner
SID, state, create / modify FILETIMEs) sits just before the first file of
the job; each file is attributed to the nearest preceding job marker.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MIN_FT = int((datetime(2010, 1, 1, tzinfo=timezone.utc) - _EPOCH)
              .total_seconds() * 10_000_000)
_MAX_FT = int((datetime(2040, 1, 1, tzinfo=timezone.utc) - _EPOCH)
              .total_seconds() * 10_000_000)

_LOCAL = re.compile(r"^(?:[A-Za-z]:\\|\\\\[^\\]|\\Device\\)")
_URL = re.compile(r"^(?:https?|ftp)://", re.I)
_SID = re.compile(r"^S-1-\d+(?:-\d+){1,15}$")
_STATES = {0: "queued", 1: "connecting", 2: "transferring", 3: "suspended",
           4: "error", 5: "transient-error", 6: "transferred",
           7: "acknowledged", 8: "cancelled"}
_TYPES = {0: "download", 1: "upload", 2: "upload-reply"}


def _ft(v: int) -> str:
    if not (_MIN_FT <= v <= _MAX_FT):
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


def _wstr_at(buf: bytes, pos: int, *, maxchars=4096):
    """Read a u32-char-count-prefixed UTF-16LE string at pos."""
    if pos + 4 > len(buf):
        return None
    n = struct.unpack_from("<I", buf, pos)[0]
    if n == 0 or n > maxchars:
        return None
    end = pos + 4 + n * 2
    if end > len(buf):
        return None
    raw = buf[pos + 4:end]
    if raw[-2:] == b"\x00\x00":
        raw = raw[:-2]
    try:
        s = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if "\x00" in s or any(ord(c) < 9 for c in s):
        return None
    return s, end


@dataclass
class BitsFile:
    job_name: str = ""
    job_id: str = ""
    job_type: str = ""
    state: str = ""
    owner: str = ""
    url: str = ""
    dest: str = ""
    tmp_file: str = ""
    download_size: int = -1
    transfer_size: int = -1
    ctime: str = ""
    mtime: str = ""
    offset: int = 0
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "ctime": self.ctime, "mtime": self.mtime,
            "job_name": self.job_name, "job_id": self.job_id,
            "type": self.job_type, "state": self.state, "owner": self.owner,
            "url": self.url, "dest": self.dest, "tmp_file": self.tmp_file,
            "download_size": self.download_size,
            "bytes_transferred": self.transfer_size,
            "offset": self.offset, "source": self.source,
            "notable": ";".join(self.notable),
        }


def _find_files(buf: bytes) -> list[BitsFile]:
    out: list[BitsFile] = []
    seen_prefix = set()
    # anchor on "://" (UTF-16LE) occurrences and walk back to the u32 prefix
    for m in re.finditer(b":\x00/\x00/\x00", buf):
        url_prefix = None
        for back in range(4, 80):
            q = m.start() - back
            if q < 0:
                break
            got = _wstr_at(buf, q, maxchars=8192)
            if got and _URL.match(got[0]) and q + 4 <= m.start() < got[1]:
                url_prefix = q
                url_s, url_end = got
                break
        if url_prefix is None or url_prefix in seen_prefix:
            continue
        seen_prefix.add(url_prefix)

        # dest string: its terminator prefix sits just before the url prefix
        dest_s = ""
        for back in range(4, 96):
            q = url_prefix - back
            if q < 0:
                break
            got = _wstr_at(buf, q)
            if got and got[1] == url_prefix and _LOCAL.match(got[0]):
                dest_s = got[0]
                break
        f = BitsFile(url=url_s, dest=dest_s, offset=url_prefix)

        # tmp file + sizes follow the url
        pos = url_end
        got = _wstr_at(buf, pos)
        if got and ("\\" in got[0] or got[0].lower().endswith(".tmp")):
            f.tmp_file, pos = got
        if pos + 16 <= len(buf):
            a, b = struct.unpack_from("<QQ", buf, pos)
            f.download_size = -1 if a == 0xFFFFFFFFFFFFFFFF else a
            f.transfer_size = -1 if b == 0xFFFFFFFFFFFFFFFF else b
        out.append(f)
    return out


def _job_markers(buf: bytes):
    """Yield (offset, name, job_id, job_type, state) for job headers."""
    markers = []
    # A job header: u32 type (0..2), u32 priority (0..3), u32 state (0..8),
    # 16-byte job_id, u32 name-count, name (utf16), u32 desc-count, desc.
    for m in re.finditer(rb"[\x00-\x02]\x00\x00\x00.\x00\x00\x00"
                         rb"[\x00-\x08]\x00\x00\x00", buf):
        off = m.start()
        jtype = buf[off]
        state = buf[off + 8]
        gid = buf[off + 12:off + 28]
        got = _wstr_at(buf, off + 28)
        if not got:
            continue
        name, nend = got
        if not name.isprintable():
            continue
        guid = _guid(gid)
        markers.append((off, name, guid, _TYPES.get(jtype, str(jtype)),
                        _STATES.get(state, str(state))))
    return markers


def _guid(b: bytes) -> str:
    if len(b) != 16:
        return ""
    d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
    d4 = b[8:10]
    d5 = b[10:16]
    return "{%08x-%04x-%04x-%s-%s}" % (d1, d2, d3, d4.hex(), d5.hex())


def _sids(buf: bytes):
    out = []
    for got_m in re.finditer(b"S\x00-\x001\x00-\x00", buf):
        p = got_m.start()
        got = _wstr_at(buf, p - 4)
        if got and _SID.match(got[0]):
            out.append((p - 4, got[0]))
    return out


def _filetimes(buf: bytes, start: int, span: int = 512):
    out = []
    end = min(len(buf) - 8, start + span)
    for p in range(max(start, 0), end, 2):
        v = struct.unpack_from("<Q", buf, p)[0]
        if _MIN_FT <= v <= _MAX_FT:
            out.append(_ft(v))
    return out


def carve(buf: bytes, source: str) -> list[BitsFile]:
    files = _find_files(buf)
    if not files:
        return []
    markers = sorted(_job_markers(buf))
    sids = sorted(_sids(buf))
    for f in files:
        prev = [mk for mk in markers if mk[0] < f.offset]
        if prev:
            off, name, guid, jtype, state = prev[-1]
            f.job_name, f.job_id, f.job_type, f.state = name, guid, jtype, state
        prev_sid = [s for s in sids if s[0] < f.offset]
        if prev_sid:
            f.owner = prev_sid[-1][1]
        fts = _filetimes(buf, f.offset, 1024)
        if fts:
            f.ctime = fts[0]
            f.mtime = fts[-1]
        f.source = source
    return files
