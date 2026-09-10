"""Locate qmgr databases under a path and carve their jobs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from windows_bits import carve, flags

_NAMES = re.compile(r"^(qmgr(\d)?\.(dat|db)|qmgr)$", re.I)
_ESE_MAGIC_OFF = 4


@dataclass
class Result:
    rows: list = field(default_factory=list)
    files_seen: int = 0
    jobs: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def _ese_blob(data: bytes) -> bytes:
    """Best-effort: pull long/text/binary cell bytes out of a qmgr.db so the
    carver sees payload even if page layout confuses a raw scan."""
    try:
        from windows_bits.esedb import EseDatabase, EseError
    except Exception:  # noqa: BLE001
        return b""
    try:
        db = EseDatabase(data)
    except (EseError, Exception):  # noqa: BLE001
        return b""
    out = bytearray()
    try:
        for tname in db.table_names:
            try:
                tbl = db.table(tname)
                for rec in tbl.records():
                    for v in rec.values():
                        if isinstance(v, (bytes, bytearray)):
                            out += v
                        elif isinstance(v, str):
                            out += v.encode("utf-16-le")
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return bytes(out)


def collect(paths) -> Result:
    res = Result()
    targets: list[Path] = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and (_NAMES.match(f.name) or
                                    f.name.lower().startswith("qmgr")):
                    targets.append(f)

    for f in targets:
        try:
            data = f.read_bytes()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        res.files_seen += 1
        res.sources.add(str(f))
        blob = data
        if data[_ESE_MAGIC_OFF:_ESE_MAGIC_OFF + 4] == b"\xef\xcd\xab\x89":
            extra = _ese_blob(data)
            if extra:
                blob = data + b"\x00" * 8 + extra
        found = carve.carve(blob, str(f))
        seen_jobs = set()
        for bf in found:
            n, s = flags.classify(bf)
            bf.notable = n
            row = bf.row()
            row["severity"] = s
            res.rows.append(row)
            if bf.job_id:
                seen_jobs.add(bf.job_id)
        res.jobs += len(seen_jobs) or (1 if found else 0)

    res.rows.sort(key=lambda r: (r.get("ctime") or r.get("mtime") or "",
                                 r.get("url", "")))
    return res
