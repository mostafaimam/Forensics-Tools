"""Discover Defender artefacts under a path and build one timeline."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from windows_defender import defevtx, flags, hivecfg, mplog
from windows_defender.quarantine import read_entries

_MPLOG = re.compile(r"MPLog.*\.log$", re.I)
_DEF_EVTX = re.compile(r"(Windows[ _]?Defender.*Operational|"
                       r"Microsoft-Windows-Windows Defender)\.evtx$", re.I)
_REGF_MAGIC = b"regf"


@dataclass
class Result:
    rows: list = field(default_factory=list)
    mplogs: int = 0
    evtx_files: int = 0
    quarantine_entries: int = 0
    hives: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def _looks_like_software_hive(f: Path) -> bool:
    n = f.name.lower()
    if n in ("software", "software.hiv") or n.endswith((".hive", ".hiv")) \
            or "software" in n:
        try:
            with f.open("rb") as fh:
                return fh.read(4) == _REGF_MAGIC
        except OSError:
            return False
    return False


def _finalise(res: Result):
    for r in res.rows:
        n, s = flags.classify(r)
        r["notable"] = ";".join(n)
        r["severity"] = s
    res.rows.sort(key=lambda r: (r.get("time") or "", r.get("kind", "")))


def collect(paths, *, want_quarantine=True) -> Result:
    res = Result()
    for path in paths:
        p = Path(path)
        files: list[Path] = []
        qdirs: list[Path] = []
        if p.is_file():
            files = [p]
        elif p.is_dir():
            if (p / "Entries").is_dir() or p.name.lower() == "quarantine":
                qdirs.append(p)
            for f in p.rglob("*"):
                if f.is_dir() and f.name.lower() == "quarantine":
                    qdirs.append(f)
                elif f.is_file():
                    files.append(f)

        for f in files:
            try:
                if _MPLOG.search(f.name):
                    res.mplogs += 1
                    res.sources.add(str(f))
                    raw = f.read_bytes()
                    if raw[:2] == b"\xff\xfe":
                        txt = raw.decode("utf-16-le", "replace")
                    else:
                        txt = raw.decode("utf-8", "replace")
                    for e in mplog.parse_mplog(txt, str(f)):
                        res.rows.append(e.row())
                elif _DEF_EVTX.search(f.name):
                    res.evtx_files += 1
                    res.sources.add(str(f))
                    evs, errs = defevtx.parse_defender_evtx(
                        f.read_bytes(), str(f))
                    res.errors.extend(errs)
                    for e in evs:
                        res.rows.append(e.row())
                elif _looks_like_software_hive(f):
                    res.hives += 1
                    res.sources.add(str(f))
                    for c in hivecfg.parse_software_hive(
                            f.read_bytes(), str(f)):
                        res.rows.append(c.row())
            except OSError as e:
                res.errors.append(f"{f}: {e}")

        if want_quarantine:
            for q in qdirs:
                res.sources.add(str(q))
                for ent in read_entries(q):
                    res.quarantine_entries += 1
                    for row in ent.rows():
                        res.rows.append(row)

    _finalise(res)
    return res
