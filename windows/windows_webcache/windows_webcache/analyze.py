"""Open WebCacheV01.dat, walk every container, normalise the entries."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from windows_webcache import flags as _flags
from windows_webcache.esedb import EseDatabase, EseError
from windows_webcache.esedb.coltypes import filetime

_CONTAINER_RE = re.compile(r"^Container_\d+$")
_VISITED = re.compile(r"^(?:Visited|:\d{4}\d*):\s*([^@]+@)?", re.I)
_COOKIE = re.compile(r"^Cookie:\s*([^@]+)@(.+)$", re.I)


@dataclass
class Entry:
    container: str
    entry_type: str          # history | cookie | content | download | dom | other
    url: str
    filename: str
    size: int
    access_count: int
    modified: str
    accessed: str
    expiry: str
    sync: str
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "container": self.container, "entry_type": self.entry_type,
            "url": self.url, "filename": self.filename, "size": self.size,
            "access_count": self.access_count, "modified": self.modified,
            "accessed": self.accessed, "expiry": self.expiry,
            "sync": self.sync, "source": self.source,
            "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    entries: list = field(default_factory=list)
    containers: dict = field(default_factory=dict)     # name -> count
    errors: list = field(default_factory=list)


def _ft(v):
    if isinstance(v, int) and v > 0:
        return filetime(v)
    return ""


def _classify(container_name: str, url: str) -> tuple[str, str]:
    low = container_name.lower()
    if "history" in low:
        m = _VISITED.match(url)
        return "history", url[m.end():] if m else url
    if "cookie" in low:
        m = _COOKIE.match(url)
        if m:
            return "cookie", m.group(2)
        return "cookie", url
    if "download" in low:
        return "download", url
    if "domstore" in low or "dom" == low[:3]:
        return "dom", url
    if "content" in low:
        return "content", url
    return "other", url


def analyze(paths) -> Result:
    res = Result()
    for path in paths:
        try:
            db = EseDatabase.from_file(path)
        except (EseError, OSError) as e:
            res.errors.append(f"{path}: {e}")
            continue
        if not db.info()["clean"]:
            res.errors.append(f"{path}: not cleanly shut down (best-effort)")

        id_to_name: dict[int, str] = {}
        try:
            for rec in db.table("Containers").records():
                cid = rec.get("ContainerId")
                nm = rec.get("Name") or ""
                if cid is not None:
                    id_to_name[int(cid)] = str(nm)
        except EseError:
            pass

        for tname in db.all_table_names():
            if not _CONTAINER_RE.match(tname):
                continue
            try:
                table = db.table(tname)
            except EseError as e:
                res.errors.append(f"{tname}: {e}")
                continue
            have = {c.name for c in table.columns}
            for rec in table.records():
                cid = rec.get("ContainerId")
                cname = id_to_name.get(int(cid), tname) if cid is not None \
                    else tname
                url = str(rec.get("Url") or "").strip()
                if not url:
                    continue
                etype, clean_url = _classify(cname, url)
                e = Entry(
                    container=cname, entry_type=etype, url=clean_url,
                    filename=str(rec.get("Filename") or ""),
                    size=int(rec.get("FileSize") or rec.get(
                        "CacheEntryFileSize") or 0),
                    access_count=int(rec.get("AccessCount") or 0),
                    modified=_ft(rec.get("ModifiedTime")),
                    accessed=_ft(rec.get("AccessedTime")),
                    expiry=_ft(rec.get("ExpiryTime")),
                    sync=_ft(rec.get("SyncTime")),
                    source=str(path))
                e.notable = _flags.flag(e)
                res.entries.append(e)
                res.containers[cname] = res.containers.get(cname, 0) + 1

    res.entries.sort(key=lambda e: (e.accessed or e.modified or "",
                                    e.container))
    return res
