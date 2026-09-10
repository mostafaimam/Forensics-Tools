"""Turn a parsed SDB tag tree into flat records."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from windows_sdb.sdb import Sdb, as_guid

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(v) -> str:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return (_EPOCH + timedelta(microseconds=v // 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


@dataclass
class Record:
    kind: str                 # database | exe | shim | patch | layer
    name: str = ""
    detail: str = ""
    guid: str = ""
    time: str = ""
    dll: str = ""
    module: str = ""
    matches: list = field(default_factory=list)
    shims: list = field(default_factory=list)
    patches: list = field(default_factory=list)
    layers: list = field(default_factory=list)
    command_line: str = ""
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "kind": self.kind, "name": self.name, "detail": self.detail,
            "guid": self.guid, "time": self.time, "dll": self.dll,
            "module": self.module,
            "matching_files": "; ".join(self.matches),
            "shims": "; ".join(self.shims),
            "patches": "; ".join(self.patches),
            "layers": "; ".join(self.layers),
            "command_line": self.command_line,
            "source": self.source, "notable": ";".join(self.notable),
        }


def extract(sdb: Sdb, source: str) -> list[Record]:
    out: list[Record] = []
    db = sdb.root.get("DATABASE") or sdb.root
    dbid = ""
    for c in db.children:
        if c.name in ("DATABASE_ID", "DATABASE_ID2") and \
                isinstance(c.value, (bytes, bytearray)):
            dbid = as_guid(c.value)
    out.append(Record(
        kind="database", name=db.getv("NAME", "") or "(unnamed)",
        guid=dbid, time=_ft(db.getv("TIME")),
        detail=f"SDB v{sdb.major}.{sdb.minor}", source=source))

    # LIBRARY: shim + patch definitions
    lib = db.get("LIBRARY")
    if lib is not None:
        for sh in lib.all("SHIM"):
            out.append(Record(
                kind="shim", name=sh.getv("NAME", ""),
                dll=sh.getv("DLLFILE", ""), module=sh.getv("MODULE", ""),
                detail=sh.getv("DESCRIPTION", "") or "", source=source))
        for pt in lib.all("PATCH"):
            bits = pt.get("PATCH_BITS")
            n = len(bits.value) if bits is not None and \
                isinstance(bits.value, (bytes, bytearray)) else 0
            out.append(Record(
                kind="patch", name=pt.getv("NAME", ""),
                detail=f"{n} bytes of patch data", source=source))
        for fl in lib.all("FILE"):
            nm = fl.getv("NAME", "")
            if nm:
                out.append(Record(kind="file", name=nm, source=source,
                                  detail="shim target file definition"))

    # EXE entries
    for exe in db.all("EXE"):
        rec = Record(kind="exe", name=exe.getv("NAME", ""),
                     source=source, command_line=exe.getv("COMMAND_LINE", ""))
        rec.detail = " / ".join(x for x in (
            exe.getv("APP_NAME", ""), exe.getv("VENDOR", "")) if x)
        for c in exe.children:
            if c.name == "EXE_ID" and isinstance(c.value, (bytes, bytearray)):
                rec.guid = as_guid(c.value)
        for mf in exe.all("MATCHING_FILE"):
            fn = mf.getv("NAME", "") or "*"
            extra = mf.getv("COMPANY_NAME", "") or \
                mf.getv("PRODUCT_NAME", "") or ""
            rec.matches.append(f"{fn} ({extra})" if extra else fn)
        for sr in exe.all("SHIM_REF"):
            rec.shims.append(sr.getv("NAME", "") or "?")
        for pr in exe.all("PATCH_REF"):
            rec.patches.append(pr.getv("NAME", "") or "?")
        for lr in exe.all("LAYER"):
            rec.layers.append(lr.getv("NAME", "") or "?")
        out.append(rec)

    # top-level LAYER definitions
    for lay in db.all("LAYER"):
        nm = lay.getv("NAME", "")
        shims = [s.getv("NAME", "") for s in lay.all("SHIM_REF")]
        if nm:
            out.append(Record(kind="layer", name=nm, source=source,
                              shims=[s for s in shims if s]))
    return out
