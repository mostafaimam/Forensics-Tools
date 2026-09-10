"""Parse InstallHistory.plist and the receipt plists, then correlate."""

from __future__ import annotations

import datetime as _dt
import plistlib
from dataclasses import dataclass, field
from pathlib import Path

from macos_installhistory import flags as _flags

_EXPECTED_PROCS = {"softwareupdated", "installer", "Installer",
                   "storedownloadd", "package_script_service",
                   "PackageKit", "installd", "system_installd", "OSInstaller",
                   "macOS Installer", "Software Update", "com.apple.dt.Xcode"}


def _iso(v) -> str:
    if isinstance(v, _dt.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=_dt.timezone.utc)
        return v.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(v or "")


@dataclass
class Record:
    kind: str                  # history | receipt
    date: str
    name: str
    version: str
    package_ids: list
    process: str
    content_type: str
    prefix: str
    pkg_file: str
    source: str
    correlated: bool = False
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "kind": self.kind, "date": self.date, "name": self.name,
            "version": self.version,
            "package_ids": ",".join(self.package_ids),
            "process": self.process, "content_type": self.content_type,
            "prefix": self.prefix, "pkg_file": self.pkg_file,
            "correlated": "yes" if self.correlated else "",
            "source": self.source, "notable": ";".join(self.notable),
        }


def parse_history(data: bytes, source: str) -> list[Record]:
    out: list[Record] = []
    try:
        arr = plistlib.loads(data)
    except Exception:                            # noqa: BLE001
        return out
    for e in arr if isinstance(arr, list) else []:
        if not isinstance(e, dict):
            continue
        out.append(Record(
            kind="history", date=_iso(e.get("date")),
            name=str(e.get("displayName", "") or ""),
            version=str(e.get("displayVersion", "") or ""),
            package_ids=[str(x) for x in (e.get("packageIdentifiers")
                                          or [])],
            process=str(e.get("processName", "") or ""),
            content_type=str(e.get("contentType", "") or ""),
            prefix="", pkg_file="", source=source))
    return out


def parse_receipt(data: bytes, source: str) -> Record | None:
    try:
        d = plistlib.loads(data)
    except Exception:                            # noqa: BLE001
        return None
    if not isinstance(d, dict) or "PackageIdentifier" not in d:
        return None
    return Record(
        kind="receipt", date=_iso(d.get("InstallDate")),
        name=str(d.get("PackageIdentifier", "") or ""),
        version=str(d.get("PackageVersion", "") or ""),
        package_ids=[str(d.get("PackageIdentifier", "") or "")],
        process=str(d.get("InstallProcessName", "") or ""),
        content_type="", prefix=str(d.get("InstallPrefixPath", "") or ""),
        pkg_file=str(d.get("PackageFileName", "") or ""),
        source=source)


@dataclass
class Result:
    records: list = field(default_factory=list)
    history_count: int = 0
    receipt_count: int = 0
    errors: list = field(default_factory=list)


def collect(root: str) -> Result:
    res = Result()
    r = Path(root)

    hist_paths = []
    if r.is_file() and r.name == "InstallHistory.plist":
        hist_paths = [r]
    elif r.is_dir():
        hist_paths = [p for p in r.rglob("InstallHistory.plist")
                      if p.is_file()]

    for hp in hist_paths:
        try:
            recs = parse_history(hp.read_bytes(), str(hp))
        except OSError as e:
            res.errors.append(f"{hp}: {e}")
            continue
        res.records += recs
        res.history_count += len(recs)

    receipt_dirs = []
    if r.is_dir():
        for rel in ("private/var/db/receipts", "var/db/receipts",
                    "System/Library/Receipts", "Library/Receipts"):
            d = r / rel
            if d.is_dir():
                receipt_dirs.append(d)
    for d in receipt_dirs:
        for p in sorted(d.glob("*.plist")):
            try:
                rec = parse_receipt(p.read_bytes(), str(p))
            except OSError as e:
                res.errors.append(f"{p}: {e}")
                continue
            if rec is not None:
                res.records.append(rec)
                res.receipt_count += 1

    # correlate on package id
    hist_ids: set[str] = set()
    for rec in res.records:
        if rec.kind == "history":
            hist_ids.update(rec.package_ids)
    recpt_ids = {rec.package_ids[0] for rec in res.records
                 if rec.kind == "receipt" and rec.package_ids}
    for rec in res.records:
        if rec.kind == "history":
            rec.correlated = any(i in recpt_ids for i in rec.package_ids)
        else:
            rec.correlated = bool(rec.package_ids and
                                  rec.package_ids[0] in hist_ids)
        rec.notable = _flags.flag(rec, _EXPECTED_PROCS)

    res.records.sort(key=lambda x: (x.date or "", x.kind, x.name))
    return res
