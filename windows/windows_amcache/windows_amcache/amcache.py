r"""Parse ``Amcache.hve`` - the Application Compatibility inventory hive.

Two formats:

* **modern** (Windows 10 1607 and later) - named-value keys under
  ``Root\InventoryApplicationFile``, ``Root\InventoryApplication``,
  ``Root\InventoryDriverBinary`` (``LowerCaseLongPath``, ``FileId``, ``Size``,
  ``Publisher``, ``ProgramId``, ``LinkDate``, ...).
* **legacy** (Windows 8 / 8.1 / early 10) - numbered-value keys under
  ``Root\File\<volume-guid>\<file-id>`` and ``Root\Programs\<id>``.

Every record keeps the SHA-1 of the executable where the hive records it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from windows_amcache.hive import RegistryHive, to_text


def _norm_sha1(v) -> str:
    s = to_text(v).strip().lower()
    if s.startswith("0000") and len(s) == 44:
        s = s[4:]
    if len(s) == 40 and all(c in "0123456789abcdef" for c in s):
        return s
    return ""


def _iso(dt) -> str:
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return ""


@dataclass
class AmcacheRecord:
    category: str                 # "file" | "program" | "driver"
    key_path: str
    key_last_written: str = ""
    fields: dict = field(default_factory=dict)

    def get(self, *names, default=""):
        low = {k.lower(): v for k, v in self.fields.items()}
        for n in names:
            if n.lower() in low:
                return low[n.lower()]
        return default

    def as_row(self) -> dict:
        return {
            "category": self.category,
            "name": self.get("Name", "0", "ProductName"),
            "path": self.get("LowerCaseLongPath", "FullPath", "DriverName",
                             "15", "Path"),
            "sha1": self.get("__sha1__"),
            "size": self.get("Size", "6"),
            "publisher": self.get("Publisher", "ProgramInstanceId", "1"),
            "product": self.get("ProductName", "0"),
            "version": self.get("Version", "f", "ProductVersion"),
            "program_id": self.get("ProgramId", "100"),
            "link_date": self.get("LinkDate"),
            "install_date": self.get("InstallDate", "a"),
            "driver_company": self.get("DriverCompany"),
            "driver_signed": self.get("DriverSigned", "IsSigned"),
            "key_last_written_utc": self.key_last_written,
            "key_path": self.key_path,
        }


_MODERN_ROOTS = {
    "InventoryApplicationFile": "file",
    "InventoryApplication": "program",
    "InventoryDriverBinary": "driver",
    "InventoryApplicationShortcut": "shortcut",
}


def parse(data: bytes) -> list[AmcacheRecord]:
    hive = RegistryHive(data)
    root = hive.root()
    top = {k.name.lower(): k for k in root.subkeys()}
    # some hives nest everything under a "Root" key
    if "root" in top:
        root = top["root"]
        top = {k.name.lower(): k for k in root.subkeys()}

    records: list[AmcacheRecord] = []
    modern = any(name.lower() in top for name in _MODERN_ROOTS)
    if modern:
        for name, category in _MODERN_ROOTS.items():
            key = top.get(name.lower())
            if key:
                records.extend(_walk_modern(key, category))
    if "file" in top:
        records.extend(_walk_legacy_files(top["file"]))
    if "programs" in top:
        records.extend(_walk_legacy_programs(top["programs"]))
    return records


def _walk_modern(key, category: str, _depth: int = 0):
    if _depth > 6:
        return
    for sub in key.subkeys():
        vals = {v.name: v.data for v in sub.values() if v.name != "(default)"}
        if vals:
            rec = AmcacheRecord(
                category=category,
                key_path=sub.path,
                key_last_written=_iso(sub.last_written),
                fields={k: _clean(v) for k, v in vals.items()},
            )
            fid = vals.get("FileId") or vals.get("DriverId")
            if fid is not None:
                rec.fields["__sha1__"] = _norm_sha1(fid)
            for date_field in ("LinkDate", "DriverLastWriteTime",
                               "DriverSignedTime"):
                if date_field in rec.fields:
                    rec.fields[date_field] = _maybe_date(rec.fields[date_field])
            yield rec
        yield from _walk_modern(sub, category, _depth + 1)


def _walk_legacy_files(file_key):
    for volume in file_key.subkeys():                 # volume GUID
        for entry in volume.subkeys():                # file id
            vals = {v.name: v.data for v in entry.values()
                    if v.name != "(default)"}
            if not vals:
                continue
            rec = AmcacheRecord(
                category="file", key_path=entry.path,
                key_last_written=_iso(entry.last_written),
                fields={k: _clean(v) for k, v in vals.items()},
            )
            if "101" in vals:
                rec.fields["__sha1__"] = _norm_sha1(vals["101"])
            for k in ("11", "12", "17", "f"):
                if k in rec.fields:
                    rec.fields[k] = _maybe_date(rec.fields[k])
            yield rec


def _walk_legacy_programs(programs_key):
    for entry in programs_key.subkeys():
        vals = {v.name: v.data for v in entry.values() if v.name != "(default)"}
        if not vals:
            continue
        yield AmcacheRecord(
            category="program", key_path=entry.path,
            key_last_written=_iso(entry.last_written),
            fields={k: _clean(v) for k, v in vals.items()},
        )


# -- value normalisation ----------------------------------------------
def _clean(v):
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, list):
        return " | ".join(str(x) for x in v)
    return v


_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _maybe_date(v):
    """Amcache stores dates variously: FILETIME int, Unix int, or a string."""
    if isinstance(v, str):
        return v
    if isinstance(v, int):
        if 1_000_000_000_000_000 < v < 300_000_000_000_000_000:      # FILETIME
            try:
                from datetime import timedelta
                return _iso(_FT_EPOCH + timedelta(microseconds=v / 10))
            except (OverflowError, ValueError):
                return v
        if 1_000_000_000 < v < 4_000_000_000:                        # Unix
            try:
                return _iso(datetime.fromtimestamp(v, tz=timezone.utc))
            except (OverflowError, OSError, ValueError):
                return v
    return v
