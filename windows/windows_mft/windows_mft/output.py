from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from windows_mft.ntfs.attributes import iso_utc
from windows_mft.ntfs.mft import Entry, Mft
from windows_mft.ntfs.usn import UsnRecord

MFT_COLUMNS = [
    "entry", "sequence", "state", "type", "path", "name", "extension",
    "parent_entry", "logical_size", "hard_links", "is_resident",
    "has_ads", "ads_names", "fixup_ok",
    "si_created_utc", "si_modified_utc", "si_mft_modified_utc", "si_accessed_utc",
    "fn_created_utc", "fn_modified_utc", "fn_mft_modified_utc", "fn_accessed_utc",
    "timestomp", "timestomp_reasons",
]

USN_COLUMNS = [
    "usn", "timestamp_utc", "file_entry", "file_sequence", "parent_entry",
    "name", "reasons", "source_info", "file_attributes",
]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _mft_row(mft: Mft, e: Entry) -> dict:
    si, fn = e.si, e.fn
    resident = any(s.name == "" and s.resident for s in e.streams)
    return {
        "entry": e.number,
        "sequence": e.sequence,
        "state": "allocated" if e.in_use else "deleted",
        "type": "dir" if e.is_directory else "file",
        "path": mft.full_path(e),
        "name": e.name,
        "extension": e.extension,
        "parent_entry": e.parent_entry,
        "logical_size": e.logical_size,
        "hard_links": e.hard_links,
        "is_resident": "yes" if resident else "no",
        "has_ads": "yes" if e.has_ads else "no",
        "ads_names": " | ".join(e.ads_names),
        "fixup_ok": "yes" if e.fixup_ok else "no",
        "si_created_utc": iso_utc(si.created) if si else "",
        "si_modified_utc": iso_utc(si.modified) if si else "",
        "si_mft_modified_utc": iso_utc(si.mft_modified) if si else "",
        "si_accessed_utc": iso_utc(si.accessed) if si else "",
        "fn_created_utc": iso_utc(fn.created) if fn else "",
        "fn_modified_utc": iso_utc(fn.modified) if fn else "",
        "fn_mft_modified_utc": iso_utc(fn.mft_modified) if fn else "",
        "fn_accessed_utc": iso_utc(fn.accessed) if fn else "",
        "timestomp": "yes" if e.timestomp.any else "no",
        "timestomp_reasons": "; ".join(e.timestomp.reasons()),
    }


def write_mft_csv(mft: Mft, entries: list[Entry], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=MFT_COLUMNS, dialect="excel")
        w.writeheader()
        for e in entries:
            w.writerow({k: _san(v) for k, v in _mft_row(mft, e).items()})


def write_mft_json(mft: Mft, entries: list[Entry], path: Path) -> None:
    path.write_text(json.dumps([_mft_row(mft, e) for e in entries], indent=2),
                    encoding="utf-8")


def write_bodyfile(mft: Mft, entries: list[Entry], path: Path) -> None:
    """3.x bodyfile format using the $SI timestamps."""
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for e in entries:
            si = e.si
            if si is None:
                continue
            def ep(dt):
                return int(dt.timestamp()) if dt else 0
            name = (mft.full_path(e) or e.name).replace("|", "/")
            fh.write(f"0|{name} (entry {e.number}{'' if e.in_use else ', deleted'})"
                     f"|{e.number}|0|0|0|{e.logical_size}"
                     f"|{ep(si.accessed)}|{ep(si.modified)}"
                     f"|{ep(si.mft_modified)}|{ep(si.created)}\n")


def _usn_row(r: UsnRecord) -> dict:
    return {
        "usn": r.usn,
        "timestamp_utc": iso_utc(r.timestamp),
        "file_entry": r.file_entry,
        "file_sequence": r.file_sequence,
        "parent_entry": r.parent_entry,
        "name": r.name,
        "reasons": "; ".join(r.reason_names()),
        "source_info": r.source_info,
        "file_attributes": "; ".join(r.attribute_names()),
    }


def write_usn_csv(records, path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=USN_COLUMNS, dialect="excel")
        w.writeheader()
        for r in records:
            w.writerow({k: _san(v) for k, v in _usn_row(r).items()})


def write_usn_json(records, path: Path) -> None:
    path.write_text(json.dumps([_usn_row(r) for r in records], indent=2),
                    encoding="utf-8")


def render_mft_table(mft: Mft, entries: list[Entry], limit: int = 200) -> str:
    out = io.StringIO()
    cols = [("entry", 8), ("state", 10), ("type", 5), ("logical_size", 12),
            ("timestomp", 10), ("path", 55)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 105 + "\n")
    for e in entries[:limit]:
        r = _mft_row(mft, e)
        out.write("  ".join(
            (str(r[h])[: w - 1] + "…") if len(str(r[h])) > w
            else str(r[h]).ljust(w) for h, w in cols).rstrip() + "\n")
    if len(entries) > limit:
        out.write(f"... {len(entries) - limit} more (use --csv)\n")
    return out.getvalue()
