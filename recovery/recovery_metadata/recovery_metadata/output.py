from __future__ import annotations

import csv
import hashlib
from pathlib import Path

from recovery_metadata.ntfs.attributes import iso_utc
from recovery_metadata.ntfs.volume import Entry, NtfsVolume

_COLUMNS = [
    "entry", "sequence_state", "type", "path", "size_bytes", "resident",
    "fixup_ok", "si_created_utc", "si_modified_utc", "si_accessed_utc",
    "si_mft_modified_utc", "fn_created_utc", "fn_modified_utc",
]


def _san(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


_ILLEGAL = '<>:"|?*\x00'


def _safe_relpath(path: str) -> str:
    parts = []
    for seg in path.replace("\\", "/").split("/"):
        seg = seg.strip().strip(".")
        seg = "".join("_" if c in _ILLEGAL or ord(c) < 32 else c for c in seg)
        if seg and seg not in ("", ".", ".."):
            parts.append(seg[:200])
    return "/".join(parts)


def _row(vol: NtfsVolume, e: Entry) -> dict:
    si = e.si
    fn = e.fn
    return {
        "entry": e.number,
        "sequence_state": "allocated" if e.in_use else "deleted",
        "type": "dir" if e.is_directory else "file",
        "path": vol.full_path(e),
        "size_bytes": e.size,
        "resident": "yes" if e.resident_data else ("no" if e.has_data else ""),
        "fixup_ok": "yes" if e.fixup_ok else "no",
        "si_created_utc": iso_utc(si.created) if si else "",
        "si_modified_utc": iso_utc(si.modified) if si else "",
        "si_accessed_utc": iso_utc(si.accessed) if si else "",
        "si_mft_modified_utc": iso_utc(si.mft_modified) if si else "",
        "fn_created_utc": iso_utc(fn.created) if fn else "",
        "fn_modified_utc": iso_utc(fn.modified) if fn else "",
    }


def write_listing_csv(vol: NtfsVolume, entries: list[Entry], path: Path) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLUMNS, dialect="excel")
        w.writeheader()
        for e in entries:
            w.writerow({k: _san(v) for k, v in _row(vol, e).items()})


def render_table(vol: NtfsVolume, entries: list[Entry], limit: int = 200) -> str:
    import io
    out = io.StringIO()
    cols = [("entry", 8), ("sequence_state", 10), ("type", 5),
            ("size_bytes", 12), ("path", 60)]
    out.write("  ".join(h.upper().ljust(w) for h, w in cols).rstrip() + "\n")
    out.write("-" * 100 + "\n")
    for e in entries[:limit]:
        r = _row(vol, e)
        cells = [(str(r[h])[: w - 1] + "…") if len(str(r[h])) > w
                 else str(r[h]).ljust(w) for h, w in cols]
        out.write("  ".join(cells).rstrip() + "\n")
    if len(entries) > limit:
        out.write(f"... {len(entries) - limit} more (use --csv)\n")
    return out.getvalue()


def extract_tree(vol: NtfsVolume, entries: list[Entry], out_dir: Path,
                 hashes: tuple[str, ...], logger) -> tuple[int, int]:
    manifest = (out_dir / "recovery_metadata_extracted.csv").open(
        "w", encoding="utf-8-sig", newline="")
    mw = csv.DictWriter(manifest, dialect="excel", fieldnames=[
        "entry", "state", "path", "output_path", "size_bytes", *hashes, "note"])
    mw.writeheader()
    ok = 0
    failed = 0
    skipped = 0
    for e in entries:
        if e.is_directory or not e.has_data:
            continue
        if e.number < 16 or e.fn is None:
            skipped += 1          # NTFS system metadata files ($MFT, $LogFile, ...)
            continue
        rel = _safe_relpath(vol.full_path(e)) or f"entry_{e.number}"
        sub = "deleted" if e.deleted else "allocated"
        dest = out_dir / sub / rel
        note = ""
        try:
            data = vol.read_file(e)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            digs = {a: hashlib.new(a, data).hexdigest() for a in hashes}
            ok += 1
            logger.debug("extracted %s (%d bytes)", rel, len(data))
        except Exception as exc:  # noqa: BLE001
            failed += 1
            note = f"failed: {exc}"
            data = b""
            digs = {a: "" for a in hashes}
            logger.warning("extract failed for entry %d (%s): %s",
                           e.number, rel, exc)
        mw.writerow({
            "entry": e.number, "state": sub, "path": rel,
            "output_path": str(dest) if not note else "",
            "size_bytes": len(data), **digs, "note": note,
        })
    manifest.close()
    if skipped:
        logger.info("skipped %d system / unnamed metadata entries", skipped)
    return ok, failed
