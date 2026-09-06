"""Walk input paths, dispatch to the right parser, and enrich records with the
account SID and any matching ``$R`` / ``Dc`` content file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from windows_recycle.models import RecycleRecord
from windows_recycle.parser_i import parse_i_file
from windows_recycle.parser_info2 import parse_info2_file

_SID_RE = re.compile(r"S-1-\d+(?:-\d+){1,}", re.IGNORECASE)
_DC_RE = re.compile(r"^D[a-z](\d+)(?:\..*)?$", re.IGNORECASE)


def _sid_from_path(path: str) -> str:
    for part in os.path.normpath(path).split(os.sep):
        if _SID_RE.fullmatch(part):
            return part
    m = _SID_RE.search(path)
    return m.group(0) if m else ""


# Container folder names that begin with "$R"/"$I" but are not artefacts.
_BIN_FOLDERS = {"$recycle.bin", "$recycler"}


def _is_i_file(name: str) -> bool:
    return name[:2].lower() == "$i" and name.lower() not in _BIN_FOLDERS


def _is_r_file(name: str) -> bool:
    return name[:2].lower() == "$r" and name.lower() not in _BIN_FOLDERS


def _is_info2(name: str) -> bool:
    return name.lower() in ("info2", "info")


def _drive_of(path: str) -> str:
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return path[0].upper() + ":"
    return ""


@dataclass
class ScanResult:
    records: list[RecycleRecord]
    files_seen: int
    artefacts_parsed: int
    orphan_content: int


def scan(paths: list[str], recursive: bool = True) -> ScanResult:
    i_files: list[str] = []
    info2_files: list[str] = []
    pending_errors: list[RecycleRecord] = []
    # directory -> { content-key : (fullpath, is_dir) }
    content_index: dict[str, dict[str, tuple[str, bool]]] = {}
    files_seen = 0

    def note_content(fullpath: str) -> None:
        bucket = content_index.setdefault(os.path.dirname(fullpath), {})
        name = os.path.basename(fullpath)
        if _is_r_file(name):
            bucket["r:" + name[2:].lower()] = (fullpath, os.path.isdir(fullpath))
        else:
            m = _DC_RE.match(name)
            if m:
                bucket["dc:" + m.group(1)] = (fullpath, os.path.isdir(fullpath))

    def visit_file(fullpath: str) -> None:
        nonlocal files_seen
        files_seen += 1
        name = os.path.basename(fullpath)
        if _is_i_file(name):
            i_files.append(fullpath)
        elif _is_info2(name):
            info2_files.append(fullpath)
        elif _is_r_file(name) or _DC_RE.match(name):
            note_content(fullpath)

    for raw in paths:
        p = os.path.abspath(raw)
        if os.path.isfile(p):
            visit_file(p)
        elif os.path.isdir(p):
            if recursive:
                for root, dirs, files in os.walk(p):
                    for fn in files:
                        visit_file(os.path.join(root, fn))
                    for dn in dirs:
                        if _is_r_file(dn):
                            note_content(os.path.join(root, dn))
            else:
                with os.scandir(p) as it:
                    for e in it:
                        if e.is_file():
                            visit_file(e.path)
                        elif e.is_dir() and _is_r_file(e.name):
                            note_content(e.path)
        else:
            err = RecycleRecord(source=raw, source_kind="?", format_version="?")
            err.parse_error = "path does not exist"
            pending_errors.append(err)

    records: list[RecycleRecord] = []
    artefacts = 0
    matched_paths: set[str] = set()

    for fp in i_files:
        artefacts += 1
        rec = parse_i_file(fp)
        rec.sid = _sid_from_path(fp)
        if not rec.drive:
            rec.drive = _drive_of(rec.original_path)
        _match(rec, content_index.get(os.path.dirname(fp), {}),
               "r:" + rec.recycle_id.lower(), matched_paths)
        records.append(rec)

    for fp in info2_files:
        artefacts += 1
        bucket = content_index.get(os.path.dirname(fp), {})
        for rec in parse_info2_file(fp):
            rec.sid = _sid_from_path(fp)
            if rec.index is not None:
                _match(rec, bucket, "dc:" + str(rec.index), matched_paths)
            records.append(rec)

    records.extend(pending_errors)

    orphans = 0
    for bucket in content_index.values():
        for fullpath, is_dir in bucket.values():
            if fullpath in matched_paths:
                continue
            orphans += 1
            orec = RecycleRecord(source=fullpath, source_kind="$R",
                                 format_version="-")
            orec.content_present = True
            orec.content_path = fullpath
            orec.content_is_dir = is_dir
            orec.sid = _sid_from_path(fullpath)
            name = os.path.basename(fullpath)
            orec.recycle_id = name[2:] if _is_r_file(name) else name
            orec.warnings.append(
                "content file with no matching $I / INFO2 metadata"
            )
            records.append(orec)

    return ScanResult(records, files_seen, artefacts, orphans)


def _match(rec: RecycleRecord, bucket: dict, key: str, seen: set) -> None:
    hit = bucket.get(key)
    if hit:
        rec.content_present = True
        rec.content_path, rec.content_is_dir = hit
        seen.add(rec.content_path)
