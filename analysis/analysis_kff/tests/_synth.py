"""Hash-set fixtures in each supported distribution format."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path


def h(data: bytes) -> dict:
    return {"md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def nsrl_text(path: Path, records: list[dict]) -> Path:
    lines = ['"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode",'
             '"OpSystemCode","SpecialCode"']
    for i, r in enumerate(records):
        lines.append(f'"{r["sha1"].upper()}","{r["md5"].upper()}",'
                     f'"00000000","file{i}.dll","1024","1","1",""')
    path.write_text("\n".join(lines) + "\n")
    return path


def nsrl_sqlite(path: Path, records: list[dict]) -> Path:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, "
                "crc32 TEXT, file_name TEXT, file_size INT, package_id INT)")
    con.executemany(
        "INSERT INTO FILE VALUES (?,?,?,?,?,?,?)",
        [(r["sha256"], r["sha1"], r["md5"], "0", f"f{i}", 10, 1)
         for i, r in enumerate(records)])
    con.commit()
    con.close()
    return path


def projectvic(path: Path, records: list[dict]) -> Path:
    doc = {"odata.metadata": "x", "value": [
        {"Category": 1, "MediaSize": 10,
         "files": [{"MD5": r["md5"], "SHA1": r["sha1"]}]}
        for r in records]}
    path.write_text(json.dumps(doc))
    return path


def csv_list(path: Path, records: list[dict]) -> Path:
    lines = ["md5,sha1,notes"]
    for r in records:
        lines.append(f'{r["md5"]},{r["sha1"]},sample')
    path.write_text("\n".join(lines) + "\n")
    return path


def lines_list(path: Path, records: list[dict]) -> Path:
    out = []
    for i, r in enumerate(records):
        out.append(r["md5"] if i % 2 else f'sha256:{r["sha256"]}')
    path.write_text("\n".join(out) + "\n")
    return path
