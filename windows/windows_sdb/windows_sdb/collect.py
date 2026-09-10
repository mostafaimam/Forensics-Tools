"""Find .sdb files under a path, parse and flag them."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from windows_sdb import flags
from windows_sdb.extract import extract
from windows_sdb.sdb import Sdb, SdbError


@dataclass
class Result:
    rows: list = field(default_factory=list)
    databases: int = 0
    errors: list = field(default_factory=list)
    sources: set = field(default_factory=set)


def _is_system_db(path: str, db_name: str) -> bool:
    p = path.lower()
    return p.endswith("sysmain.sdb") or p.endswith("msimain.sdb") or \
        p.endswith("drvmain.sdb") or "\\apppatch\\" in p


def collect(paths) -> Result:
    res = Result()
    targets: list[Path] = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() == ".sdb":
                    targets.append(f)

    for f in targets:
        try:
            data = f.read_bytes()
        except OSError as e:
            res.errors.append(f"{f}: {e}")
            continue
        try:
            sdb = Sdb(data)
        except SdbError as e:
            res.errors.append(f"{f}: {e}")
            continue
        res.databases += 1
        res.sources.add(str(f))
        recs = extract(sdb, str(f))
        db_name = next((r.name for r in recs if r.kind == "database"), "")
        is_sys = _is_system_db(str(f), db_name)
        for rec in recs:
            n, s = flags.classify(rec, is_system_db=is_sys)
            rec.notable = n
            row = rec.row()
            row["severity"] = s
            res.rows.append(row)

    order = {"database": 0, "exe": 1, "patch": 2, "shim": 3, "layer": 4,
             "file": 5}
    res.rows.sort(key=lambda r: (order.get(r["kind"], 9),
                                 -flags._ORDER.get(r.get("severity"), 0),
                                 r.get("name", "")))
    return res
