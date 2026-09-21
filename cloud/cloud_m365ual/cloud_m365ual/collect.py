"""Tie discovery, record reading, flattening, and flagging together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_m365ual.discover import find
from cloud_m365ual.flags import flag_mass_download, flag_record
from cloud_m365ual.flatten import flatten
from cloud_m365ual.records import read_records


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def collect(targets: list[str]) -> Result:
    res = Result()
    files = []
    for t in targets:
        files.extend(find(t))
    if not files:
        res.warnings.append("no UAL export (.json/.csv, optionally .gz) "
                            "found")
        return res
    for f in files:
        try:
            for record in read_records(f):
                if not isinstance(record, dict) or not record:
                    continue
                row = flatten(record, str(f))
                row["notable"] = flag_record(row, record)
                res.rows.append(row)
        except OSError as e:
            res.warnings.append(f"{f}: {e}")
    flag_mass_download(res.rows)
    if not res.rows:
        res.warnings.append("no records found in the discovered file(s)")
    return res
