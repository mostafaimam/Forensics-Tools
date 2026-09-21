"""Tie discovery, record reading, flattening, and flagging together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_cloudtrail.discover import find
from cloud_cloudtrail.flags import flag_delete_bursts, flag_record
from cloud_cloudtrail.flatten import COLUMNS
from cloud_cloudtrail.flatten import flatten as _flatten
from cloud_cloudtrail.records import read_records


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
        res.warnings.append("no CloudTrail .json/.json.gz file found")
        return res
    for f in files:
        try:
            for record in read_records(f):
                if not isinstance(record, dict):
                    continue
                row = _flatten(record, str(f))
                row["notable"] = flag_record(row, record)
                res.rows.append(row)
        except OSError as e:
            res.warnings.append(f"{f}: {e}")
    flag_delete_bursts(res.rows)
    if not res.rows:
        res.warnings.append("no records found in the discovered file(s)")
    return res
