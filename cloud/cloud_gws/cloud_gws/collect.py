"""Tie discovery, activity reading, flattening, and flagging together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_gws.discover import find
from cloud_gws.flags import flag_event
from cloud_gws.flatten import flatten_activity
from cloud_gws.records import read_activities


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
        res.warnings.append("no Workspace audit export (.json/.json.gz) "
                            "found")
        return res
    for f in files:
        try:
            for activity in read_activities(f):
                if not isinstance(activity, dict):
                    continue
                for row in flatten_activity(activity, str(f)):
                    row["notable"] = flag_event(row)
                    res.rows.append(row)
        except OSError as e:
            res.warnings.append(f"{f}: {e}")
    if not res.rows:
        res.warnings.append("no events found in the discovered file(s)")
    return res
