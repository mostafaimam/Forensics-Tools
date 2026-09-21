"""Tie discovery, classification, flattening, and flagging together."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloud_azuread.discover import find
from cloud_azuread.flags import flag_audit, flag_new_country, flag_signin
from cloud_azuread.flatten import flatten_audit, flatten_signin
from cloud_azuread.records import classify, read_records


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
        res.warnings.append("no Entra ID log export (.json/.json.gz) found")
        return res
    for f in files:
        try:
            for record in read_records(f):
                if not isinstance(record, dict):
                    continue
                kind = classify(record)
                if kind == "signin":
                    row = flatten_signin(record, str(f))
                    row["notable"] = flag_signin(row)
                elif kind == "audit":
                    row = flatten_audit(record, str(f))
                    row["notable"] = flag_audit(row)
                else:
                    continue
                res.rows.append(row)
        except OSError as e:
            res.warnings.append(f"{f}: {e}")
    flag_new_country(res.rows)
    if not res.rows:
        res.warnings.append("no sign-in or audit records recognised in "
                            "the discovered file(s)")
    return res
