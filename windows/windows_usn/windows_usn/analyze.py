"""Fold USN records into operations and flag them."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from windows_usn import usnparse as _u

_EXE = re.compile(r"\.(exe|dll|scr|ps1|psm1|bat|cmd|hta|vbs|js|jse|wsf|jar|"
                  r"msi|com|cpl|sys)$", re.I)


@dataclass
class Operation:
    ts: str
    op: str                  # create | rename | delete | data-write | attr
    name: str
    old_name: str
    path: str
    file_entry: int
    file_sequence: int
    parent_entry: int
    usn_first: int
    usn_last: int
    reasons: list
    attributes: list
    carved: bool
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "ts": self.ts, "op": self.op, "name": self.name,
            "old_name": self.old_name, "path": self.path,
            "file_entry": self.file_entry, "file_sequence": self.file_sequence,
            "parent_entry": self.parent_entry, "usn_first": self.usn_first,
            "usn_last": self.usn_last, "reasons": ",".join(self.reasons),
            "attributes": ",".join(self.attributes),
            "carved": "yes" if self.carved else "",
            "source": self.source, "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    operations: list = field(default_factory=list)
    records: int = 0
    carved: int = 0
    errors: list = field(default_factory=list)


def _fold(records: list[_u.UsnRecord], paths: dict[int, str]) -> list[Operation]:
    # group consecutive records with the same USN "transaction" (same file
    # entry + close timestamp), keyed by (file_entry, usn>>? ) - simplest:
    # one op per (file_entry, first_usn_of_run)
    ops: list[Operation] = []
    by_file: dict[int, list[_u.UsnRecord]] = {}
    order: list[int] = []
    for r in records:
        if r.file_entry not in by_file:
            by_file[r.file_entry] = []
            order.append(r.file_entry)
        by_file[r.file_entry].append(r)

    for fe in order:
        recs = sorted(by_file[fe], key=lambda r: r.usn)
        # split into runs closed by a CLOSE record or a big USN jump
        run: list[_u.UsnRecord] = []
        for r in recs:
            run.append(r)
            if r.reason & 0x80000000:            # CLOSE
                ops.append(_run_to_op(run, paths))
                run = []
        if run:
            ops.append(_run_to_op(run, paths))
    ops.sort(key=lambda o: (o.ts or "", o.usn_first))
    return ops


def _run_to_op(run: list[_u.UsnRecord], paths: dict[int, str]) -> Operation:
    reasons: set[str] = set()
    attrs: set[str] = set()
    old_name = ""
    name = run[-1].name
    for r in run:
        reasons.update(r.reason_names())
        attrs.update(r.attribute_names())
        if r.reason & 0x1000:                    # RENAME_OLD_NAME
            old_name = r.name
        if r.reason & 0x2000:                    # RENAME_NEW_NAME
            name = r.name
    if "FILE_CREATE" in reasons:
        op = "create"
    elif "FILE_DELETE" in reasons:
        op = "delete"
    elif "RENAME_NEW_NAME" in reasons or old_name:
        op = "rename"
    elif reasons & {"DATA_OVERWRITE", "DATA_EXTEND", "DATA_TRUNCATION"}:
        op = "data-write"
    elif reasons & {"BASIC_INFO_CHANGE", "SECURITY_CHANGE",
                    "OBJECT_ID_CHANGE"}:
        op = "attr"
    else:
        op = "change"
    pe = run[-1].parent_entry
    parent_path = paths.get(pe, "")
    full = f"{parent_path}\\{name}" if parent_path else name
    ts = next((r.iso() for r in reversed(run) if r.timestamp), "")
    return Operation(
        ts=ts, op=op, name=name, old_name=old_name, path=full,
        file_entry=run[-1].file_entry, file_sequence=run[-1].file_sequence,
        parent_entry=pe, usn_first=run[0].usn, usn_last=run[-1].usn,
        reasons=sorted(reasons), attributes=sorted(attrs),
        carved=any(r.carved for r in run))


_WRITABLE = re.compile(r"\\(users\\[^\\]+\\|appdata\\|temp\\|programdata\\|"
                       r"public\\|windows\\temp\\|perflogs\\)", re.I)


def _flag(ops: list[Operation]):
    # per-op
    for o in ops:
        if o.op == "create" and _EXE.search(o.name):
            if _WRITABLE.search(o.path) or not o.path.count("\\"):
                o.notable.append(f"executable / script created ({o.name})")
        if o.op == "attr" and "DATA_OVERWRITE" not in o.reasons and \
                "DATA_EXTEND" not in o.reasons:
            o.notable.append("attribute-only change (no data write) - review "
                             "for timestamp manipulation")
        if o.carved:
            o.notable.append("carved record (not in the live journal)")

    # create-then-delete of the same file entry, close in time
    by_entry: dict[int, list[Operation]] = {}
    for o in ops:
        by_entry.setdefault(o.file_entry, []).append(o)
    for entry, group in by_entry.items():
        kinds = [g.op for g in group]
        if "create" in kinds and "delete" in kinds:
            for g in group:
                g.notable.append("file created and deleted within this "
                                 "journal window")

    # mass-delete burst: >= 15 deletes within a 60s window
    deletes = sorted((o for o in ops if o.op == "delete" and o.ts),
                     key=lambda o: o.ts)
    for i in range(len(deletes)):
        j = i
        while j < len(deletes) and deletes[j].ts[:19] <= _plus60(deletes[i].ts):
            j += 1
        if j - i >= 15:
            for k in range(i, j):
                if "mass-delete burst" not in " ".join(deletes[k].notable):
                    deletes[k].notable.append(
                        f"mass-delete burst ({j - i} files in ~60s)")
            break


def _plus60(iso: str) -> str:
    from datetime import datetime, timedelta
    try:
        dt = datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S") + \
            timedelta(seconds=60)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return iso[:19]


def analyze(records: list[_u.UsnRecord], paths: dict[int, str] | None = None
           ) -> Result:
    res = Result()
    res.records = len(records)
    res.carved = sum(1 for r in records if r.carved)
    ops = _fold(records, paths or {})
    _flag(ops)
    res.operations = ops
    return res


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    sev = {
        "executable / script created": "high",
        "file created and deleted within this journal window": "medium",
        "mass-delete burst": "high",
        "attribute-only change": "low",
        "carved record": "low",
    }
    top = "none"
    for n in notable:
        for k, v in sev.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
