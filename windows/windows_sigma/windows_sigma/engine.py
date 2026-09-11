"""Load normalised rows, flatten their fields, and run rules over them."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

from windows_sigma import condition as _cond
from windows_sigma import logsource as _ls
from windows_sigma.match import selection_matches

_PS_ALIASES = {
    "ScriptBlockText": "text", "ScriptBlockId": "scriptblock_id",
    "User": "user", "Computer": "computer", "Path": "path",
    "HostApplication": "host_app", "EventID": "event_id",
}


def _load_rows(path: str) -> list[dict]:
    p = Path(path)
    text = p.read_text(encoding="utf-8-sig", errors="replace")
    if p.suffix.lower() == ".jsonl":
        return [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    if text.lstrip()[:1] in ("[", "{"):
        data = json.loads(text)
        return data if isinstance(data, list) else data.get("rows", [])
    return [dict(r) for r in csv.DictReader(io.StringIO(text))]


def _flatten(row: dict) -> dict:
    kind = _ls.row_kind(row)
    fields = dict(row)
    if "EventId" in fields and "EventID" not in fields:
        fields["EventID"] = fields["EventId"]
    if kind == "powershell":
        for sigma_name, our_name in _PS_ALIASES.items():
            if our_name in row and sigma_name not in fields:
                fields[sigma_name] = row[our_name]
    payload = row.get("Payload")
    if payload:
        try:
            extra = json.loads(payload) if isinstance(payload, str) \
                else payload
            if isinstance(extra, dict):
                for k, v in extra.items():
                    fields.setdefault(k, v)
        except (json.JSONDecodeError, TypeError):
            pass
    return fields


@dataclass
class Hit:
    rule_title: str
    rule_id: str
    level: str
    tags: list
    row: dict
    source: str
    matched_fields: dict = field(default_factory=dict)

    def row_out(self) -> dict:
        interesting = {k: v for k, v in self.matched_fields.items()
                      if v not in (None, "")}
        return {
            "rule": self.rule_title, "rule_id": self.rule_id,
            "level": self.level, "tags": ";".join(self.tags),
            "time": self.row.get("TimeCreated") or self.row.get("time", ""),
            "source": self.source,
            "matched": "; ".join(f"{k}={v}" for k, v in
                                 list(interesting.items())[:8]),
        }


def _extract_matched(rule, fields: dict) -> dict:
    out = {}
    names = rule.fields or []
    for n in names:
        for k in fields:
            if k.lower() == n.lower():
                out[n] = fields[k]
                break
    if not names:
        for sel in rule.selections.values():
            if isinstance(sel, dict):
                for k in sel:
                    name = k.split("|")[0]
                    for fk in fields:
                        if fk.lower() == name.lower():
                            out[name] = fields[fk]
                            break
    return out


def run_rules(rules, row_paths, *, min_level="informational") -> list[Hit]:
    levels = ["informational", "low", "medium", "high", "critical"]
    min_idx = levels.index(min_level) if min_level in levels else 0
    hits: list[Hit] = []
    for path in row_paths:
        try:
            rows = _load_rows(path)
        except (OSError, json.JSONDecodeError):
            continue
        for row in rows:
            fields = _flatten(row)
            for rule in rules:
                if not _ls.applies(rule.logsource, row):
                    continue
                results = {name: selection_matches(fields, sel)
                          for name, sel in rule.selections.items()}
                try:
                    ok = _cond.evaluate(rule.condition_ast, results,
                                        rule.selection_names())
                except _cond.ConditionError:
                    ok = False
                if ok:
                    lvl_idx = levels.index(rule.level) if rule.level in \
                        levels else 2
                    if lvl_idx < min_idx:
                        continue
                    hits.append(Hit(
                        rule_title=rule.title, rule_id=rule.id,
                        level=rule.level, tags=rule.tags, row=row,
                        source=path,
                        matched_fields=_extract_matched(rule, fields)))
    return hits
