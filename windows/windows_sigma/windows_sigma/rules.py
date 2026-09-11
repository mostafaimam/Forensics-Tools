"""Load a Sigma-shaped rule file into a Rule object."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from windows_sigma import condition as _cond
from windows_sigma import yamlmini
from windows_sigma.yamlmini import YamlError


class RuleError(ValueError):
    pass


@dataclass
class Rule:
    title: str
    id: str
    level: str
    status: str
    description: str
    logsource: dict
    selections: dict
    condition_text: str
    condition_ast: tuple
    fields: list
    tags: list
    falsepositives: list
    source: str

    def selection_names(self) -> set:
        return set(self.selections)


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def load_text(text: str, source: str = "") -> Rule:
    try:
        doc = yamlmini.load(text)
    except YamlError as e:
        raise RuleError(f"YAML parse error: {e}") from e
    if not isinstance(doc, dict) or "detection" not in doc:
        raise RuleError("not a Sigma rule (no 'detection' block)")
    det = doc["detection"]
    if "condition" not in det:
        raise RuleError("detection block has no 'condition'")
    cond_text = det["condition"]
    selections = {k: v for k, v in det.items() if k != "condition"}
    try:
        ast = _cond.parse(cond_text, set(selections))
    except _cond.ConditionError as e:
        raise RuleError(f"bad condition {cond_text!r}: {e}") from e
    return Rule(
        title=doc.get("title", "(untitled)"), id=doc.get("id", ""),
        level=str(doc.get("level", "medium")).lower(),
        status=doc.get("status", ""), description=doc.get("description", ""),
        logsource=doc.get("logsource", {}) or {}, selections=selections,
        condition_text=cond_text, condition_ast=ast,
        fields=_as_list(doc.get("fields")), tags=_as_list(doc.get("tags")),
        falsepositives=_as_list(doc.get("falsepositives")), source=source)


def load_file(path: str) -> Rule:
    return load_text(Path(path).read_text(encoding="utf-8"), source=path)


def load_dir(path: str) -> tuple[list[Rule], list[str]]:
    rules, errors = [], []
    for f in sorted(Path(path).rglob("*.yml")) + \
            sorted(Path(path).rglob("*.yaml")):
        try:
            rules.append(load_file(str(f)))
        except RuleError as e:
            errors.append(f"{f}: {e}")
    return rules, errors
