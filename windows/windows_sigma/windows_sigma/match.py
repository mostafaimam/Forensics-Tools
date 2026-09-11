"""Evaluate one Sigma selection block (field modifiers + wildcards)."""

from __future__ import annotations

import fnmatch
import re


def _norm(v) -> str:
    return "" if v is None else str(v)


def _has_glob(s: str) -> bool:
    return "*" in s or "?" in s


def _one_value_matches(field_val, want, mod: str) -> bool:
    fv = _norm(field_val)
    wv = _norm(want)
    if mod == "contains":
        return wv.lower() in fv.lower()
    if mod == "startswith":
        return fv.lower().startswith(wv.lower())
    if mod == "endswith":
        return fv.lower().endswith(wv.lower())
    if mod == "re":
        try:
            return re.search(want, fv, re.I) is not None
        except re.error:
            return False
    if mod == "gt":
        return _numeric(fv, wv, lambda a, b: a > b)
    if mod == "gte":
        return _numeric(fv, wv, lambda a, b: a >= b)
    if mod == "lt":
        return _numeric(fv, wv, lambda a, b: a < b)
    if mod == "lte":
        return _numeric(fv, wv, lambda a, b: a <= b)
    # default: exact (case-insensitive) or glob if the pattern has wildcards
    if _has_glob(wv):
        return fnmatch.fnmatch(fv.lower(), wv.lower())
    return fv.lower() == wv.lower()


def _numeric(a: str, b: str, cmp) -> bool:
    try:
        return cmp(float(a), float(b))
    except ValueError:
        return False


def field_matches(fields: dict, key: str, want) -> bool:
    parts = key.split("|")
    name = parts[0]
    mods = parts[1:]
    require_all = "all" in mods
    mods = [m for m in mods if m != "all"]
    mod = mods[0] if mods else ""

    val = None
    for k, v in fields.items():
        if k.lower() == name.lower():
            val = v
            break

    wants = want if isinstance(want, list) else [want]
    if val is None:
        return any(w is None for w in wants)
    results = [_one_value_matches(val, w, mod) for w in wants]
    return all(results) if require_all else any(results)


def selection_matches(fields: dict, selection) -> bool:
    """A selection value is a dict (AND across keys) or a list of dicts
    (OR across alternatives - each still AND across its own keys)."""
    if isinstance(selection, list):
        return any(selection_matches(fields, alt) for alt in selection)
    if not isinstance(selection, dict):
        return False
    return all(field_matches(fields, k, v) for k, v in selection.items())
