"""Parse and apply headless filter / sort specs."""

from __future__ import annotations

import re

_OPS = [
    ("!~", lambda a, b: b.lower() not in a.lower()),
    ("~", lambda a, b: b.lower() in a.lower()),
    (">=", lambda a, b: _num(a) >= _num(b)),
    ("<=", lambda a, b: _num(a) <= _num(b)),
    ("!=", lambda a, b: a != b),
    (">", lambda a, b: _num(a) > _num(b)),
    ("<", lambda a, b: _num(a) < _num(b)),
    ("=", lambda a, b: a == b),
]


def _num(v):
    try:
        return float(str(v).replace(",", ""))
    except (TypeError, ValueError):
        return float("nan")


def parse(spec: str):
    """'col OP value' -> a predicate over a row dict."""
    for op, fn in _OPS:
        if op in spec:
            col, _, val = spec.partition(op)
            col, val = col.strip(), val.strip()

            def pred(row, col=col, val=val, fn=fn):
                if col not in row and col != "*":
                    return False
                if col == "*":
                    return any(fn(str(v), val) for v in row.values())
                try:
                    return fn(str(row.get(col, "")), val)
                except (ValueError, TypeError):
                    return False
            return pred
    # bare word -> full-text contains
    def contains(row, needle=spec.strip().lower()):
        return any(needle in str(v).lower() for v in row.values())
    return contains


def apply_filters(rows, specs, mode="and"):
    if not specs:
        return list(rows)
    preds = [parse(s) for s in specs]
    if mode == "or":
        return [r for r in rows if any(p(r) for p in preds)]
    return [r for r in rows if all(p(r) for p in preds)]


def apply_search(rows, text):
    if not text:
        return list(rows)
    low = text.lower()
    return [r for r in rows
            if any(low in str(v).lower() for v in r.values())]


_SORT_TS = re.compile(r"^\d{4}-\d\d-\d\d[ T]\d\d:\d\d")


def _sortkey(v: str):
    s = str(v)
    if _SORT_TS.match(s):
        return (0, s)
    try:
        return (1, float(s.replace(",", "")))
    except (ValueError, TypeError):
        return (2, s.lower())


def apply_sort(rows, sort_spec: str):
    """'col' or 'col:desc' or 'a,b:desc,c'."""
    if not sort_spec:
        return list(rows)
    out = list(rows)
    for part in reversed([p.strip() for p in sort_spec.split(",") if p.strip()]):
        col, _, direction = part.partition(":")
        out.sort(key=lambda r, c=col.strip(): _sortkey(r.get(c.strip(), "")),
                 reverse=direction.strip().lower().startswith("d"))
    return out
