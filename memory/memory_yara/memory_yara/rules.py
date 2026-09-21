"""Parse a practical subset of the YARA rule language.

Supported per rule: an optional ``meta:`` block (``key = "value" | number
| true|false``), a ``strings:`` block (text / hex-byte / regex patterns,
each with an ``$id``), and a ``condition:`` block (a boolean expression
over string ids, ``N of (...)``/``any of them``/``all of them``, ``#id``
match counts, and ``filesize``). See the README for exactly what is
*not* supported (nibble wildcards, hex alternation, string offsets
``@id``, module/PE-specific conditions, ``for`` loops, includes).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


class RuleSyntaxError(ValueError):
    pass


@dataclass
class StringDef:
    id: str
    kind: str                      # text | hex | regex
    raw: str
    modifiers: frozenset[str] = frozenset()


@dataclass
class Rule:
    name: str
    meta: dict = field(default_factory=dict)
    strings: list[StringDef] = field(default_factory=list)
    condition: object = None       # an AST node from conditions.py
    source: str = ""


# ---------------------------------------------------------------- rules

_RULE_HEADER = re.compile(r"\brule\s+([A-Za-z_]\w*)\s*(?::[^{]*)?\{")


def _strip_comments(text: str) -> str:
    out = []
    i, n = 0, len(text)
    while i < n:
        if text[i:i + 2] == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if text[i:i + 2] == "/*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, open_pos: int) -> int:
    depth = 0
    i = open_pos
    in_str = False
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise RuleSyntaxError("unbalanced braces in rule source")


def split_rules(text: str) -> list[tuple[str, str]]:
    text = _strip_comments(text)
    out = []
    pos = 0
    while True:
        m = _RULE_HEADER.search(text, pos)
        if not m:
            break
        open_pos = m.end() - 1
        close_pos = _find_matching_brace(text, open_pos)
        out.append((m.group(1), text[open_pos + 1:close_pos]))
        pos = close_pos + 1
    return out


_SECTION_KEYS = ("meta:", "strings:", "condition:")


def _split_sections(body: str) -> dict:
    marks = []
    for key in _SECTION_KEYS:
        idx = body.find(key)
        if idx != -1:
            marks.append((idx, key))
    marks.sort()
    sections = {}
    for i, (idx, key) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(body)
        sections[key[:-1]] = body[idx + len(key):end]
    return sections


# ---------------------------------------------------------------- meta

_META_LINE = re.compile(
    r'(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(true|false)|(-?\d+))', re.I)


def _parse_meta(text: str) -> dict:
    out = {}
    for m in _META_LINE.finditer(text):
        key, s, boolean, num = m.groups()
        if s is not None:
            out[key] = s.replace('\\"', '"')
        elif boolean is not None:
            out[key] = boolean.lower() == "true"
        else:
            out[key] = int(num)
    return out


# ---------------------------------------------------------------- strings

_STRING_LINE = re.compile(
    r'\$(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|\{([^}]*)\}|/((?:[^/\\]|\\.)*)/)'
    r'([\w\s]*)')

_VALID_MODIFIERS = {"nocase", "wide", "ascii", "fullword"}


def _parse_modifiers(tail: str) -> frozenset:
    words = {w.lower() for w in tail.split()}
    unknown = words - _VALID_MODIFIERS
    if unknown:
        raise RuleSyntaxError(f"unsupported string modifier(s): "
                              f"{', '.join(sorted(unknown))}")
    return frozenset(words)


def _parse_strings(text: str) -> list[StringDef]:
    out = []
    for m in _STRING_LINE.finditer(text):
        ident, txt, hexb, regex, tail = m.groups()
        mods = _parse_modifiers(tail or "")
        if txt is not None:
            out.append(StringDef(f"${ident}", "text",
                                 txt.replace('\\"', '"'), mods))
        elif hexb is not None:
            out.append(StringDef(f"${ident}", "hex", hexb, mods))
        else:
            out.append(StringDef(f"${ident}", "regex", regex, mods))
    return out


# ---------------------------------------------------------------- rule

def parse_rule(name: str, body: str) -> Rule:
    sections = _split_sections(body)
    meta = _parse_meta(sections.get("meta", ""))
    strings = _parse_strings(sections.get("strings", ""))
    cond_text = sections.get("condition", "").strip()
    if not cond_text:
        raise RuleSyntaxError(f"rule {name!r} has no condition")
    from memory_yara.conditions import parse_condition
    condition = parse_condition(cond_text, {s.id for s in strings})
    return Rule(name=name, meta=meta, strings=strings, condition=condition,
               source=body)


def parse_rules(text: str) -> list[Rule]:
    return [parse_rule(name, body) for name, body in split_rules(text)]
