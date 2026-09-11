"""A small indentation-based YAML-subset reader (Sigma rules only).

Handles block mappings, block lists (``- item`` and ``- key: value``),
scalars (quoted / bare / numbers / booleans / null), and ``---`` document
separators. No anchors, flow collections (``{}`` / ``[]``... a *simple*
inline flow list ``[a, b]`` is supported since Sigma field lists sometimes
use it), tags, or multi-line block scalars. That covers the Sigma rules in
the wild closely enough for detection purposes; anything fancier is
rejected with a clear error rather than mis-parsed.
"""

from __future__ import annotations

import re

_KV = re.compile(r"^([^:]+):\s*(.*)$")


class YamlError(ValueError):
    pass


def _scalar(tok: str):
    tok = tok.strip()
    if tok == "" or tok == "~" or tok.lower() == "null":
        return None
    if tok in ("true", "True", "TRUE"):
        return True
    if tok in ("false", "False", "FALSE"):
        return False
    if (tok[0] == tok[-1] == "'" and len(tok) >= 2) or \
            (tok[0] == tok[-1] == '"' and len(tok) >= 2):
        return tok[1:-1]
    if tok.startswith("[") and tok.endswith("]"):
        inner = tok[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x) for x in _split_flow(inner)]
    try:
        if re.match(r"^-?\d+$", tok):
            return int(tok)
        if re.match(r"^-?\d+\.\d+$", tok):
            return float(tok)
    except ValueError:
        pass
    return tok


def _split_flow(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for c in s:
        if c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        out.append(cur)
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comments(lines: list[str]) -> list[tuple[int, str]]:
    out = []
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line.strip() in ("---", "..."):
            continue
        # drop a trailing ' # comment' that isn't inside quotes
        if "#" in line:
            q = None
            cut = None
            for i, c in enumerate(line):
                if c in "'\"":
                    if q is None:
                        q = c
                    elif q == c:
                        q = None
                elif c == "#" and q is None and (i == 0 or line[i - 1] == " "):
                    cut = i
                    break
            if cut is not None:
                line = line[:cut].rstrip()
        if line.strip():
            out.append((_indent(line), line))
    return out


def _parse_block(lines: list[tuple[int, str]], pos: int, indent: int):
    """Parse a mapping or list starting at lines[pos] with indent `indent`.
    Returns (value, next_pos)."""
    if pos >= len(lines):
        return None, pos
    first_indent, first_text = lines[pos]
    if first_indent != indent:
        raise YamlError(f"unexpected indent at: {first_text!r}")

    if first_text.lstrip().startswith("- "):
        out = []
        while pos < len(lines) and lines[pos][0] == indent and \
                lines[pos][1].lstrip().startswith("- "):
            ind, text = lines[pos]
            content = text.lstrip()[2:]
            m = _KV.match(content)
            if m and not content.startswith(("'", '"')):
                key, val = m.group(1).strip(), m.group(2).strip()
                item = {}
                if val:
                    item[key] = _scalar(val)
                    pos += 1
                else:
                    pos += 1
                    sub_indent = ind + 2
                    child, pos = _parse_block(lines, pos, sub_indent) \
                        if pos < len(lines) and lines[pos][0] > ind else \
                        (None, pos)
                    item[key] = child
                # sibling key: value lines at ind+2 continuing the same item
                while pos < len(lines) and lines[pos][0] == ind + 2:
                    ind2, text2 = lines[pos]
                    m2 = _KV.match(text2)
                    if not m2:
                        break
                    k2, v2 = m2.group(1).strip(), m2.group(2).strip()
                    if v2:
                        item[k2] = _scalar(v2)
                        pos += 1
                    else:
                        pos += 1
                        child, pos = _parse_block(lines, pos, ind2 + 2)
                        item[k2] = child
                out.append(item)
            else:
                out.append(_scalar(content))
                pos += 1
        return out, pos

    out = {}
    while pos < len(lines) and lines[pos][0] == indent:
        ind, text = lines[pos]
        m = _KV.match(text)
        if not m:
            raise YamlError(f"expected 'key: value' at: {text!r}")
        key, val = m.group(1).strip().strip("'\""), m.group(2).strip()
        pos += 1
        if val:
            out[key] = _scalar(val)
        elif pos < len(lines) and lines[pos][0] > ind:
            out[key], pos = _parse_block(lines, pos, lines[pos][0])
        else:
            out[key] = None
    return out, pos


def load(text: str):
    lines = _strip_comments(text.splitlines())
    if not lines:
        return {}
    value, pos = _parse_block(lines, 0, lines[0][0])
    if pos != len(lines):
        ind, txt = lines[pos]
        raise YamlError(
            f"unconsumed content at line {txt!r} (indent {ind}) - a "
            f"multi-line folded/plain scalar is not supported; put the "
            f"value on one line or use a quoted string")
    return value
