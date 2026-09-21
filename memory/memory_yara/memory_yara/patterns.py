"""Compile a StringDef into one or more scannable byte-regex patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

from memory_yara.rules import RuleSyntaxError, StringDef

_MAX_JUMP = 4096

_HEX_TOKEN = re.compile(
    rb"\s*(?:([0-9A-Fa-f]{2})|(\?\?)|\[(\d+)(-(\d*))?\])")


@dataclass
class CompiledPattern:
    string_id: str
    regex: "re.Pattern"
    fullword: bool


def _fullword_wrap(pattern: bytes) -> bytes:
    word = rb"[A-Za-z0-9_]"
    return rb"(?<!" + word + rb")(?:" + pattern + rb")(?!" + word + rb")"


def _compile_hex(strdef: StringDef) -> bytes:
    raw = strdef.raw.encode("ascii", "ignore")
    out = bytearray()
    pos = 0
    n = len(raw)
    while pos < n:
        if raw[pos:pos + 1].isspace():
            pos += 1
            continue
        m = _HEX_TOKEN.match(raw, pos)
        if not m or m.start() != pos:
            raise RuleSyntaxError(
                f"unsupported hex pattern syntax in {strdef.id}: "
                f"{strdef.raw!r} (v0.1 supports byte pairs, ?? and "
                f"[n]/[n-m]/[n-] jumps only - no nibble wildcards or "
                f"alternation)")
        byte_hex, wildcard, lo, has_hi, hi = m.groups()
        if byte_hex:
            out += re.escape(bytes.fromhex(byte_hex.decode()))
        elif wildcard:
            out += b"."
        else:
            lo_n = int(lo)
            if has_hi and hi:
                out += b".{%d,%d}" % (lo_n, int(hi))
            elif has_hi:
                out += b".{%d,%d}" % (lo_n, _MAX_JUMP)
            else:
                out += b".{%d}" % lo_n
        pos = m.end()
    return bytes(out)


def compile_string(strdef: StringDef) -> list[CompiledPattern]:
    flags = re.DOTALL
    fullword = "fullword" in strdef.modifiers
    out = []
    if strdef.kind == "hex":
        body = _compile_hex(strdef)
        if fullword:
            body = _fullword_wrap(body)
        out.append(CompiledPattern(strdef.id, re.compile(body, flags),
                                   fullword))
        return out
    if strdef.kind == "regex":
        rflags = flags | (re.IGNORECASE if "nocase" in strdef.modifiers
                          else 0)
        body = strdef.raw.encode("utf-8")
        if fullword:
            body = _fullword_wrap(body)
        out.append(CompiledPattern(strdef.id, re.compile(body, rflags),
                                   fullword))
        return out

    # text
    variants = []
    if "wide" in strdef.modifiers:
        variants.append(strdef.raw.encode("utf-16-le"))
    if "ascii" in strdef.modifiers or "wide" not in strdef.modifiers:
        variants.append(strdef.raw.encode("utf-8"))
    rflags = flags | (re.IGNORECASE if "nocase" in strdef.modifiers else 0)
    for v in variants:
        body = re.escape(v)
        if fullword:
            body = _fullword_wrap(body)
        out.append(CompiledPattern(strdef.id, re.compile(body, rflags),
                                   fullword))
    return out
