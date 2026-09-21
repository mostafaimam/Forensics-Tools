"""Scan byte buffers (or a chunked stream) against compiled rules."""

from __future__ import annotations

from dataclasses import dataclass, field

from memory_yara.conditions import MatchContext, evaluate
from memory_yara.patterns import compile_string
from memory_yara.rules import Rule

_OVERLAP = 8192
_CHUNK = 8 << 20
_MAX_OFFSETS_PER_STRING = 20


@dataclass
class CompiledRule:
    rule: Rule
    patterns: list       # list[CompiledPattern]


def compile_rule(rule: Rule) -> CompiledRule:
    patterns = []
    for s in rule.strings:
        patterns.extend(compile_string(s))
    return CompiledRule(rule, patterns)


@dataclass
class Hit:
    rule_name: str
    meta: dict
    matched_strings: dict = field(default_factory=dict)  # id -> [offsets]


def scan_buffer(compiled: list[CompiledRule], data: bytes, *,
                base_offset: int = 0, filesize: int | None = None
                ) -> list[Hit]:
    filesize = len(data) if filesize is None else filesize
    hits = []
    for cr in compiled:
        offsets: dict[str, list[int]] = {}
        for cp in cr.patterns:
            for m in cp.regex.finditer(data):
                lst = offsets.setdefault(cp.string_id, [])
                if len(lst) < _MAX_OFFSETS_PER_STRING:
                    lst.append(base_offset + m.start())
        counts = {sid: len(v) for sid, v in offsets.items()}
        ctx = MatchContext(counts, filesize)
        if evaluate(cr.rule.condition, ctx):
            hits.append(Hit(cr.rule.name, dict(cr.rule.meta), offsets))
    return hits


def scan_stream(compiled: list[CompiledRule], chunks, *, filesize: int = 0
               ) -> list[Hit]:
    """`chunks` yields (base_offset, bytes) pairs, e.g. from a memory
    image's stream_runs(). Uses a fixed-size overlap window so matches
    (and jump-based hex patterns) spanning a chunk boundary aren't
    missed, up to the overlap size - see the README for the limit."""
    merged: dict[str, dict] = {}   # rule_name -> {"meta":..., "offsets":{}}
    carry = b""
    carry_base = 0
    for base, chunk in chunks:
        buf = carry + chunk
        buf_base = carry_base if carry else base
        for cr in compiled:
            offsets: dict[str, list[int]] = {}
            for cp in cr.patterns:
                for m in cp.regex.finditer(buf):
                    lst = offsets.setdefault(cp.string_id, [])
                    if len(lst) < _MAX_OFFSETS_PER_STRING:
                        lst.append(buf_base + m.start())
            if offsets:
                slot = merged.setdefault(cr.rule.name,
                                         {"meta": dict(cr.rule.meta),
                                          "offsets": {}, "rule": cr.rule})
                for sid, offs in offsets.items():
                    existing = slot["offsets"].setdefault(sid, [])
                    for o in offs:
                        if o not in existing and \
                                len(existing) < _MAX_OFFSETS_PER_STRING:
                            existing.append(o)
        overlap = min(_OVERLAP, len(buf))
        carry = buf[-overlap:]
        carry_base = buf_base + len(buf) - overlap

    out = []
    for name, slot in merged.items():
        counts = {sid: len(v) for sid, v in slot["offsets"].items()}
        ctx = MatchContext(counts, filesize)
        if evaluate(slot["rule"].condition, ctx):
            out.append(Hit(name, slot["meta"], slot["offsets"]))
    return out
