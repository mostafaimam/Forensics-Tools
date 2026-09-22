"""Schemaless Protocol Buffers wire-format decoder.

The wire format itself (varint tags, LEB128 varints, length-delimited
fields, fixed32/fixed64) is Google's own public, precisely specified
encoding - decoding the *structure* needs no ``.proto`` schema, only
each field's self-describing number and wire type. What a schema would
normally add - field *names* and whether a length-delimited field is a
string, raw bytes, or a nested message - is inferred heuristically:
try UTF-8 text, then try recursively parsing as a nested message (kept
only if the field numbers found look plausible), otherwise report raw
bytes. That guess is explicitly lower-confidence than the wire-level
decode - see the README.
"""

from __future__ import annotations

from dataclasses import dataclass

_MAX_PLAUSIBLE_FIELD_NUMBER = 2000


class ProtobufError(ValueError):
    pass


@dataclass
class Field:
    number: int
    wire_type: int
    kind: str          # varint | fixed64 | fixed32 | string | bytes | message
    value: object


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ProtobufError("truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtobufError("varint too long")


def _looks_like_text(b: bytes) -> bool:
    if not b:
        return False
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return printable / len(text) > 0.85


def _plausible(fields: list[Field]) -> bool:
    return bool(fields) and all(
        1 <= f.number <= _MAX_PLAUSIBLE_FIELD_NUMBER for f in fields)


def decode_message(data: bytes, *, max_depth: int = 6) -> list[Field] | None:
    """Best-effort schemaless decode of one message. Returns ``None``
    if `data` cannot possibly be a valid protobuf message (used both
    for the top-level call and the recursive nested-message guess)."""
    if not data:
        return []
    fields: list[Field] = []
    pos = 0
    n = len(data)
    while pos < n:
        try:
            tag, pos = _read_varint(data, pos)
        except ProtobufError:
            return None
        wire_type = tag & 0x7
        number = tag >> 3
        if number == 0 or wire_type in (3, 4, 6, 7):
            return None
        if wire_type == 0:
            try:
                v, pos = _read_varint(data, pos)
            except ProtobufError:
                return None
            fields.append(Field(number, wire_type, "varint", v))
        elif wire_type == 1:
            if pos + 8 > n:
                return None
            fields.append(Field(number, wire_type, "fixed64",
                                data[pos:pos + 8]))
            pos += 8
        elif wire_type == 5:
            if pos + 4 > n:
                return None
            fields.append(Field(number, wire_type, "fixed32",
                                data[pos:pos + 4]))
            pos += 4
        elif wire_type == 2:
            try:
                length, pos = _read_varint(data, pos)
            except ProtobufError:
                return None
            if pos + length > n:
                return None
            chunk = data[pos:pos + length]
            pos += length
            kind, value = _classify_bytes(chunk, max_depth)
            fields.append(Field(number, wire_type, kind, value))
        else:
            return None
    return fields


def _classify_bytes(chunk: bytes, max_depth: int):
    if max_depth > 0:
        nested = decode_message(chunk, max_depth=max_depth - 1)
        if nested is not None and _plausible(nested):
            return "message", nested
    if _looks_like_text(chunk):
        return "string", chunk.decode("utf-8")
    return "bytes", chunk


def decode_top(data: bytes) -> list[Field] | None:
    """Decode `data` as a top-level protobuf message. Unlike a nested
    guess, an empty top-level result is accepted only for empty input;
    non-empty input that fails to parse structurally returns None."""
    return decode_message(data)


def to_jsonable(fields: list[Field]):
    out = []
    for f in fields:
        v = f.value
        if f.kind == "message":
            v = to_jsonable(v)
        elif f.kind in ("bytes", "fixed64", "fixed32"):
            v = v.hex()
        out.append({"field": f.number, "wire_type": f.wire_type,
                   "kind": f.kind, "value": v})
    return out
