"""A minimal forward protobuf encoder + plist builder, for tests."""

from __future__ import annotations

import plistlib


def encode_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def varint_field(field_number: int, value: int) -> bytes:
    return tag(field_number, 0) + encode_varint(value)


def bytes_field(field_number: int, value: bytes) -> bytes:
    return tag(field_number, 2) + encode_varint(len(value)) + value


def string_field(field_number: int, value: str) -> bytes:
    return bytes_field(field_number, value.encode("utf-8"))


def message_field(field_number: int, inner: bytes) -> bytes:
    return bytes_field(field_number, inner)


def fixed32_field(field_number: int, raw4: bytes) -> bytes:
    return tag(field_number, 5) + raw4


def build_plist_file(path, obj) -> None:
    path.write_bytes(plistlib.dumps(obj, fmt=plistlib.FMT_BINARY))
