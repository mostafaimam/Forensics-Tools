"""Hand-assemble minimal but valid EVTX / BinXml for the test-suite."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_DATA = 512


def ft(dt: datetime) -> int:
    return int((dt - _FT_EPOCH).total_seconds() * 10_000_000)


# ---- BinXml builders (always inline names: name_offset = 0xFFFFFFFF) ----
def bx_name(s: str) -> bytes:
    u = s.encode("utf-16-le")
    return b"\x00\x00\x00\x00" + struct.pack("<HH", 0, len(s)) + u + b"\x00\x00"


def bx_frag_header() -> bytes:
    return b"\x0f\x01\x01\x00"


def bx_open(name: str, has_attrs: bool = False) -> bytes:
    token = 0x41 if has_attrs else 0x01
    b = bytes([token]) + b"\xff\xff" + struct.pack("<II", 0, 0xFFFFFFFF)
    b += bx_name(name)
    if has_attrs:
        b += struct.pack("<I", 0)          # attribute-list byte size
    return b


def bx_attr(name: str, value: str) -> bytes:
    b = bytes([0x06]) + struct.pack("<I", 0xFFFFFFFF) + bx_name(name)
    b += bx_value_text(value)
    return b


def bx_attr_sub(name: str, index: int, optional: bool = False) -> bytes:
    b = bytes([0x06]) + struct.pack("<I", 0xFFFFFFFF) + bx_name(name)
    b += bytes([0x0E if optional else 0x0D]) + struct.pack("<H", index) + b"\x01"
    return b


def bx_value_text(s: str) -> bytes:
    u = s.encode("utf-16-le")
    return bytes([0x05, 0x01]) + struct.pack("<H", len(s)) + u


def bx_sub(index: int, optional: bool = False) -> bytes:
    return bytes([0x0E if optional else 0x0D]) + struct.pack("<H", index) + b"\x01"


CLOSE_START = b"\x02"
CLOSE_EMPTY = b"\x03"
END_ELEMENT = b"\x04"
EOF = b"\x00"


def element(name: str, text: str) -> bytes:
    return bx_open(name) + CLOSE_START + bx_value_text(text) + END_ELEMENT


def element_sub(name: str, index: int) -> bytes:
    return bx_open(name) + CLOSE_START + bx_sub(index) + END_ELEMENT


def self_closing(name: str, **attrs) -> bytes:
    b = bx_open(name, has_attrs=True)
    for k, v in attrs.items():
        b += bx_attr(k, v)
    return b + CLOSE_EMPTY


# ---- a full Event fragment (no template) ----
def event_fragment(*, event_id: str, provider: str, level: str, channel: str,
                   computer: str, time_created: str, data: dict) -> bytes:
    system = bx_open("System") + CLOSE_START
    system += self_closing("Provider", Name=provider)
    system += element("EventID", event_id)
    system += element("Level", level)
    system += element("Channel", channel)
    system += element("Computer", computer)
    system += self_closing("TimeCreated", SystemTime=time_created)
    system += self_closing("Security", UserID="S-1-5-18")
    system += self_closing("Execution", ProcessID="1234", ThreadID="5678")
    system += END_ELEMENT

    ed = bx_open("EventData") + CLOSE_START
    for k, v in data.items():
        ed += bx_open("Data", has_attrs=True) + bx_attr("Name", k) + CLOSE_START
        ed += bx_value_text(v) + END_ELEMENT
    ed += END_ELEMENT

    body = bx_open("Event") + CLOSE_START + system + ed + END_ELEMENT
    return bx_frag_header() + body + EOF


# ---- a fragment that uses a resident template + substitutions ----
def event_fragment_templated(*, values: list[tuple[int, str]],
                             binxml_offset: int = 536,
                             template_id: int = 0x11111111) -> bytes:
    """values: list of (binxml_type, string) - only wstring (0x01) used here."""
    # template body: <Event><System><EventID>{sub0}</EventID>
    #   <Computer>{sub1}</Computer></System>
    #   <EventData><Data Name="X">{sub2}</Data></EventData></Event>
    tbody = bx_open("Event") + CLOSE_START
    tbody += bx_open("System") + CLOSE_START
    tbody += element_sub("EventID", 0)
    tbody += element_sub("Computer", 1)
    tbody += self_closing("TimeCreated", SystemTime="2024-01-02T03:04:05.000000Z")
    tbody += END_ELEMENT
    tbody += bx_open("EventData") + CLOSE_START
    tbody += bx_open("Data", has_attrs=True) + bx_attr("Name", "Payload") + CLOSE_START
    tbody += bx_sub(2) + END_ELEMENT
    tbody += END_ELEMENT
    tbody += END_ELEMENT + EOF

    # substitution array
    subs = struct.pack("<I", len(values))
    payloads = b""
    for vtype, s in values:
        raw = s.encode("utf-16-le")
        subs += struct.pack("<HBB", len(raw), vtype, 0)
        payloads += raw

    frag = bx_frag_header()
    # TemplateInstance: token, unknown, template_id, template_offset.
    # Resident: template_offset points just past the 10-byte instance header
    # (= binxml_offset + 4 for the fragment header + 10).
    template_offset = binxml_offset + 14
    frag += bytes([0x0C, 0x01]) + struct.pack("<II", template_id, template_offset)
    frag += struct.pack("<I", 0)                 # TemplateNode next offset
    frag += b"\x00" * 16                          # guid
    frag += struct.pack("<I", len(tbody))         # data length
    frag += tbody
    frag += subs + payloads
    return frag


# ---- EVTX container ----
def _record(rec_id: int, dt: datetime, binxml: bytes) -> bytes:
    size = 24 + len(binxml) + 4
    pad = (-size) % 8
    size += pad
    return (struct.pack("<II", 0x00002A2A, size)
            + struct.pack("<QQ", rec_id, ft(dt))
            + binxml + b"\x00" * pad
            + struct.pack("<I", size))


def build_evtx(fragments: list) -> bytes:
    """A fragment may be bytes, or a callable(binxml_chunk_offset) -> bytes."""
    dt = datetime(2024, 3, 5, 10, 0, 0, tzinfo=timezone.utc)
    records = b""
    for i, frag in enumerate(fragments, 1):
        binxml_offset = CHUNK_DATA + len(records) + 24
        if callable(frag):
            frag = frag(binxml_offset)
        records += _record(i, dt, frag)

    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = b"ElfChnk\x00"
    struct.pack_into("<QQQQ", chunk, 8, 1, len(fragments), 1, len(fragments))
    struct.pack_into("<III", chunk, 0x28, 128, CHUNK_DATA + len(records), 0)
    chunk[CHUNK_DATA:CHUNK_DATA + len(records)] = records

    header = bytearray(FILE_HEADER_SIZE)
    header[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQ", header, 8, 0, 0, len(fragments) + 1)
    struct.pack_into("<IHHHH", header, 0x20, 128, 1, 3, 4096, 1)
    return bytes(header) + bytes(chunk)
