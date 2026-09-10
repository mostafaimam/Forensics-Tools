"""Build synthetic OLE2 (.doc-like) and OOXML (.docx / .docm) test files."""

from __future__ import annotations

import struct
import zipfile
from datetime import datetime, timezone
from io import BytesIO

import _ole_synth as O

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(dt):
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


def _raw_container(payload: bytes) -> bytes:
    """A single-raw-chunk MS-OVBA compressed container."""
    return b"\x01" + struct.pack("<H", 0x0FFF) + payload.ljust(4096, b"\x00")


def _propset(fmtid_pairs):
    """fmtid_pairs: list of (fmtid_guid_bytes, {pid: (vtype, value)})."""
    hdr = bytearray(0x1C + 20 * len(fmtid_pairs))
    hdr[0:2] = b"\xfe\xff"
    struct.pack_into("<H", hdr, 2, 0)
    struct.pack_into("<I", hdr, 0x18, len(fmtid_pairs))
    sections = bytearray()
    base = len(hdr)
    for i, (fmtid, props) in enumerate(fmtid_pairs):
        struct.pack_into("<16s", hdr, 0x1C + i * 20, fmtid)
        struct.pack_into("<I", hdr, 0x1C + i * 20 + 16, base + len(sections))
        sec = _one_section(props)
        sections += sec
    return bytes(hdr) + bytes(sections)


def _one_section(props: dict) -> bytes:
    ids = bytearray()
    values = bytearray()
    idx_size = 8 + 8 * len(props)
    for pid, (vtype, val) in sorted(props.items()):
        struct.pack_into  # noqa
        ids += struct.pack("<II", pid, idx_size + len(values))
        values += struct.pack("<H", vtype) + b"\x00\x00"
        if vtype == 0x1E:                      # VT_LPSTR
            b = val.encode("latin-1") + b"\x00"
            values += struct.pack("<I", len(b)) + b
            values += b"\x00" * ((-len(b)) % 4)
        elif vtype == 0x40:                    # VT_FILETIME
            values += struct.pack("<Q", val)
        elif vtype == 0x03:                    # VT_I4
            values += struct.pack("<i", val)
    total = 8 + len(ids) + len(values)
    return struct.pack("<II", total, len(props)) + bytes(ids) + bytes(values)


FMTID_SUMMARY = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
FMTID_DOCSUM = bytes.fromhex("02d5cdd59c2e1b1093970800 2b2cf9ae".replace(" ", ""))

VBA_SRC = (
    "Sub AutoOpen()\r\n"
    "    Dim s As String\r\n"
    "    s = \"powershell -enc ZQBjAGgAbwA=\"\r\n"
    "    CreateObject(\"WScript.Shell\").Run s, 0\r\n"
    "End Sub\r\n"
)


def _vba_storage() -> dict:
    recs = bytearray()

    def rec(rid, payload=b""):
        return struct.pack("<HI", rid, len(payload)) + payload

    recs += rec(0x0019, b"Module1")
    recs += rec(0x001A, b"Module1")
    recs += rec(0x0031, struct.pack("<I", 0))
    recs += rec(0x0021)
    recs += rec(0x0010)
    return {
        "dir": _raw_container(bytes(recs)),
        "Module1": _raw_container(VBA_SRC.encode("latin-1")),
    }


def build_doc(*, author="Alice", saver="Bob",
              created=datetime(2026, 3, 10, 9, 0, tzinfo=timezone.utc),
              saved=datetime(2026, 3, 16, 17, 0, tzinfo=timezone.utc),
              company="Acme Corp", template="Normal.dotm",
              with_macros=True) -> bytes:
    summ = {
        4: (0x1E, author), 8: (0x1E, saver), 7: (0x1E, template),
        9: (0x1E, "12"), 10: (0x40, 0),
        12: (0x40, _ft(created)), 13: (0x40, _ft(saved)),
        18: (0x1E, "Microsoft Office Word"),
    }
    docsum = {15: (0x1E, company), 14: (0x1E, "Mallory")}
    props = _propset([(FMTID_SUMMARY, summ)])
    dprops = _propset([(FMTID_DOCSUM, docsum)])
    top = {
        "\x05SummaryInformation": props,
        "\x05DocumentSummaryInformation": dprops,
        "WordDocument": b"\xec\xa5" + b"\x00" * 200,
    }
    storages = {}
    if with_macros:
        storages["Macros"] = _vba_storage()
    return O.build_msg_ole(top, storages)


def build_docx(*, macro=False, remote_template=None) -> bytes:
    buf = BytesIO()
    kind = "docm" if macro else "docx"
    ct = ('<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats'
          '.org/package/2006/content-types">')
    if macro:
        ct += ('<Override PartName="/word/vbaProject.bin" ContentType='
               '"application/vnd.ms-office.vbaProject"/>'
               '<Override PartName="/word/document.xml" ContentType='
               '"application/vnd.ms-word.document.macroEnabled.main+xml"/>')
    else:
        ct += ('<Override PartName="/word/document.xml" ContentType='
               '"application/vnd.openxmlformats-officedocument'
               '.wordprocessingml.document.main+xml"/>')
    ct += "</Types>"

    core = ('<?xml version="1.0"?><cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
            'metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:creator>Alice</dc:creator>'
            '<cp:lastModifiedBy>Bob</cp:lastModifiedBy>'
            '<dc:title>Quarterly Report</dc:title>'
            '<cp:revision>7</cp:revision>'
            '<dcterms:created>2026-03-10T09:00:00Z</dcterms:created>'
            '<dcterms:modified>2026-03-16T17:00:00Z</dcterms:modified>'
            '</cp:coreProperties>')
    app = ('<?xml version="1.0"?><Properties xmlns="http://schemas'
           '.openxmlformats.org/officeDocument/2006/extended-properties">'
           '<Application>Microsoft Office Word</Application>'
           '<Company>Acme Corp</Company>'
           '<TotalTime>0</TotalTime><Pages>3</Pages><Words>812</Words>'
           '</Properties>')

    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        z.writestr("word/document.xml", "<w:document/>")
        rels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas'
                '.openxmlformats.org/package/2006/relationships">')
        if remote_template:
            rels += (f'<Relationship Id="rId1" Type="http://schemas'
                     f'.openxmlformats.org/officeDocument/2006/relationships/'
                     f'attachedTemplate" Target="{remote_template}" '
                     f'TargetMode="External"/>')
        rels += "</Relationships>"
        z.writestr("word/_rels/document.xml.rels", rels)
        if macro:
            z.writestr("word/vbaProject.bin",
                       build_doc(with_macros=True))  # an OLE2 with Macros
    return buf.getvalue()
