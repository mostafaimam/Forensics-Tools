"""Outlook ``.msg`` (OLE2) parser."""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone

from analysis_email.message import Attachment, Message
from analysis_email.ole import OleError, OleFile

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# property tag -> attribute
_STR = {
    "0037": "subject", "0C1A": "from_name", "0C1F": "from_addr",
    "5D01": "from_addr", "0E1D": "subject", "1000": "body",
    "0E04": "to", "0E03": "cc", "0E02": "bcc",
    "1035": "message_id", "007D": "headers", "5D02": "return_path",
}
_PROP_TIME = {0x0039: "date", 0x0E06: "delivered", 0x3007: "created"}


def _stream_name(entry: str) -> tuple[str, str] | None:
    # __substg1.0_0037001F  ->  ("0037", "001F")
    if not entry.startswith("__substg1.0_") or len(entry) < 20:
        return None
    body = entry[len("__substg1.0_"):]
    return body[:4].upper(), body[4:8].upper()


def _decode(data: bytes, ptype: str) -> str:
    if ptype in ("001F", "101F"):
        return data.decode("utf-16-le", "replace").rstrip("\x00")
    if ptype in ("001E", "101E"):
        return data.decode("cp1252", "replace").rstrip("\x00")
    return data.decode("latin-1", "replace").rstrip("\x00")


def _ft_to_iso(ticks: int) -> str:
    if ticks <= 0 or ticks > (1 << 63):
        return ""
    try:
        return (_FT_EPOCH + timedelta(microseconds=ticks / 10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return ""


def _read_properties(ole: OleFile, prefix: str, out: dict) -> None:
    try:
        blob = ole.read_path(f"{prefix}__properties_version1.0")
    except OleError:
        return
    # header: 8 (top level) or 24 bytes; entries are 16 bytes
    start = 32 if prefix == "" else 24
    for i in range(start, len(blob) - 15, 16):
        tag, ptype = struct.unpack_from("<HH", blob, i)
        val = blob[i + 8:i + 16]
        if ptype == 0x0040:                       # PtypTime
            out[tag] = struct.unpack("<Q", val)[0]


def _parse_container(ole: OleFile, prefix: str) -> dict:
    fields: dict = {}
    for path, e in ole.walk():
        if not path.startswith(prefix):
            continue
        rel = path[len(prefix):]
        if "/" in rel:
            continue
        parsed = _stream_name(rel)
        if not parsed:
            continue
        tag, ptype = parsed
        try:
            data = ole.read_path(path)
        except OleError:
            continue
        if tag in _STR:
            fields.setdefault(_STR[tag], _decode(data, ptype))
        elif tag == "3704" or tag == "3707":
            fields["att_name"] = _decode(data, ptype)
        elif tag.startswith("3701"):
            fields["att_data"] = data
        elif tag == "370E":
            fields["att_mime"] = _decode(data, ptype)
    times: dict = {}
    _read_properties(ole, prefix, times)
    for t, name in _PROP_TIME.items():
        if t in times:
            fields[name] = _ft_to_iso(times[t])
    return fields


def parse(path: str, source: str) -> list[Message]:
    with open(path, "rb") as fh:
        ole = OleFile(fh.read())
    m = Message(source=source, container="msg", index=0)
    top = _parse_container(ole, "")
    m.subject = top.get("subject", "")
    m.from_name = top.get("from_name", "")
    m.from_addr = top.get("from_addr", "")
    m.to = top.get("to", "")
    m.cc = top.get("cc", "")
    m.bcc = top.get("bcc", "")
    m.message_id = top.get("message_id", "")
    m.return_path = top.get("return_path", "")
    m.date = top.get("date", "")
    m.delivered = top.get("delivered", "")
    body = top.get("body", "")
    m.body_bytes = len(body.encode("utf-8", "replace"))
    m.body_preview = " ".join(body.split())[:400]
    hdrs = top.get("headers", "")
    if hdrs:
        from email import message_from_string
        from email import policy as _policy

        from analysis_email.rfc822 import _flag as _rfc_flag
        pm = message_from_string(hdrs, policy=_policy.default)
        m.headers_present = [k for k, _ in pm.items()]
        m.return_path = m.return_path or (pm.get("Return-Path") or "").strip("<> ")
        m.reply_to = m.reply_to or (pm.get("Reply-To") or "").strip()
        m.x_originating_ip = m.x_originating_ip or \
            (pm.get("X-Originating-IP") or "").strip("[] ")
        for r in pm.get_all("Received") or []:
            m.received_chain.append({"raw": " ".join(r.split())[:300], "ip": ""})
        _rfc_flag(pm, m)

    for storage_path, e in list(ole.walk()):
        if storage_path.startswith("__attach_version1.0_") and \
                "/" not in storage_path:
            att = _parse_container(ole, storage_path + "/")
            data = att.get("att_data", b"")
            name = att.get("att_name", "") or "(unnamed)"
            m.attachments.append(Attachment.of(name, data,
                                               att.get("att_mime", "")))
    return [m]
