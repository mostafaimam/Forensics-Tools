"""Synthetic EML / MBOX / MSG fixtures."""

from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage

from _ole_synth import build_msg_ole, properties_stream, substg

_FT_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(dt: datetime) -> int:
    return int((dt.replace(tzinfo=timezone.utc) - _FT_EPOCH)
               .total_seconds() * 10_000_000)


def eml(*, subject="Invoice", frm="Alice <alice@good.example>",
        to="bob@corp.example", date="Mon, 01 Sep 2026 08:00:00 +0000",
        return_path="alice@good.example", body="Please pay the invoice.",
        attachments=(), extra_headers=()) -> bytes:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = frm
    m["To"] = to
    m["Date"] = date
    m["Message-ID"] = "<abc123@good.example>"
    if return_path:
        m["Return-Path"] = f"<{return_path}>"
    for k, v in extra_headers:
        m[k] = v
    m["Received"] = ("from mail.good.example (mail.good.example [203.0.113.5]) "
                     "by mx.corp.example; " + date)
    m.set_content(body)
    for name, data, ctype in attachments:
        maintype, _, subtype = (ctype or "application/octet-stream").partition("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream",
                         filename=name)
    return m.as_bytes()


def mbox(messages: list[bytes]) -> bytes:
    out = bytearray()
    for i, raw in enumerate(messages):
        out += f"From sender{i}@x  Mon Sep  1 08:0{i}:00 2026\n".encode()
        out += raw.replace(b"\nFrom ", b"\n>From ")
        if not out.endswith(b"\n"):
            out += b"\n"
        out += b"\n"
    return bytes(out)


def msg(*, subject="Wire transfer request",
        from_name="CEO", from_addr="ceo@company.example",
        to="cfo@company.example", body="Please wire $50,000 today.",
        submit=datetime(2026, 9, 1, 9, 30, 0),
        delivered=datetime(2026, 9, 1, 9, 31, 0),
        headers="Return-Path: <ceo@attacker.example>\r\n"
                "X-Originating-IP: [198.51.100.9]\r\n",
        attachments=()) -> bytes:
    top = dict([
        substg("0037", "001F", subject),
        substg("0C1A", "001F", from_name),
        substg("0C1F", "001F", from_addr),
        substg("0E04", "001F", to),
        substg("1000", "001F", body),
        substg("007D", "001F", headers),
    ])
    top["__properties_version1.0"] = properties_stream(
        {0x0039: _ft(submit), 0x0E06: _ft(delivered)}, top_level=True)
    storages = {}
    for i, (name, data) in enumerate(attachments):
        storages[f"__attach_version1.0_#{i:08X}"] = dict([
            substg("3704", "001F", name),
            substg("3701", "0102", data),
        ])
    return build_msg_ole(top, storages)
