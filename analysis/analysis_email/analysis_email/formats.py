"""Detect the container and dispatch to the right parser."""

from __future__ import annotations

import mailbox
from email import message_from_binary_file, policy
from pathlib import Path

from analysis_email import msg as msg_parser
from analysis_email.message import Message
from analysis_email.rfc822 import from_pymessage

_PST_SIG = b"!BDN"


def detect(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            head = fh.read(16)
    except OSError:
        return "unknown"
    if head[:4] == _PST_SIG:
        return "pst"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "msg"
    if head[:5] == b"From " or path.suffix.lower() in (".mbox", ".mbx"):
        return "mbox"
    if path.suffix.lower() in (".eml", ".msg-eml") or head[:1] in \
            (b"R", b"D", b"F", b"S", b"M", b"T", b"X") and b":" in head:
        return "eml"
    if b"\n" in head or b"\r" in head:
        return "eml"
    return "unknown"


def parse_file(path: str) -> list[Message]:
    p = Path(path)
    fmt = detect(p)
    if fmt == "msg":
        return msg_parser.parse(str(p), str(p))
    if fmt == "mbox":
        return _parse_mbox(p)
    if fmt == "eml":
        return _parse_eml(p)
    if fmt == "pst":
        raise NotImplementedError(
            "PST / OST parsing is not implemented yet - export the folder to "
            "MBOX / EML (e.g. with `readpst`, Thunderbird, or Outlook) and "
            "re-run")
    raise ValueError(f"unrecognised email container: {path}")


def _parse_eml(p: Path) -> list[Message]:
    with p.open("rb") as fh:
        pm = message_from_binary_file(fh, policy=policy.default)
    m = Message(source=str(p), container="eml", index=0)
    return [from_pymessage(pm, m)]


def _parse_mbox(p: Path) -> list[Message]:
    box = mailbox.mbox(str(p))
    out = []
    try:
        for i, key in enumerate(box.iterkeys()):
            try:
                pm = box.get_message(key)
            except Exception:  # noqa: BLE001
                continue
            m = Message(source=str(p), container="mbox", index=i)
            try:
                out.append(from_pymessage(pm, m))
            except Exception as e:  # noqa: BLE001
                m.flags.append(f"parse error: {e}")
                out.append(m)
    finally:
        box.close()
    return out
