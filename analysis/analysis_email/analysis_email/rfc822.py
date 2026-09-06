"""Shared RFC822 helpers - turn an ``email.message.Message`` into our model."""

from __future__ import annotations

import re
from datetime import timezone
from email.message import Message as PyMessage
from email.utils import parsedate_to_datetime

from analysis_email.message import Attachment, Message

_IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{6,})\]?")
_SPOOF_HINTS = ("X-Mailer: PHPMailer", "X-PHP-Originating-Script")


def _iso(raw: str) -> str:
    if not raw:
        return ""
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return ""
        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError):
        return raw.strip()[:40]


def _addr(value: str) -> tuple[str, str]:
    if not value:
        return "", ""
    m = re.match(r'\s*"?([^"<]*)"?\s*<([^>]+)>', value)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return "", value.strip()


def from_pymessage(msg: PyMessage, out: Message) -> Message:
    out.headers_present = [k for k, _ in msg.items()]
    out.message_id = (msg.get("Message-ID") or "").strip()
    out.subject = _decode_header(msg.get("Subject", ""))
    out.date = _iso(msg.get("Date", ""))
    out.from_name, out.from_addr = _addr(_decode_header(msg.get("From", "")))
    out.to = _decode_header(msg.get("To", ""))
    out.cc = _decode_header(msg.get("Cc", ""))
    out.bcc = _decode_header(msg.get("Bcc", ""))
    out.reply_to = _decode_header(msg.get("Reply-To", ""))
    out.return_path = (msg.get("Return-Path") or "").strip("<> ")
    out.x_originating_ip = (msg.get("X-Originating-IP") or "").strip("[] ")

    received = msg.get_all("Received") or []
    for r in received:
        m = _IP_RE.search(r)
        out.received_chain.append({"raw": " ".join(r.split())[:300],
                                   "ip": m.group(1) if m else ""})

    _walk_parts(msg, out)
    _flag(msg, out)
    return out


def _walk_parts(msg: PyMessage, out: Message) -> None:
    body = []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        fn = part.get_filename()
        if part.is_multipart():
            continue
        if fn or "attachment" in disp:
            try:
                data = part.get_payload(decode=True) or b""
            except Exception:  # noqa: BLE001
                data = b""
            out.attachments.append(Attachment.of(
                _decode_header(fn or ""), data, ctype))
            continue
        if ctype == "text/plain" and len(body) < 1:
            try:
                body.append(part.get_content())
            except Exception:  # noqa: BLE001
                pass
        elif ctype == "text/html":
            out.has_html = True
    text = "\n".join(body)
    out.body_bytes = len(text.encode("utf-8", "replace"))
    out.body_preview = " ".join(text.split())[:400]


def _decode_header(value: str) -> str:
    if not value:
        return ""
    try:
        from email.header import decode_header, make_header
        return str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001
        return value


def _flag(msg: PyMessage, out: Message) -> None:
    frm = out.from_addr.lower()
    rp = out.return_path.lower()
    if frm and rp and frm.split("@")[-1] != rp.split("@")[-1]:
        out.flags.append("From domain != Return-Path domain")
    if out.reply_to and out.from_addr and \
            out.reply_to.lower() != out.from_addr.lower() and \
            "@" in out.reply_to:
        rd = out.reply_to.split("@")[-1].strip("> ").lower()
        if rd and rd != frm.split("@")[-1]:
            out.flags.append("Reply-To domain differs from From")
    hdrs = "\n".join(f"{k}: {v}" for k, v in msg.items())
    if any(h in hdrs for h in _SPOOF_HINTS):
        out.flags.append("bulk-mailer header present")
    auth = (msg.get("Authentication-Results") or "").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if f"{mech}=fail" in auth or f"{mech}=softfail" in auth:
            out.flags.append(f"{mech.upper()} {('soft' if 'soft' in auth else '')}fail")
    if len(out.received_chain) == 0 and out.container in ("eml", "mbox"):
        out.flags.append("no Received headers")
