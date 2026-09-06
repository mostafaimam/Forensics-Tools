"""The normalised message model shared by the mbox / eml / msg parsers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


@dataclass
class Attachment:
    name: str
    size: int = 0
    sha256: str = ""
    content_type: str = ""
    data: bytes = b""          # kept only for --attachments-dir; not serialised

    @classmethod
    def of(cls, name: str, data: bytes, content_type: str = ""):
        return cls(name=name or "(unnamed)", size=len(data),
                   sha256=hashlib.sha256(data).hexdigest(),
                   content_type=content_type, data=data)


@dataclass
class Message:
    source: str = ""
    container: str = ""        # mbox | eml | msg | pst
    index: int = 0
    message_id: str = ""
    date: str = ""             # best available send/submit time, ISO-8601 UTC
    delivered: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    to: str = ""
    cc: str = ""
    bcc: str = ""
    reply_to: str = ""
    return_path: str = ""
    x_originating_ip: str = ""
    received_chain: list = field(default_factory=list)
    body_preview: str = ""
    body_bytes: int = 0
    has_html: bool = False
    attachments: list = field(default_factory=list)   # list[Attachment]
    headers_present: list = field(default_factory=list)
    flags: list = field(default_factory=list)          # heuristics

    def as_row(self) -> dict:
        return {
            "source": self.source, "container": self.container,
            "index": self.index, "date": self.date,
            "delivered": self.delivered, "from_name": self.from_name,
            "from_addr": self.from_addr, "to": self.to, "cc": self.cc,
            "bcc": self.bcc, "subject": self.subject,
            "message_id": self.message_id, "reply_to": self.reply_to,
            "return_path": self.return_path,
            "x_originating_ip": self.x_originating_ip,
            "attachments": "; ".join(
                f"{a.name} ({a.size}B)" for a in self.attachments),
            "attachment_count": len(self.attachments),
            "body_bytes": self.body_bytes, "has_html": "yes" if self.has_html
            else "no",
            "flags": " ; ".join(self.flags),
        }
