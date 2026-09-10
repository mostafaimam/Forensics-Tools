"""Turn a parsed BinXml element tree into an :class:`EventRecord` and an XML
string."""

from __future__ import annotations

import xml.sax.saxutils as sx
from dataclasses import dataclass, field

from windows_defender.evtx.binxml import Context, Element, filetime_to_iso
from windows_defender.evtx.headers import RawRecord


@dataclass
class EventRecord:
    record_id: int
    chunk_number: int
    timestamp_utc: str            # $WrittenTime from the record header
    time_created_utc: str = ""    # System/TimeCreated @SystemTime
    event_id: str = ""
    level: str = ""
    provider: str = ""
    channel: str = ""
    computer: str = ""
    user_id: str = ""             # System/Security @UserID (SID)
    task: str = ""
    opcode: str = ""
    keywords: str = ""
    process_id: str = ""
    thread_id: str = ""
    activity_id: str = ""
    data: dict = field(default_factory=dict)   # EventData / UserData name -> value
    xml: str = ""
    parse_error: str = ""

    def payload_columns(self, count: int = 6) -> list[str]:
        items = list(self.data.items())
        out = []
        for i in range(count):
            if i < len(items):
                k, v = items[i]
                out.append(f"{k}: {v}" if k else str(v))
            else:
                out.append("")
        return out


_LEVELS = {"0": "Info", "1": "Critical", "2": "Error", "3": "Warning",
           "4": "Information", "5": "Verbose"}


def _text(el: Element) -> str:
    return "".join(c for c in el.children if isinstance(c, str))


def _attr(el: Element, name: str) -> str:
    for k, v in el.attributes:
        if k == name:
            return str(v)
    return ""


def _to_xml(node, out: list) -> None:
    if isinstance(node, str):
        out.append(sx.escape(node))
        return
    attrs = "".join(f' {k}={sx.quoteattr(str(v))}' for k, v in node.attributes)
    kids = node.children
    if not kids:
        out.append(f"<{node.name}{attrs}/>")
        return
    out.append(f"<{node.name}{attrs}>")
    for c in kids:
        _to_xml(c, out)
    out.append(f"</{node.name}>")


def parse_record(raw: RawRecord, chunk: bytes) -> EventRecord:
    rec = EventRecord(
        record_id=raw.identifier,
        chunk_number=raw.chunk_number,
        timestamp_utc=filetime_to_iso(raw.timestamp_filetime),
    )
    try:
        ctx = Context(chunk)
        roots = ctx.parse_from(raw.binxml_offset)
    except Exception as e:  # noqa: BLE001
        rec.parse_error = f"binxml: {e}"
        return rec

    event = None
    for r in roots:
        if r.name.lower().endswith("event"):
            event = r
            break
    event = event or (roots[0] if roots else None)
    if event is None:
        rec.parse_error = "no Event element"
        return rec

    xml_parts: list = []
    _to_xml(event, xml_parts)
    rec.xml = "".join(xml_parts)

    for child in event.children:
        if not isinstance(child, Element):
            continue
        tag = child.name.split("}")[-1]
        if tag == "System":
            _fill_system(rec, child)
        elif tag in ("EventData", "UserData", "DebugData", "ProcessingErrorData"):
            _fill_data(rec, child)

    if rec.level and rec.level in _LEVELS:
        rec.level = _LEVELS[rec.level]
    return rec


def _fill_system(rec: EventRecord, sysel: Element) -> None:
    for c in sysel.children:
        if not isinstance(c, Element):
            continue
        tag = c.name.split("}")[-1]
        if tag == "Provider":
            rec.provider = _attr(c, "Name") or _attr(c, "EventSourceName")
        elif tag == "EventID":
            rec.event_id = _text(c)
        elif tag == "Level":
            rec.level = _text(c)
        elif tag == "Task":
            rec.task = _text(c)
        elif tag == "Opcode":
            rec.opcode = _text(c)
        elif tag == "Keywords":
            rec.keywords = _text(c)
        elif tag == "Channel":
            rec.channel = _text(c)
        elif tag == "Computer":
            rec.computer = _text(c)
        elif tag == "TimeCreated":
            rec.time_created_utc = _attr(c, "SystemTime")
        elif tag == "Security":
            rec.user_id = _attr(c, "UserID")
        elif tag == "Execution":
            rec.process_id = _attr(c, "ProcessID")
            rec.thread_id = _attr(c, "ThreadID")
        elif tag == "Correlation":
            rec.activity_id = _attr(c, "ActivityID")


def _fill_data(rec: EventRecord, datael: Element) -> None:
    idx = 0
    for c in datael.children:
        if not isinstance(c, Element):
            continue
        tag = c.name.split("}")[-1]
        if tag == "Data":
            key = _attr(c, "Name")
            if not key:
                key = f"Data{idx}"
                idx += 1
            rec.data[key] = _text(c)
        elif any(isinstance(g, Element) for g in c.children):
            _flatten(c, tag, rec.data)      # UserData-style nested block
        else:
            rec.data[tag] = _text(c)


def _flatten(el: Element, prefix: str, out: dict) -> None:
    for c in el.children:
        if not isinstance(c, Element):
            continue
        tag = c.name.split("}")[-1]
        if any(isinstance(g, Element) for g in c.children):
            _flatten(c, tag, out)
        else:
            key = tag if tag not in out else f"{prefix}.{tag}"
            out[key] = _text(c)
