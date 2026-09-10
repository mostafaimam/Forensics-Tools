"""Parse a single Task Scheduler XML definition."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

_NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _txt(el, default=""):
    return el.text.strip() if el is not None and el.text else default


def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


@dataclass
class Action:
    kind: str = ""            # exec | comhandler
    command: str = ""
    arguments: str = ""
    working_dir: str = ""
    class_id: str = ""
    data: str = ""

    def text(self) -> str:
        if self.kind == "comhandler":
            return f"COM {self.class_id}"
        return (self.command + (" " + self.arguments if self.arguments else "")
                ).strip()


@dataclass
class Trigger:
    kind: str = ""
    description: str = ""
    enabled: bool = True


@dataclass
class TaskDef:
    author: str = ""
    reg_date: str = ""
    description: str = ""
    uri: str = ""
    source: str = ""
    hidden: bool = False
    enabled: bool = True
    principal_id: str = ""
    run_as: str = ""          # UserId / GroupId
    run_level: str = ""       # LeastPrivilege | HighestAvailable
    logon_type: str = ""
    triggers: list = field(default_factory=list)      # Trigger
    actions: list = field(default_factory=list)       # Action

    def command_line(self) -> str:
        return " | ".join(a.text() for a in self.actions)


def _read_text(path) -> str:
    from pathlib import Path
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-16-le", "replace")


_TRIGGER_LABELS = {
    "TimeTrigger": "one-time", "CalendarTrigger": "calendar",
    "LogonTrigger": "at logon", "BootTrigger": "at boot",
    "RegistrationTrigger": "on registration", "EventTrigger": "on event",
    "IdleTrigger": "on idle", "SessionStateChangeTrigger": "on session change",
    "WnfStateChangeTrigger": "on WNF state change",
}


def _describe_trigger(el) -> Trigger:
    kind = _strip_ns(el.tag)
    label = _TRIGGER_LABELS.get(kind, kind)
    parts = [label]
    start = el.find(f"{_NS}StartBoundary")
    if start is not None and start.text:
        parts.append(f"from {start.text.strip()}")
    uid = el.find(f"{_NS}UserId")
    if uid is not None and uid.text:
        parts.append(f"user {uid.text.strip()}")
    for sched, word in (("ScheduleByDay", "daily"),
                        ("ScheduleByWeek", "weekly"),
                        ("ScheduleByMonth", "monthly")):
        if el.find(f"{_NS}{sched}") is not None:
            parts.append(word)
    rep = el.find(f"{_NS}Repetition/{_NS}Interval")
    if rep is not None and rep.text:
        parts.append(f"repeat every {rep.text.strip()}")
    sub = el.find(f"{_NS}Subscription")
    if sub is not None and sub.text:
        parts.append("event: " + re.sub(r"\s+", " ", sub.text.strip())[:120])
    enabled = _txt(el.find(f"{_NS}Enabled"), "true") != "false"
    return Trigger(kind=kind, description=" ".join(parts), enabled=enabled)


def parse(path) -> TaskDef:
    text = _read_text(path)
    # tolerate a stray leading BOM / whitespace
    text = text.lstrip("﻿ \r\n\t")
    root = ET.fromstring(text)
    td = TaskDef(source=str(path))

    ri = root.find(f"{_NS}RegistrationInfo")
    if ri is not None:
        td.author = _txt(ri.find(f"{_NS}Author"))
        td.reg_date = _txt(ri.find(f"{_NS}Date"))
        td.description = _txt(ri.find(f"{_NS}Description"))
        td.uri = _txt(ri.find(f"{_NS}URI"))

    st = root.find(f"{_NS}Settings")
    if st is not None:
        td.hidden = _txt(st.find(f"{_NS}Hidden"), "false") == "true"
        td.enabled = _txt(st.find(f"{_NS}Enabled"), "true") != "false"

    princ = root.find(f"{_NS}Principals")
    if princ is not None:
        p = princ.find(f"{_NS}Principal")
        if p is not None:
            td.principal_id = p.get("id", "")
            td.run_as = _txt(p.find(f"{_NS}UserId")) or \
                _txt(p.find(f"{_NS}GroupId"))
            td.run_level = _txt(p.find(f"{_NS}RunLevel"))
            td.logon_type = _txt(p.find(f"{_NS}LogonType"))

    trg = root.find(f"{_NS}Triggers")
    if trg is not None:
        for el in list(trg):
            td.triggers.append(_describe_trigger(el))

    acts = root.find(f"{_NS}Actions")
    if acts is not None:
        for el in list(acts):
            tag = _strip_ns(el.tag)
            if tag == "Exec":
                td.actions.append(Action(
                    kind="exec",
                    command=_txt(el.find(f"{_NS}Command")),
                    arguments=_txt(el.find(f"{_NS}Arguments")),
                    working_dir=_txt(el.find(f"{_NS}WorkingDirectory"))))
            elif tag == "ComHandler":
                td.actions.append(Action(
                    kind="comhandler",
                    class_id=_txt(el.find(f"{_NS}ClassId")),
                    data=_txt(el.find(f"{_NS}Data"))[:200]))
    return td
