"""Recover event-subscription objects from repository strings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CONSUMER_CLASSES = (
    "CommandLineEventConsumer", "ActiveScriptEventConsumer",
    "LogFileEventConsumer", "NTEventLogEventConsumer", "SMTPEventConsumer",
    "ScriptingStandardConsumerSetting",
)
_NAME_IN_REF = re.compile(r'(?:__EventFilter|EventConsumer|Filter|Consumer)'
                          r'\.Name="([^"]+)"', re.I)
_NAMESPACE = re.compile(r'\\\\[.\w-]+\\(root\\[\w\\]+)', re.I)
_WQL = re.compile(r"\bSELECT\b\s+.+?\s+\bFROM\b\s+.+", re.I | re.S)
_BAD_NAME = {
    "__eventfilter", "__filtertoconsumerbinding", "__eventconsumer",
    "commandlineeventconsumer", "activescripteventconsumer",
    "logfileeventconsumer", "nteventlogeventconsumer", "smtpeventconsumer",
    "scriptingstandardconsumersetting", "__win32provider", "__namespace",
    "jscript", "vbscript", "select", "true", "false",
}


def _name_ok(t: str) -> bool:
    t = t.strip()
    if not (2 <= len(t) <= 80):
        return False
    if t.lower() in _BAD_NAME:
        return False
    if t.startswith(("\\", "//", "root", "SELECT", "select")):
        return False
    if t.lower().endswith((".vbs", ".js", ".jse", ".ps1", ".exe", ".dll",
                           ".bat", ".log")):
        return False
    return bool(re.match(r"^[\w .$@-]+$", t))


@dataclass
class WmiObject:
    otype: str                       # filter | consumer | binding
    cls: str
    name: str = ""
    namespace: str = ""
    query: str = ""
    action: str = ""
    action_kind: str = ""
    filter_ref: str = ""
    consumer_ref: str = ""
    offset: int = 0
    live: bool = True
    source: str = ""
    strings: list = field(default_factory=list)
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "type": self.otype, "class": self.cls, "name": self.name,
            "namespace": self.namespace, "query": self.query[:2000],
            "action_kind": self.action_kind, "action": self.action[:4000],
            "filter": self.filter_ref, "consumer": self.consumer_ref,
            "offset": self.offset, "live": self.live, "source": self.source,
            "notable": ";".join(self.notable),
        }


def _window_text(repo, offset):
    return [s.text for s in repo.near(offset)]


def _first(strs, pred, default=""):
    for s in strs:
        if pred(s):
            return s
    return default


def _extract_filters(repo):
    out = []
    data = repo.objects
    for m in re.finditer(rb"__EventFilter\x00", data):
        off = m.start()
        strs = _window_text(repo, off)
        query = ""
        for s in strs:
            if _WQL.search(s):
                query = re.sub(r"\s+", " ", s).strip()
                break
        name = ""
        for s in strs:
            if _name_ok(s):
                name = s.strip()
                break
        nsm = None
        for s in strs:
            nsm = _NAMESPACE.search(s)
            if nsm:
                break
        if not query and not name:
            continue
        out.append(WmiObject(
            otype="filter", cls="__EventFilter", name=name,
            namespace=(nsm.group(1) if nsm else ""), query=query,
            offset=off, live=repo.page_live(off), source=repo.source,
            strings=strs))
    return out


def _extract_consumers(repo):
    out = []
    data = repo.objects
    for cls in _CONSUMER_CLASSES:
        for m in re.finditer(cls.encode() + rb"\x00", data):
            off = m.start()
            strs = _window_text(repo, off)
            name = ""
            action = ""
            akind = ""
            for s in strs:
                t = s.strip()
                if cls == "CommandLineEventConsumer":
                    if re.search(r"\.exe\b|powershell|cmd(?:\.exe)?|/c |"
                                 r"-enc |rundll32|mshta|wscript|cscript|"
                                 r"regsvr32", t, re.I) and len(t) > len(action):
                        action, akind = t, "command-line"
                elif cls == "ActiveScriptEventConsumer":
                    if re.search(r"(CreateObject|GetObject|WScript|eval\(|"
                                 r"function |Set \w+ ?=|powershell|"
                                 r"MSXML2|WinHttp|ADODB|\.Run\b|Xmlhttp)",
                                 t, re.I) and len(t) > len(action):
                        action, akind = t, "script"
                    if t.lower().endswith((".vbs", ".js", ".ps1", ".jse")):
                        action = action or t
                        akind = akind or "script-file"
                elif cls in ("LogFileEventConsumer", "NTEventLogEventConsumer",
                             "SMTPEventConsumer"):
                    if len(t) > len(action) and 3 < len(t) < 500 and \
                            "EventConsumer" not in t and \
                            not t.startswith("\\\\") and not _name_ok(t):
                        action, akind = t, cls.replace("EventConsumer", "")\
                            .lower()
            for s in strs:
                if _name_ok(s):
                    name = s.strip()
                    break
            nsm = None
            for s in strs:
                nsm = _NAMESPACE.search(s)
                if nsm:
                    break
            if not action and not name:
                continue
            out.append(WmiObject(
                otype="consumer", cls=cls, name=name,
                namespace=(nsm.group(1) if nsm else ""),
                action=action, action_kind=akind or cls,
                offset=off, live=repo.page_live(off), source=repo.source,
                strings=strs))
    return out


def _extract_bindings(repo):
    out = []
    data = repo.objects
    for m in re.finditer(rb"__FilterToConsumerBinding\x00", data):
        off = m.start()
        strs = _window_text(repo, off, )
        frefs, crefs = [], []
        for s in strs:
            for rm in _NAME_IN_REF.finditer(s):
                whole = rm.group(0).lower()
                if "consumer" in whole:
                    crefs.append(rm.group(1))
                else:
                    frefs.append(rm.group(1))
            if "EventConsumer" in s and 'Name="' in s and \
                    s not in (c for c in crefs):
                mm = re.search(r'Name="([^"]+)"', s)
                if mm and "consumer" in s.lower():
                    crefs.append(mm.group(1))
        nsm = None
        for s in strs:
            nsm = _NAMESPACE.search(s)
            if nsm:
                break
        if not frefs and not crefs:
            continue
        out.append(WmiObject(
            otype="binding", cls="__FilterToConsumerBinding",
            namespace=(nsm.group(1) if nsm else ""),
            filter_ref=frefs[0] if frefs else "",
            consumer_ref=crefs[0] if crefs else "",
            offset=off, live=repo.page_live(off), source=repo.source,
            strings=strs))
    return out


def extract(repo) -> list[WmiObject]:
    objs = (_extract_filters(repo) + _extract_consumers(repo)
            + _extract_bindings(repo))
    # de-dup by (type, class, name, action/query, offset//0x400)
    seen = set()
    uniq = []
    for o in objs:
        key = (o.otype, o.cls, o.name, o.query[:60], o.action[:60],
               o.offset // 0x800)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(o)
    return uniq
