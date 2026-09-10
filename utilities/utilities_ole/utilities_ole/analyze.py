"""Top-level: sniff the container, extract structure + properties + flags."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from utilities_ole import ooxml as _ooxml
from utilities_ole import props as _props
from utilities_ole import vba as _vba
from utilities_ole.ole import OleError, OleFile

_OLE_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MACRO_SUS = re.compile(
    r"\b(Auto_?Open|AutoOpen|Document_Open|Workbook_Open|AutoExec|"
    r"Auto_?Close|Shell|WScript\.Shell|CreateObject|GetObject|"
    r"URLDownloadToFile|MSXML2|WinHttp|XmlHttp|ADODB\.Stream|"
    r"Environ|Chr\s*\(|StrReverse|Xor\b|powershell|cmd\.exe|"
    r"ExecuteExcel4Macro|CallByName|Application\.Run|"
    r"VBA\.CreateObject|Kill\b|Open\b.+\bFor\s+Output)", re.I)


@dataclass
class OleReport:
    path: str
    container: str = ""            # ole2 | ooxml | unknown
    doc_kind: str = ""
    streams: list = field(default_factory=list)      # (path, size, kind)
    properties: dict = field(default_factory=dict)
    macros: bool = False
    macro_modules: list = field(default_factory=list)  # (name, lines, susp)
    embedded: list = field(default_factory=list)
    external_targets: list = field(default_factory=list)
    notable: list = field(default_factory=list)
    severity: str = "none"
    error: str = ""

    def rows(self) -> list[dict]:
        out = []
        for k, v in self.properties.items():
            out.append({"kind": "property", "name": k, "value": str(v),
                        "detail": "", "source": self.path})
        for name, lines, susp in self.macro_modules:
            out.append({"kind": "macro-module", "name": name,
                        "value": f"{lines} line(s)",
                        "detail": "; ".join(susp), "source": self.path})
        for e in self.embedded:
            out.append({"kind": "embedded-object", "name": e, "value": "",
                        "detail": "", "source": self.path})
        for t in self.external_targets:
            out.append({"kind": "external-target", "name": t, "value": "",
                        "detail": "", "source": self.path})
        for p, sz, knd in self.streams:
            out.append({"kind": "stream", "name": p, "value": str(sz),
                        "detail": knd, "source": self.path})
        return out


_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _flag(rep: OleReport):
    n = rep.notable
    sev = "none"

    def bump(t):
        nonlocal sev
        if _ORDER[t] > _ORDER[sev]:
            sev = t

    if rep.macros:
        n.append("contains VBA macros")
        bump("medium")
    for _name, _lines, susp in rep.macro_modules:
        if susp:
            n.append("macro uses auto-exec / shell / download constructs")
            bump("high")
            break
    p = rep.properties
    author = str(p.get("author", "")).strip().lower()
    saver = str(p.get("last_saved_by", "")).strip().lower()
    if author and saver and author != saver:
        n.append(f"different author ({p['author']}) and last-saver "
                 f"({p['last_saved_by']})")
        bump("low")
    tmpl = str(p.get("template", ""))
    if tmpl.startswith(("http://", "https://", "\\\\", "//")):
        n.append(f"remote / UNC template: {tmpl}")
        bump("high")
    for t in rep.external_targets:
        if t.startswith(("http://", "https://", "\\\\", "mhtml:", "file:")):
            n.append(f"external relationship target: {t}")
            bump("medium")
    et = str(p.get("total_edit_time", ""))
    rev = str(p.get("revision_number", ""))
    if et in ("0:00:00", "0", "") and rev.isdigit() and int(rev) > 3:
        n.append("high revision count with zero total editing time")
        bump("low")
    if rep.embedded:
        n.append(f"{len(rep.embedded)} embedded object(s)")
        bump("low")
    rep.severity = sev


def analyze(path: str) -> OleReport:
    rep = OleReport(path=path)
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        rep.error = str(e)
        return rep

    if data[:8] == _OLE_SIG:
        rep.container = "ole2"
        try:
            ole = OleFile(data)
        except OleError as e:
            rep.error = str(e)
            return rep
        for p, e in ole.walk():
            if e.entry_type == 2:
                knd = ""
                if p.startswith("\x05"):
                    knd = "property set"
                rep.streams.append((p, e.size, knd))
        for cand in ("\x05SummaryInformation",
                     "\x05DocumentSummaryInformation"):
            for p, e in ole.walk():
                if p == cand and e.entry_type == 2:
                    rep.properties.update(
                        _props.parse_property_stream(ole.read_path(p)))
        vp = _vba.extract(ole)
        rep.macros = vp.present
        for m in vp.modules:
            susp = sorted(set(_MACRO_SUS.findall(m.source or "")))
            rep.macro_modules.append(
                (m.name, len((m.source or "").splitlines()), susp))
        _flag(rep)
        return rep

    if data[:2] == b"PK":
        o = _ooxml.parse(data)
        if o.is_ooxml:
            rep.container = "ooxml"
            rep.doc_kind = o.kind
            rep.properties = o.props
            rep.macros = o.macros
            rep.embedded = o.embedded
            rep.external_targets = o.external_targets
            rep.streams = [(n, 0, "") for n in o.parts]
            if o.macros:
                # OOXML VBA lives in an embedded OLE (vbaProject.bin)
                import zipfile
                from io import BytesIO
                try:
                    zf = zipfile.ZipFile(BytesIO(data))
                    for mp in o.macro_parts:
                        vp = _vba.extract(OleFile(zf.read(mp)))
                        for m in vp.modules:
                            susp = sorted(set(_MACRO_SUS.findall(
                                m.source or "")))
                            rep.macro_modules.append(
                                (m.name,
                                 len((m.source or "").splitlines()), susp))
                except Exception:  # noqa: BLE001
                    pass
            _flag(rep)
            return rep
        rep.error = o.error or "PK container but not OOXML"
        return rep

    rep.container = "unknown"
    rep.error = "not an OLE2 or OOXML file"
    return rep
