"""OOXML (docx / xlsx / pptx) core / app / custom properties + macro detect."""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from xml.etree import ElementTree as ET

_CORE_MAP = {
    "title": "title", "subject": "subject", "creator": "author",
    "keywords": "keywords", "description": "comments",
    "lastModifiedBy": "last_saved_by", "revision": "revision_number",
    "created": "created", "modified": "last_saved",
    "lastPrinted": "last_printed", "category": "category",
    "contentStatus": "content_status",
}
_APP_MAP = {
    "Application": "application", "AppVersion": "app_version",
    "Company": "company", "Manager": "manager", "Template": "template",
    "TotalTime": "total_edit_time", "Pages": "page_count",
    "Words": "word_count", "Characters": "char_count", "Slides": "slide_count",
    "Paragraphs": "paragraph_count", "HyperlinkBase": "hyperlink_base",
    "DocSecurity": "security",
}


@dataclass
class Ooxml:
    is_ooxml: bool = False
    kind: str = ""
    props: dict = field(default_factory=dict)
    parts: list = field(default_factory=list)
    macros: bool = False
    macro_parts: list = field(default_factory=list)
    embedded: list = field(default_factory=list)
    external_targets: list = field(default_factory=list)
    error: str = ""


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text_props(xml: bytes, mapping: dict) -> dict:
    out: dict = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for el in root.iter():
        ln = _localname(el.tag)
        if ln in mapping and (el.text or "").strip():
            out[mapping[ln]] = el.text.strip()
    return out


def _custom_props(xml: bytes) -> dict:
    out: dict = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return out
    for prop in root:
        name = prop.get("name")
        if not name:
            continue
        val = "".join(t.text or "" for t in prop).strip()
        if val:
            out[f"custom:{name}"] = val
    return out


def parse(data: bytes) -> Ooxml:
    o = Ooxml()
    if data[:2] != b"PK":
        return o
    try:
        zf = zipfile.ZipFile(BytesIO(data))
    except zipfile.BadZipFile as e:
        o.error = str(e)
        return o
    names = set(zf.namelist())
    if "[Content_Types].xml" not in names:
        return o
    o.is_ooxml = True
    o.parts = sorted(names)

    ct = zf.read("[Content_Types].xml").decode("utf-8", "replace")
    macro = "macroEnabled" in ct or any(
        n.endswith("vbaProject.bin") for n in names)
    if "wordprocessingml" in ct or "ms-word" in ct or "word/document.xml" \
            in names:
        o.kind = "docm" if macro else "docx"
    elif "spreadsheetml" in ct or "ms-excel" in ct or "xl/workbook.xml" \
            in names:
        o.kind = "xlsm" if macro else "xlsx"
    elif "presentationml" in ct or "ms-powerpoint" in ct or \
            "ppt/presentation.xml" in names:
        o.kind = "pptm" if macro else "pptx"
    if "macroEnabled" in ct or any(
            n.endswith("vbaProject.bin") for n in names):
        o.macros = True
        o.macro_parts = [n for n in names if n.endswith("vbaProject.bin")]

    for part, mapping in (("docProps/core.xml", _CORE_MAP),
                          ("docProps/app.xml", _APP_MAP)):
        if part in names:
            o.props.update(_text_props(zf.read(part), mapping))
    if "docProps/custom.xml" in names:
        o.props.update(_custom_props(zf.read("docProps/custom.xml")))

    o.embedded = sorted(n for n in names
                        if "/embeddings/" in n or "/oleObject" in n.lower()
                        or n.lower().endswith((".bin", ".xlsx", ".docx"))
                        and "embeddings" in n)

    # external relationship targets (remote templates, linked images, DDE)
    for n in names:
        if n.endswith(".rels"):
            rel = zf.read(n).decode("utf-8", "replace")
            for m in re.finditer(r'Target="([^"]+)"\s+TargetMode="External"',
                                 rel):
                o.external_targets.append(m.group(1))
            for m in re.finditer(r'TargetMode="External"\s+Target="([^"]+)"',
                                 rel):
                o.external_targets.append(m.group(1))
    o.external_targets = sorted(set(o.external_targets))
    return o
