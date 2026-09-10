"""Sniff a file and extract a plain-text (or tabular) rendering."""

from __future__ import annotations

import csv as _csv
import html as _html
import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from email import message_from_bytes
from pathlib import Path
from xml.etree import ElementTree as ET

_OLE_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


@dataclass
class View:
    path: str
    fmt: str = "unknown"
    encoding: str = ""
    text: str = ""
    rows: list = field(default_factory=list)     # for csv/xlsx: list[list]
    truncated: bool = False
    note: str = ""
    error: str = ""


# -- helpers -------------------------------------------------------------

def _decode_text(raw: bytes) -> tuple[str, str]:
    for bom, enc in ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"),
                     (b"\xef\xbb\xbf", "utf-8-sig")):
        if raw.startswith(bom):
            return raw.decode(enc, "replace"), enc
    sample = raw[:4096]
    zeros = sample.count(0)
    if sample and zeros / len(sample) > 0.25:
        odd = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
        even = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
        if odd > even * 2:
            return raw.decode("utf-16-le", "replace"), "utf-16-le"
        if even > odd * 2:
            return raw.decode("utf-16-be", "replace"), "utf-16-be"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace"), "latin-1"


class _HTMLStrip:
    _SKIP = {"script", "style", "head", "noscript"}

    def __call__(self, markup: str) -> str:
        from html.parser import HTMLParser

        buf: list[str] = []
        skip = [0]

        class P(HTMLParser):
            def handle_starttag(s, tag, attrs):
                if tag in _HTMLStrip._SKIP:
                    skip[0] += 1
                if tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3"):
                    buf.append("\n")

            def handle_endtag(s, tag):
                if tag in _HTMLStrip._SKIP and skip[0]:
                    skip[0] -= 1

            def handle_data(s, data):
                if not skip[0]:
                    buf.append(data)

        p = P()
        p.feed(markup)
        text = _html.unescape("".join(buf))
        return re.sub(r"[ \t]*\n[ \t]*", "\n",
                      re.sub(r"[ \t]{2,}", " ", text)).strip()


_strip_html = _HTMLStrip()


def _rtf_to_text(data: bytes) -> str:
    s = data.decode("latin-1", "replace")
    s = re.sub(r"\\'([0-9a-fA-F]{2})",
               lambda m: bytes([int(m.group(1), 16)]).decode("latin-1"), s)
    s = re.sub(r"\\u(-?\d+)\s?\??",
               lambda m: chr(int(m.group(1)) % 0x110000), s)
    s = re.sub(r"\\par[d]?\b", "\n", s)
    s = re.sub(r"\\line\b", "\n", s)
    s = re.sub(r"\\tab\b", "\t", s)
    s = re.sub(r"\{\\\*.*?\}", "", s, flags=re.S)     # groups like \*\fonttbl
    s = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", s)          # remaining control words
    s = s.replace("{", "").replace("}", "").replace("\\\n", "\n")
    return re.sub(r"\n{3,}", "\n\n", s).strip()


_XL = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"


def _docx_text(zf: zipfile.ZipFile) -> str:
    if "word/document.xml" not in zf.namelist():
        return ""
    root = ET.fromstring(zf.read("word/document.xml"))
    out: list[str] = []
    for para in root.iter(f"{_W}p"):
        runs = "".join(t.text or "" for t in para.iter(f"{_W}t"))
        out.append(runs)
    return "\n".join(out).strip()


def _pptx_text(zf: zipfile.ZipFile) -> str:
    slides = sorted(n for n in zf.namelist()
                    if re.match(r"ppt/slides/slide\d+\.xml$", n))
    out: list[str] = []
    for i, s in enumerate(slides, 1):
        root = ET.fromstring(zf.read(s))
        txt = "\n".join(t.text or "" for t in root.iter(f"{_A}t") if t.text)
        out.append(f"--- slide {i} ---\n{txt}")
    return "\n\n".join(out).strip()


def _col_idx(ref: str) -> int:
    m = re.match(r"([A-Z]+)", ref or "A")
    n = 0
    for c in m.group(1) if m else "A":
        n = n * 26 + (ord(c) - 64)
    return n - 1


def _xlsx_rows(zf: zipfile.ZipFile) -> list[list[str]]:
    shared: list[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        r = ET.fromstring(zf.read("xl/sharedStrings.xml"))
        for si in r.findall(f"{_XL}si"):
            shared.append("".join(t.text or "" for t in si.iter(f"{_XL}t")))
    sheets = sorted(n for n in zf.namelist()
                    if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
    if not sheets:
        return []
    root = ET.fromstring(zf.read(sheets[0]))
    grid: list[list[str]] = []
    for row in root.iter(f"{_XL}row"):
        cells: dict[int, str] = {}
        for c in row.findall(f"{_XL}c"):
            idx = _col_idx(c.get("r", "A1"))
            v = c.find(f"{_XL}v")
            t = c.get("t")
            if t == "s" and v is not None and v.text is not None:
                si = int(v.text)
                cells[idx] = shared[si] if si < len(shared) else ""
            elif t == "inlineStr":
                isn = c.find(f"{_XL}is")
                cells[idx] = "".join(x.text or ""
                                     for x in isn.iter(f"{_XL}t")) \
                    if isn is not None else ""
            elif v is not None:
                cells[idx] = v.text or ""
        width = (max(cells) + 1) if cells else 0
        grid.append([cells.get(i, "") for i in range(width)])
    return grid


def _pdf_text(data: bytes, cap: int = 400_000) -> str:
    chunks: list[str] = []
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        blob = m.group(1)
        payload = blob
        for _ in range(1):
            try:
                payload = zlib.decompress(blob)
                break
            except zlib.error:
                payload = blob
        for tm in re.finditer(rb"\((?:\\.|[^()\\])*\)\s*Tj", payload):
            chunks.append(_pdf_str(tm.group(0)))
        for tm in re.finditer(rb"\[(.*?)\]\s*TJ", payload, re.S):
            parts = re.findall(rb"\((?:\\.|[^()\\])*\)", tm.group(1))
            chunks.append("".join(_pdf_str(p) for p in parts))
        if sum(len(c) for c in chunks) > cap:
            break
    return re.sub(r"\n{3,}", "\n\n", "\n".join(c for c in chunks if c.strip()))


def _pdf_str(raw: bytes) -> str:
    s = raw
    s = s[s.find(b"(") + 1: s.rfind(b")")]
    s = re.sub(rb"\\([nrtbf()\\])",
               lambda m: {b"n": b"\n", b"r": b"\r", b"t": b"\t",
                          b"b": b"\b", b"f": b"\f"}.get(m.group(1),
                                                       m.group(1)), s)
    return s.decode("latin-1", "replace")


def _printable_runs(data: bytes, min_len: int = 4) -> str:
    runs = re.findall(rb"[\x09\x0a\x0d\x20-\x7e]{%d,}" % min_len, data)
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    text = b"\n".join(runs).decode("latin-1", "replace")
    wtext = b"".join(wide).decode("utf-16-le", "replace")
    return (wtext + "\n" + text).strip() if wtext else text


# -- main dispatch -----------------------------------------------------

def render(path: str, *, max_chars: int = 2_000_000) -> View:
    v = View(path=path)
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        v.error = str(e)
        return v

    head = raw[:8]
    lower = path.lower()

    try:
        if head[:2] == b"PK":
            zf = zipfile.ZipFile(io.BytesIO(raw))
            names = set(zf.namelist())
            if "word/document.xml" in names:
                v.fmt = "docx"
                v.text = _docx_text(zf)
            elif any(n.startswith("xl/worksheets/") for n in names):
                v.fmt = "xlsx"
                v.rows = _xlsx_rows(zf)
                v.text = "\n".join("\t".join(r) for r in v.rows[:2000])
            elif any(n.startswith("ppt/slides/") for n in names):
                v.fmt = "pptx"
                v.text = _pptx_text(zf)
            else:
                v.fmt = "zip"
                v.text = "\n".join(sorted(names))
        elif head == _OLE_SIG:
            from utilities_ezview.ole import OleFile
            ole = OleFile(raw)
            streams = {p for p, _e in ole.walk()}
            if "WordDocument" in streams:
                v.fmt = "doc"
                v.text = _printable_runs(ole.read_path("WordDocument"))
                v.note = "legacy .doc: printable-text extraction only"
            elif "Workbook" in streams or "Book" in streams:
                v.fmt = "xls"
                nm = "Workbook" if "Workbook" in streams else "Book"
                v.text = _printable_runs(ole.read_path(nm))
                v.note = "legacy .xls: printable-text extraction only"
            else:
                v.fmt = "ole2"
                v.text = "streams:\n" + "\n".join(sorted(streams))
        elif head[:4] == b"%PDF":
            v.fmt = "pdf"
            v.text = _pdf_text(raw)
            if not v.text.strip():
                v.note = "no extractable text (scanned / encrypted / " \
                         "unusual encoding)"
        elif head[:5].lower() == b"{\\rtf":
            v.fmt = "rtf"
            v.text = _rtf_to_text(raw)
        elif b"MIME-Version:" in raw[:2048] and (b"multipart/related"
                                                 in raw[:4096]
                                                 or lower.endswith(
                                                     (".mht", ".mhtml"))):
            v.fmt = "mhtml"
            msg = message_from_bytes(raw)
            htmlpart = ""
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    htmlpart = part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "replace")
                    break
            v.text = _strip_html(htmlpart) if htmlpart else _printable_runs(raw)
        else:
            text, enc = _decode_text(raw)
            v.encoding = enc
            stripped = text.lstrip()[:512].lower()
            if "<html" in stripped or "<!doctype html" in stripped or \
                    lower.endswith((".htm", ".html")):
                v.fmt = "html"
                v.text = _strip_html(text)
            elif lower.endswith((".csv", ".tsv")) or _looks_csv(text):
                v.fmt = "csv"
                delim = "\t" if (lower.endswith(".tsv")
                                 or text[:200].count("\t") > text[:200]
                                 .count(",")) else ","
                v.rows = list(_csv.reader(io.StringIO(text), delimiter=delim))
                v.text = "\n".join(delim.join(r) for r in v.rows[:5000])
            else:
                v.fmt = "text"
                v.text = text
    except (zipfile.BadZipFile, ET.ParseError, Exception) as e:  # noqa: BLE001
        v.error = f"{type(e).__name__}: {e}"
        if not v.text:
            v.text = _printable_runs(raw)
            v.fmt = v.fmt if v.fmt != "unknown" else "binary"

    if len(v.text) > max_chars:
        v.text = v.text[:max_chars]
        v.truncated = True
    return v


def _looks_csv(text: str) -> bool:
    lines = [ln for ln in text.splitlines()[:10] if ln.strip()]
    if len(lines) < 2:
        return False
    counts = [ln.count(",") for ln in lines]
    return counts[0] >= 1 and len(set(counts)) <= 2
