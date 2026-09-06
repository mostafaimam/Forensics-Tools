"""Turn a file into indexable text."""

from __future__ import annotations

import html
import re
import zipfile
from email import message_from_bytes
from email.policy import default as email_default
from pathlib import Path

_TEXT_EXT = {".txt", ".log", ".csv", ".tsv", ".json", ".ndjson", ".yaml",
             ".yml", ".ini", ".cfg", ".conf", ".md", ".rst", ".sql", ".py",
             ".js", ".ts", ".java", ".c", ".h", ".cpp", ".go", ".rb", ".sh",
             ".ps1", ".bat", ".pl", ".php", ".css", ".tex", ".srt", ".vtt"}
_MARKUP_EXT = {".html", ".htm", ".xhtml", ".xml", ".svg", ".rss", ".atom",
               ".plist"}
_OOXML_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
_EMAIL_EXT = {".eml", ".mht", ".mhtml"}

_TAG_RE = re.compile(r"<[^>]+>")
_ATTR_URL_RE = re.compile(
    r'(?:href|src|action|data|cite|longdesc|codebase)\s*=\s*["\']([^"\']+)["\']',
    re.I)
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

MAX_TEXT = 8 * 1024 * 1024        # cap extracted text per file


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", "replace")


def _strip_markup(text: str) -> str:
    urls = _ATTR_URL_RE.findall(text)
    body = html.unescape(_TAG_RE.sub(" ", text))
    if urls:
        body += "\n" + "\n".join(html.unescape(u) for u in urls)
    return body


def _strings(data: bytes) -> str:
    ascii_parts = (m.group(0).decode("ascii", "replace")
                   for m in _ASCII_RUN.finditer(data))
    u16_parts = (m.group(0).decode("utf-16-le", "replace")
                 for m in _UTF16_RUN.finditer(data))
    return "\n".join([*ascii_parts, *u16_parts])


def _ooxml(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as z:
            parts = []
            for name in z.namelist():
                low = name.lower()
                if low.endswith(".xml") and (
                        "document" in low or "sheet" in low or "slide" in low
                        or low.endswith("content.xml")
                        or low.startswith("word/") or low.startswith("ppt/")
                        or low.startswith("xl/")):
                    try:
                        parts.append(_strip_markup(_decode(z.read(name))))
                    except (zipfile.BadZipFile, KeyError):
                        continue
            return "\n".join(parts)
    except (zipfile.BadZipFile, OSError):
        return ""


def _email(data: bytes) -> str:
    try:
        msg = message_from_bytes(data, policy=email_default)
    except Exception:  # noqa: BLE001
        return _decode(data)
    out = []
    for hdr in ("From", "To", "Cc", "Subject", "Date"):
        if msg[hdr]:
            out.append(f"{hdr}: {msg[hdr]}")
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "text/plain":
            try:
                out.append(part.get_content())
            except Exception:  # noqa: BLE001
                pass
        elif ctype == "text/html":
            try:
                out.append(_strip_markup(part.get_content()))
            except Exception:  # noqa: BLE001
                pass
        elif part.get_filename():
            out.append(f"[attachment: {part.get_filename()}]")
    return "\n".join(out)


def extract(path: Path, *, max_size: int) -> tuple[str, str]:
    """Return (text, kind).  kind is text / markup / ooxml / email / strings."""
    ext = path.suffix.lower()
    try:
        size = path.stat().st_size
    except OSError:
        return "", "error"
    if size > max_size:
        return "", "skipped-large"

    if ext in _OOXML_EXT:
        return _ooxml(path)[:MAX_TEXT], "ooxml"
    try:
        data = path.read_bytes()
    except OSError:
        return "", "error"
    if ext in _EMAIL_EXT:
        return _email(data)[:MAX_TEXT], "email"
    if ext in _MARKUP_EXT:
        return _strip_markup(_decode(data))[:MAX_TEXT], "markup"
    if ext in _TEXT_EXT:
        return _decode(data)[:MAX_TEXT], "text"
    # unknown: is it mostly text?
    sample = data[:8192]
    if sample and sum(c < 9 or (13 < c < 32) for c in sample) / len(sample) < 0.05:
        return _decode(data)[:MAX_TEXT], "text"
    return _strings(data)[:MAX_TEXT], "strings"
