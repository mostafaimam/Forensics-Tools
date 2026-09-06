"""A very small Markdown -> HTML converter (headings, lists, code, links, …)."""

from __future__ import annotations

import html
import re

_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITAL = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
_CODE = re.compile(r"`([^`]+)`")


def _inline(text: str) -> str:
    t = html.escape(text)
    t = _CODE.sub(lambda m: f"<code>{m.group(1)}</code>", t)
    t = _BOLD.sub(lambda m: f"<strong>{m.group(1)}</strong>", t)
    t = _ITAL.sub(lambda m: f"<em>{m.group(1)}</em>", t)
    t = _LINK.sub(lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">'
                            f"{m.group(1)}</a>", t)
    return t


def render(text: str) -> str:
    out: list[str] = []
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.startswith("```"):
            j = i + 1
            buf = []
            while j < n and not lines[j].startswith("```"):
                buf.append(lines[j])
                j += 1
            out.append("<pre><code>" + html.escape("\n".join(buf))
                       + "</code></pre>")
            i = j + 1
            continue
        m = re.match(r"(#{1,6})\s+(.*)", line)
        if m:
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_inline(m.group(2))}</h{lvl}>")
            i += 1
            continue
        if re.match(r"\s*[-*+]\s+", line):
            items = []
            while i < n and re.match(r"\s*[-*+]\s+", lines[i]):
                items.append("<li>" + _inline(re.sub(r"\s*[-*+]\s+", "",
                                                     lines[i], count=1))
                             + "</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        if re.match(r"\s*\d+\.\s+", line):
            items = []
            while i < n and re.match(r"\s*\d+\.\s+", lines[i]):
                items.append("<li>" + _inline(re.sub(r"\s*\d+\.\s+", "",
                                                     lines[i], count=1))
                             + "</li>")
                i += 1
            out.append("<ol>" + "".join(items) + "</ol>")
            continue
        if line.strip() == "":
            i += 1
            continue
        para = [line]
        i += 1
        while i < n and lines[i].strip() and not lines[i].startswith(
                ("#", "```", "-", "*", "+")):
            para.append(lines[i])
            i += 1
        out.append("<p>" + _inline(" ".join(para)) + "</p>")
    return "\n".join(out)
