"""Heuristic flags for a Timeline activity."""

from __future__ import annotations

import re

_WRITABLE = re.compile(r"[\\/](appdata[\\/]|temp[\\/]|tmp[\\/]|"
                       r"programdata[\\/]|public[\\/]|downloads[\\/]|"
                       r"windows[\\/]temp[\\/]|perflogs[\\/]|"
                       r"\$recycle\.bin[\\/])", re.I)
_LOLBIN = re.compile(r"[\\/](powershell|pwsh|mshta|rundll32|regsvr32|wscript|"
                     r"cscript|certutil|bitsadmin|installutil|msbuild|wmic|"
                     r"cmd)\.exe$", re.I)
_SCRIPT = re.compile(r"\.(ps1|psm1|bat|cmd|hta|vbs|js|jse|wsf|py|pl)($|\?)",
                     re.I)
_SECRET = re.compile(r"(password|passwd|secret|api[_-]?key|token|"
                     r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|"
                     r"aws_secret_access_key|-----BEGIN)", re.I)


def _local(uri: str) -> str:
    if uri.lower().startswith("file:"):
        return uri[5:].lstrip("/").replace("/", "\\")
    return uri


def flag(a) -> list[str]:
    out: list[str] = []
    app = a.app or ""
    uri = _local(a.content_uri or "")

    if _WRITABLE.search(app):
        out.append(f"app runs from a user-writable path ({app})")
    if _LOLBIN.search(app):
        out.append(f"living-off-the-land binary activity ({app.split(chr(92))[-1]})")
    if _WRITABLE.search(uri) or _SCRIPT.search(uri):
        out.append(f"opened a file in a writable / script path ({uri})")
    if a.content_uri.lower().startswith(("http://", "https://")) and \
            re.search(r"://(\d{1,3}\.){3}\d{1,3}", a.content_uri):
        out.append("content URI with an IP-literal host")

    if a.clipboard_text:
        if _SECRET.search(a.clipboard_text):
            out.append("clipboard capture contains a secret-looking string")
        elif len(a.clipboard_text) > 400:
            out.append("large clipboard capture recorded")
        else:
            out.append("clipboard content recorded in the timeline")

    if a.from_operation:
        out.append("from ActivityOperation (pending sync / possibly removed "
                   "from the visible timeline)")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "app runs from a user-writable path": "high",
    "living-off-the-land binary activity": "medium",
    "opened a file in a writable / script path": "medium",
    "content URI with an IP-literal host": "medium",
    "clipboard capture contains a secret-looking string": "high",
    "large clipboard capture recorded": "low",
    "clipboard content recorded in the timeline": "low",
    "from ActivityOperation": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
