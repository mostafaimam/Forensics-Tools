"""Heuristic flags for a knowledgeC event."""

from __future__ import annotations

import re
from datetime import datetime

_CLI_APPS = {"com.apple.terminal", "com.googlecode.iterm2", "co.zeit.hyper",
             "com.apple.scripteditor2", "dev.warp.warp-stable"}
_SCRIPT_BUNDLE = re.compile(r"(osascript|python|/bin/sh|/bin/bash|/usr/bin/|"
                            r"^/tmp/|^/Users/|^/private/)", re.I)
_ANON = re.compile(r"(pastebin|paste\.ee|anonfiles|mega\.nz|transfer\.sh|"
                   r"file\.io|gofile|0x0\.st|catbox\.moe|ngrok|"
                   r"trycloudflare|duckdns|no-ip|\.onion)", re.I)
_LONG = 3600            # 1 hour continuous


def flag(e) -> list[str]:
    out: list[str] = []
    v = (e.value or "").lower()

    if e.stream_raw in ("/app/usage", "/app/inFocus"):
        if v in _CLI_APPS and e.duration_s >= _LONG:
            out.append(f"long terminal / script-editor session "
                       f"({e.duration_s // 60} min)")
        if e.bundle_id and _SCRIPT_BUNDLE.search(e.bundle_id) and \
                (e.bundle_id.startswith(("/tmp", "/Users", "/private"))):
            out.append(f"app id is an absolute path ({e.bundle_id})")

    if e.stream_raw in ("/app/webUsage", "/safari/history") and _ANON.search(v):
        out.append(f"web usage of a paste / file-sharing / tunnel site "
                   f"({e.value})")

    if e.stream_raw == "/app/intents" and re.search(
            r"(shell|terminal|run script|shortcut)", v):
        out.append(f"Siri / Shortcuts intent that runs a script ({e.value})")

    if e.stream_raw in ("/app/usage", "/app/inFocus") and e.start:
        try:
            dt = datetime.strptime(e.start[:19], "%Y-%m-%dT%H:%M:%S")
            if (dt.hour < 6 or dt.hour >= 23) and e.duration_s >= 600:
                out.append(f"app used late at night ({e.start[11:16]}, "
                           f"{e.duration_s // 60} min)")
        except ValueError:
            pass

    if e.stream_raw == "/app/install":
        out.append(f"app install recorded ({e.value})")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "long terminal / script-editor session": "medium",
    "app id is an absolute path": "high",
    "web usage of a paste / file-sharing / tunnel site": "medium",
    "Siri / Shortcuts intent that runs a script": "high",
    "app used late at night": "low",
    "app install recorded": "low",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
