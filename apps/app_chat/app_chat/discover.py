"""Locate a chat app's LevelDB (Local Storage / IndexedDB) directories."""

from __future__ import annotations

from pathlib import Path

from app_chat.store import find_dirs

_APP_KEYWORDS = {
    "slack": ("slack",),
    "discord": ("discord",),
    "teams": ("teams",),
}


def find_app_dirs(root: str, app: str) -> list[Path]:
    keywords = _APP_KEYWORDS.get(app, (app.lower(),))
    dirs = find_dirs(root)
    return [d for d in dirs
           if any(k in seg.lower() for seg in d.parts for k in keywords)]


def detect_apps(root: str) -> dict[str, list[Path]]:
    return {app: find_app_dirs(root, app) for app in _APP_KEYWORDS}
