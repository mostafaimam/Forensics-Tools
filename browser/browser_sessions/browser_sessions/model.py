"""Normalised session records."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Tab:
    browser: str = ""
    profile: str = ""
    source_file: str = ""
    window: str = ""
    index: int = 0
    pinned: bool = False
    group: str = ""
    closed: bool = False              # a recently-closed tab
    current_url: str = ""
    current_title: str = ""
    entry_count: int = 0
    last_accessed: str = ""
    history: list = field(default_factory=list)     # [(url, title)]
    has_formdata: bool = False
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "last_accessed": self.last_accessed,
            "browser": self.browser, "profile": self.profile,
            "source": self.source_file, "window": self.window,
            "index": self.index, "pinned": "yes" if self.pinned else "",
            "group": self.group, "closed": "yes" if self.closed else "",
            "current_url": self.current_url,
            "current_title": self.current_title,
            "entry_count": self.entry_count,
            "history": " <- ".join(u for u, _ in reversed(self.history[-6:])),
            "has_formdata": "yes" if self.has_formdata else "",
            "notable": ";".join(self.notable),
        }
