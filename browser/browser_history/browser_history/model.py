"""Normalised rows shared by every browser adapter."""

from __future__ import annotations

from dataclasses import dataclass, field

# transition / visit-type -> a short common label
TRANSITION = {
    "link": "link", "typed": "typed", "bookmark": "bookmark",
    "auto_bookmark": "bookmark", "generated": "generated",
    "auto_toplevel": "start-page", "form_submit": "form-submit",
    "reload": "reload", "keyword": "keyword", "keyword_generated": "keyword",
    "redirect": "redirect", "subframe": "subframe", "embed": "embed",
    "download": "download", "framed_link": "link", "restore": "session-restore",
}


@dataclass
class Visit:
    browser: str
    profile: str
    url: str
    title: str
    visit_time: str            # UTC ISO-8601
    visit_count: int
    typed: bool
    transition: str
    from_url: str = ""
    source_db: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "browser": self.browser, "profile": self.profile,
            "kind": "visit", "url": self.url, "title": self.title,
            "time": self.visit_time, "visit_count": self.visit_count,
            "typed": "yes" if self.typed else "",
            "transition": self.transition, "from_url": self.from_url,
            "detail": "", "notable": ";".join(self.notable),
            "source_db": self.source_db,
        }


@dataclass
class Download:
    browser: str
    profile: str
    url: str
    referrer: str
    target_path: str
    start_time: str
    end_time: str
    bytes: int
    total_bytes: int
    state: str
    danger: str
    mime: str
    source_db: str = ""
    tab_url: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        detail = self.target_path
        if self.bytes:
            detail += f"  ({self.bytes:,} B)"
        if self.danger and self.danger not in ("not_dangerous", "0", ""):
            detail += f"  danger={self.danger}"
        return {
            "browser": self.browser, "profile": self.profile,
            "kind": "download", "url": self.url, "title": "",
            "time": self.start_time or self.end_time,
            "visit_count": "", "typed": "", "transition": "download",
            "from_url": self.referrer or self.tab_url,
            "detail": detail, "notable": ";".join(self.notable),
            "source_db": self.source_db,
        }


@dataclass
class SearchTerm:
    browser: str
    profile: str
    term: str
    url: str
    time: str
    source_db: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "browser": self.browser, "profile": self.profile,
            "kind": "search", "url": self.url, "title": self.term,
            "time": self.time, "visit_count": "", "typed": "yes",
            "transition": "keyword", "from_url": "",
            "detail": f"searched: {self.term}",
            "notable": ";".join(self.notable), "source_db": self.source_db,
        }
