"""Spotlight-specific string classification patterns."""

from __future__ import annotations

import re

# Order matters: first match wins for --classified default single-category
# output; a string can still be reported under every category it matches
# when the caller asks for multiple categories.
LIBRARY: dict[str, re.Pattern] = {
    "kmditem": re.compile(r"^kMDItem[A-Za-z0-9]+$"),
    "url": re.compile(r"^https?://\S+$", re.I),
    "uti": re.compile(
        r"^(?:public|com\.apple|dyn)\.[A-Za-z0-9][A-Za-z0-9_\-]*"
        r"(?:\.[A-Za-z0-9][A-Za-z0-9_\-]*)*$"),
    "bundle_id": re.compile(
        r"^(?!com\.apple\b)[A-Za-z][A-Za-z0-9_\-]*"
        r"(?:\.[A-Za-z0-9][A-Za-z0-9_\-]*){2,}$"),
    "path": re.compile(
        r"^/(?:Users|Applications|System|Library|private|Volumes)/\S+$"),
}


def classify(text: str, wanted: list[str] | None = None) -> list[tuple[str, str]]:
    """Return [(category, text)] for every LIBRARY pattern ``text`` matches."""
    out = []
    for name, rx in LIBRARY.items():
        if wanted and name not in wanted:
            continue
        if rx.match(text):
            out.append((name, text))
    return out
