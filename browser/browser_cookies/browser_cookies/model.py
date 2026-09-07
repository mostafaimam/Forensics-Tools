"""Normalised cookie row."""

from __future__ import annotations

from dataclasses import dataclass, field

_SAMESITE = {-1: "unspecified", 0: "none", 1: "lax", 2: "strict"}


@dataclass
class Cookie:
    browser: str
    profile: str
    host: str
    name: str
    path: str
    created: str = ""
    expires: str = ""
    last_access: str = ""
    secure: bool = False
    http_only: bool = False
    samesite: str = "unspecified"
    session: bool = False           # no persistent expiry
    value_len: int = 0
    value: str = ""                 # only when --with-values and plaintext
    source_db: str = ""
    notable: list = field(default_factory=list)

    def row(self, with_values: bool = False) -> dict:
        r = {
            "browser": self.browser, "profile": self.profile,
            "host": self.host, "name": self.name, "path": self.path,
            "created": self.created, "last_access": self.last_access,
            "expires": self.expires,
            "session": "yes" if self.session else "",
            "secure": "yes" if self.secure else "",
            "http_only": "yes" if self.http_only else "",
            "samesite": self.samesite,
            "value_len": self.value_len,
            "notable": ";".join(self.notable),
            "source_db": self.source_db,
        }
        if with_values:
            r["value"] = self.value
        return r
