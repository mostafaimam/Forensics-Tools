"""Normalised autofill records."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Record:
    browser: str = ""
    profile: str = ""
    kind: str = ""                   # form-field | address | card
    name: str = ""                   # field name / profile label / cardholder
    value: str = ""                  # field value (masked when sensitive)
    detail: str = ""                 # address summary / card summary
    first_used: str = ""
    last_used: str = ""
    count: int = 0
    source_db: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "browser": self.browser, "profile": self.profile,
            "kind": self.kind, "name": self.name, "value": self.value,
            "detail": self.detail, "first_used": self.first_used,
            "last_used": self.last_used, "count": self.count or "",
            "source_db": self.source_db, "notable": ";".join(self.notable),
        }
