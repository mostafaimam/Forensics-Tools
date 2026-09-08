"""The normalised cache-entry record."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Entry:
    browser: str = ""
    profile: str = ""
    cache: str = ""                  # simple | cache2 | blockfile
    url: str = ""
    method: str = "GET"
    status: int = 0
    reason: str = ""
    content_type: str = ""
    content_encoding: str = ""
    declared_length: int = 0
    body_size: int = 0
    request_time: str = ""
    response_time: str = ""
    last_fetched: str = ""
    expires: str = ""
    last_modified: str = ""
    server: str = ""
    etag: str = ""
    fetch_count: int = 0
    entry_file: str = ""
    sha256: str = ""                 # of the (decoded) body, filled by --extract
    saved_as: str = ""
    truncated: bool = False
    notable: list = field(default_factory=list)
    _body: bytes = field(default=b"", repr=False)

    @property
    def filename(self) -> str:
        path = self.url.split("?", 1)[0].split("#", 1)[0].rstrip("/")
        if "://" in path:
            path = path.split("://", 1)[1]
            path = path[path.find("/") + 1:] if "/" in path else ""
        base = path.rsplit("/", 1)[-1]
        return base

    def row(self) -> dict:
        return {
            "response_time": self.response_time,
            "last_fetched": self.last_fetched,
            "browser": self.browser, "profile": self.profile,
            "cache": self.cache, "method": self.method,
            "status": self.status or "", "url": self.url,
            "content_type": self.content_type,
            "content_encoding": self.content_encoding,
            "declared_length": self.declared_length or "",
            "body_size": self.body_size,
            "request_time": self.request_time,
            "expires": self.expires, "last_modified": self.last_modified,
            "server": self.server, "etag": self.etag,
            "fetch_count": self.fetch_count or "",
            "entry_file": self.entry_file, "sha256": self.sha256,
            "saved_as": self.saved_as,
            "truncated": "yes" if self.truncated else "",
            "notable": ";".join(self.notable),
        }
