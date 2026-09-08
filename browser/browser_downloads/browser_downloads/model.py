"""The normalised download record."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Download:
    browser: str = ""
    profile: str = ""
    source: str = ""                 # history db | crdownload | zone.identifier
    url: str = ""
    referrer: str = ""
    tab_url: str = ""
    target_path: str = ""
    start_time: str = ""
    end_time: str = ""
    received_bytes: int = 0
    total_bytes: int = 0
    state: str = ""
    danger: str = ""
    interrupt: str = ""
    mime: str = ""
    opened: str = ""
    # filesystem correlation
    on_disk: str = ""                # "" | present | missing | partial
    disk_size: int = 0
    sha256: str = ""
    zone_id: str = ""
    zone_host: str = ""
    zone_referrer: str = ""
    source_db: str = ""
    notable: list = field(default_factory=list)

    @property
    def filename(self) -> str:
        p = self.target_path.replace("\\", "/").rstrip("/")
        return p.rsplit("/", 1)[-1] if p else ""

    def row(self) -> dict:
        return {
            "start_time": self.start_time, "end_time": self.end_time,
            "browser": self.browser, "profile": self.profile,
            "source": self.source, "filename": self.filename,
            "target_path": self.target_path, "url": self.url,
            "referrer": self.referrer or self.tab_url,
            "received_bytes": self.received_bytes,
            "total_bytes": self.total_bytes, "state": self.state,
            "danger": self.danger, "interrupt": self.interrupt,
            "mime": self.mime, "opened": self.opened,
            "on_disk": self.on_disk, "disk_size": self.disk_size or "",
            "sha256": self.sha256,
            "zone_id": self.zone_id, "zone_host": self.zone_host,
            "zone_referrer": self.zone_referrer,
            "source_db": self.source_db,
            "notable": ";".join(self.notable),
        }
