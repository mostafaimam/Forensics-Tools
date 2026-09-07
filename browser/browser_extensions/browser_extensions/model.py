"""Normalised extension row."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Extension:
    browser: str
    profile: str
    ext_id: str
    name: str
    version: str
    description: str = ""
    install_source: str = ""       # webstore | sideload-registry | policy |
    #                                unpacked | component | default | firefox-amo
    enabled: bool = True
    disabled_reason: str = ""
    from_webstore: bool = False
    signed_state: str = ""         # firefox: signed | preliminary | unsigned |
    #                                broken | unknown
    install_time: str = ""
    update_time: str = ""
    update_url: str = ""
    homepage: str = ""
    path: str = ""
    host_permissions: list = field(default_factory=list)
    api_permissions: list = field(default_factory=list)
    optional_permissions: list = field(default_factory=list)
    content_scripts: int = 0
    background: str = ""            # persistent | event | service-worker | none
    manifest_version: int = 0
    source_file: str = ""
    notable: list = field(default_factory=list)
    risk: str = "low"

    def row(self) -> dict:
        return {
            "browser": self.browser, "profile": self.profile,
            "name": self.name, "ext_id": self.ext_id,
            "version": self.version, "enabled": "yes" if self.enabled else "",
            "install_source": self.install_source,
            "from_webstore": "yes" if self.from_webstore else "",
            "signed_state": self.signed_state,
            "install_time": self.install_time, "update_url": self.update_url,
            "host_permissions": ", ".join(self.host_permissions),
            "api_permissions": ", ".join(sorted(self.api_permissions)),
            "content_scripts": self.content_scripts or "",
            "background": self.background,
            "notable": ";".join(self.notable), "risk": self.risk,
            "path": self.path, "source_file": self.source_file,
        }
