"""Firefox ``extensions.json`` add-on database."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from browser_extensions.model import Extension

_SIGNED = {2: "signed", 1: "preliminary", 0: "unsigned", -1: "unknown",
           -2: "broken", 3: "system"}
_LOCATION = {
    "app-profile": "user-installed", "app-system-defaults": "system",
    "app-builtin": "builtin", "app-system-addons": "system",
    "app-temporary": "temporary/unpacked", "app-system-share": "system",
}


def _ms(v) -> str:
    try:
        ms = int(v)
    except (TypeError, ValueError):
        return ""
    if ms <= 0:
        return ""
    try:
        return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def parse(path: str, browser: str, profile: str) -> list[Extension]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[Extension] = []
    for a in data.get("addons", []):
        if not isinstance(a, dict):
            continue
        if a.get("type") not in ("extension", "webextension", None):
            continue
        loc = a.get("location", "")
        perms = (a.get("userPermissions") or {})
        api = [x for x in perms.get("permissions", []) if isinstance(x, str)]
        hosts = [x for x in perms.get("origins", []) if isinstance(x, str)]
        name = a.get("defaultLocale", {}).get("name") or a.get("name") or ""
        desc = a.get("defaultLocale", {}).get("description") or ""
        disabled = bool(a.get("userDisabled") or a.get("appDisabled")
                        or a.get("softDisabled"))
        reason = []
        if a.get("userDisabled"):
            reason.append("user")
        if a.get("appDisabled"):
            reason.append("app/signature")
        if a.get("blocklistState"):
            reason.append("blocklist")
        signed = _SIGNED.get(a.get("signedState"), str(a.get("signedState", "")))
        src_uri = a.get("sourceURI") or ""
        out.append(Extension(
            browser=browser, profile=profile,
            ext_id=a.get("id", ""), name=str(name)[:120],
            version=a.get("version", ""), description=str(desc)[:200],
            install_source=_LOCATION.get(loc, loc or "unknown"),
            enabled=not disabled and a.get("active", True),
            disabled_reason=", ".join(reason),
            from_webstore=("addons.mozilla.org" in src_uri
                           or loc == "app-profile" and not src_uri),
            signed_state=signed,
            install_time=_ms(a.get("installDate")),
            update_time=_ms(a.get("updateDate")),
            update_url=a.get("updateURL", "") or "",
            homepage=(a.get("defaultLocale", {}).get("homepageURL") or ""),
            path=a.get("path", "") or "",
            host_permissions=sorted(set(hosts)),
            api_permissions=sorted(set(api)),
            content_scripts=0,
            background="", manifest_version=a.get("manifestVersion", 0) or 0,
            source_file=str(p)))
    return out
