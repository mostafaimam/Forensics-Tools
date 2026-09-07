"""Build synthetic extension databases for the test-suite."""

from __future__ import annotations

import json
from datetime import datetime, timezone

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_us(s: str) -> int:
    dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    return int((dt - _E1601).total_seconds() * 1_000_000)


def unix_ms(s: str) -> int:
    dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def chrome_preferences(path, extensions):
    """extensions: list of dicts with id, name, version, location (int),
    from_webstore, state (0/1), permissions (list), host_permissions (list),
    install_time (iso), update_url, disable_reasons (int), content_scripts,
    background ('service_worker'|'persistent'|'event'|None)."""
    settings = {}
    for e in extensions:
        man = {
            "name": e["name"], "version": e.get("version", "1.0"),
            "description": e.get("description", ""),
            "manifest_version": e.get("manifest_version", 3),
            "permissions": e.get("permissions", []),
            "host_permissions": e.get("host_permissions", []),
        }
        if e.get("optional_permissions"):
            man["optional_permissions"] = e["optional_permissions"]
        if e.get("content_scripts"):
            man["content_scripts"] = [{"matches": ["<all_urls>"]}
                                      for _ in range(e["content_scripts"])]
        if e.get("update_url"):
            man["update_url"] = e["update_url"]
        bg = e.get("background")
        if bg == "service_worker":
            man["background"] = {"service_worker": "bg.js"}
        elif bg == "persistent":
            man["background"] = {"page": "bg.html", "persistent": True}
        elif bg == "event":
            man["background"] = {"scripts": ["bg.js"]}
        s = {
            "manifest": man,
            "location": e.get("location", 1),
            "state": e.get("state", 1),
            "from_webstore": e.get("from_webstore", True),
            "path": e.get("path", f"{e['id']}/1.0_0"),
            "install_time": str(chrome_us(e.get("install_time",
                                                "2026-08-01T00:00:00"))),
        }
        if e.get("disable_reasons"):
            s["disable_reasons"] = e["disable_reasons"]
        settings[e["id"]] = s
    data = {"extensions": {"settings": settings}}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


def firefox_extensions_json(path, addons):
    """addons: list of dicts with id, name, version, location, sourceURI,
    signedState (int), userDisabled, appDisabled, blocklistState,
    userPermissions {permissions, origins}, installDate (iso), updateURL."""
    out = {"schemaVersion": 35, "addons": []}
    for a in addons:
        out["addons"].append({
            "id": a["id"], "type": a.get("type", "extension"),
            "version": a.get("version", "1.0"),
            "location": a.get("location", "app-profile"),
            "sourceURI": a.get("sourceURI",
                               "https://addons.mozilla.org/x.xpi"),
            "signedState": a.get("signedState", 2),
            "userDisabled": a.get("userDisabled", False),
            "appDisabled": a.get("appDisabled", False),
            "blocklistState": a.get("blocklistState", 0),
            "active": not (a.get("userDisabled") or a.get("appDisabled")),
            "installDate": unix_ms(a.get("installDate",
                                         "2026-08-01T00:00:00")),
            "updateDate": unix_ms(a.get("updateDate", "2026-08-01T00:00:00")),
            "updateURL": a.get("updateURL"),
            "defaultLocale": {"name": a.get("name", a["id"]),
                              "description": a.get("description", "")},
            "userPermissions": a.get("userPermissions",
                                     {"permissions": [], "origins": []}),
        })
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh)
    return path
