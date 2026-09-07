"""Chromium ``Preferences`` / ``Secure Preferences`` extension settings."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from browser_extensions.model import Extension

_E1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)

# extensions.settings.<id>.location  (Manifest::Location)
_LOCATION = {
    0: "invalid", 1: "webstore", 2: "sideload-registry", 3: "sideload-pref",
    4: "component", 5: "sideload-pref-download", 6: "policy",
    7: "policy-component", 8: "command-line", 9: "external-component",
    10: "external-component",
}
_STATE = {0: "disabled", 1: "enabled", 2: "blacklisted", 3: "external-request",
          4: "external-ack", 5: "terminated"}
_DISABLE_REASON = {
    1: "user", 2: "permissions-increase", 4: "reload", 8: "unsupported",
    16: "sideload-wipeout", 32: "unknown-from-sync", 128: "not-verified",
    256: "greylist", 512: "corrupt", 1024: "remote-install",
    4096: "not-allowlisted", 8192: "missing-update-url",
    1 << 20: "unsupported-manifest-version",
}


def _time(v) -> str:
    try:
        us = int(v)
    except (TypeError, ValueError):
        return ""
    if us <= 0:
        return ""
    try:
        return (_E1601 + timedelta(microseconds=us)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError):
        return ""


def _split_perms(perms) -> tuple[list[str], list[str]]:
    hosts, api = [], []
    for p in perms or []:
        if not isinstance(p, str):
            continue
        if "://" in p or p in ("<all_urls>",) or p.startswith("*://") \
                or p.startswith("file://"):
            hosts.append(p)
        else:
            api.append(p)
    return hosts, api


def _disable_reasons(bits) -> str:
    try:
        bits = int(bits)
    except (TypeError, ValueError):
        return ""
    return ", ".join(v for k, v in _DISABLE_REASON.items() if bits & k) or (
        str(bits) if bits else "")


def parse(pref_path: str, browser: str, profile: str) -> list[Extension]:
    p = Path(pref_path)
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    settings = (((data.get("extensions") or {}).get("settings")) or {})
    out: list[Extension] = []
    for ext_id, s in settings.items():
        if not isinstance(s, dict):
            continue
        man = s.get("manifest") or {}
        loc = _LOCATION.get(s.get("location"), str(s.get("location", "")))
        state = s.get("state")
        perms_all = ((s.get("granted_permissions") or {}))
        hosts = list(perms_all.get("explicit_host", [])) \
            + list(perms_all.get("scriptable_host", []))
        api = list(perms_all.get("api", []))
        if not (hosts or api):
            mh, ma = _split_perms(man.get("permissions"))
            hosts += mh
            api += ma
            hosts += man.get("host_permissions", []) or []
        oh, oa = _split_perms(
            ((man.get("optional_permissions") or [])
             + (man.get("optional_host_permissions") or [])))
        bg = man.get("background") or {}
        bg_kind = ("service-worker" if bg.get("service_worker")
                   else "persistent" if bg.get("persistent")
                   else "event" if (bg.get("page") or bg.get("scripts"))
                   else "none")
        out.append(Extension(
            browser=browser, profile=profile, ext_id=ext_id,
            name=(man.get("name") or s.get("name") or "")[:120],
            version=man.get("version", "") or s.get("version", ""),
            description=(man.get("description") or "")[:200],
            install_source=("webstore" if s.get("from_webstore")
                            else "unpacked" if loc == "command-line"
                            else loc),
            enabled=state == 1,
            disabled_reason=_disable_reasons(s.get("disable_reasons"))
            if state != 1 else "",
            from_webstore=bool(s.get("from_webstore")),
            install_time=_time(s.get("install_time")
                               or s.get("first_install_time")),
            update_time=_time(s.get("last_update_time")),
            update_url=man.get("update_url", "") or s.get("update_url", ""),
            homepage=man.get("homepage_url", ""),
            path=s.get("path", ""),
            host_permissions=sorted(set(hosts)),
            api_permissions=sorted(set(api)),
            optional_permissions=sorted(set(oh + oa)),
            content_scripts=len(man.get("content_scripts", []) or []),
            background=bg_kind,
            manifest_version=man.get("manifest_version", 0) or 0,
            source_file=str(p)))
    return out
