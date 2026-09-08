"""Parse Chromium ``Login Data`` and Firefox ``logins.json``."""

from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from browser_logins import timeconv as _t
from browser_logins.dbopen import connect, has_table, query, table_columns


@dataclass
class Login:
    browser: str = ""
    profile: str = ""
    origin: str = ""
    realm: str = ""
    host: str = ""
    username: str = ""
    username_field: str = ""
    date_created: str = ""
    date_last_used: str = ""
    date_password_changed: str = ""
    times_used: int = 0
    blacklisted: bool = False
    has_password_blob: bool = False
    scheme: str = ""
    source_db: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "browser": self.browser, "profile": self.profile,
            "host": self.host, "origin": self.origin, "realm": self.realm,
            "username": self.username, "username_field": self.username_field,
            "date_created": self.date_created,
            "date_last_used": self.date_last_used,
            "date_password_changed": self.date_password_changed,
            "times_used": self.times_used or "",
            "blacklisted": "yes" if self.blacklisted else "",
            "has_password": "yes" if self.has_password_blob else "",
            "scheme": self.scheme, "source_db": self.source_db,
            "notable": ";".join(self.notable),
        }


def _host_of(url: str) -> str:
    m = re.match(r"[a-z]+://([^/:]+)", url or "", re.I)
    return (m.group(1) if m else (url or "")).lower()


def _profile(p: str) -> str:
    for seg in reversed(Path(p).parts[:-1]):
        low = seg.lower()
        if low.startswith(("profile", "default")) or ".default" in low:
            return seg
    return ""


def _browser(p: str) -> str:
    s = p.lower().replace("\\", "/")
    for needle, name in (("edge", "Edge"), ("brave", "Brave"),
                         ("opera", "Opera"), ("vivaldi", "Vivaldi"),
                         ("chromium", "Chromium")):
        if needle in s:
            return name
    return "Chrome"


def _flag(lg: Login) -> None:
    if lg.blacklisted:
        lg.notable.append("site excluded from saving (never-save list)")
        return
    if lg.scheme == "http" or (lg.origin.startswith("http://")):
        lg.notable.append("credential stored for an http:// (cleartext) origin")
    h = lg.host
    if h:
        try:
            if ipaddress.ip_address(h.split(":")[0]):
                lg.notable.append("credential for a bare-IP origin")
        except ValueError:
            if "." not in h and h not in ("localhost",):
                lg.notable.append("credential for a non-FQDN host")
    if not lg.username and lg.has_password_blob:
        lg.notable.append("password saved with no username")


def parse_login_data(db_path: str) -> list[Login]:
    out: list[Login] = []
    p = str(db_path)
    br, pr = _browser(p), _profile(p)
    with connect(p) as con:
        if not has_table(con, "logins"):
            return out
        cols = table_columns(con, "logins")
        black_col = ("blacklisted_by_user" if "blacklisted_by_user" in cols
                     else "blacklisted" if "blacklisted" in cols else None)
        for r in query(con, "SELECT * FROM logins"):
            d = dict(r)
            origin = d.get("origin_url", "") or d.get("signon_realm", "") or ""
            pw = d.get("password_value")
            lg = Login(
                browser=br, profile=pr, origin=origin,
                realm=d.get("signon_realm", "") or "",
                host=_host_of(origin) or _host_of(d.get("signon_realm", "")),
                username=d.get("username_value", "") or "",
                username_field=d.get("username_element", "") or "",
                date_created=_t.chrome(d.get("date_created")),
                date_last_used=_t.chrome(d.get("date_last_used"))
                if "date_last_used" in cols else "",
                date_password_changed=_t.chrome(d.get("date_password_modified"))
                if "date_password_modified" in cols else "",
                times_used=d.get("times_used", 0) or 0,
                blacklisted=bool(d.get(black_col)) if black_col else False,
                has_password_blob=bool(pw) and len(bytes(pw)) > 0
                if pw is not None else False,
                scheme=("https" if origin.startswith("https://") else
                        "http" if origin.startswith("http://") else ""),
                source_db=p)
            _flag(lg)
            out.append(lg)
    return out


def _ff_time(ms) -> str:
    try:
        v = int(ms)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return datetime.fromtimestamp(v / 1000, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return ""


def parse_firefox_logins(json_path: str) -> list[Login]:
    out: list[Login] = []
    p = str(json_path)
    pr = _profile(p)
    key_db = Path(p).with_name("key4.db")
    primary_pw = _has_primary_password(key_db) if key_db.exists() else None
    try:
        data = json.loads(Path(p).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return out
    for e in data.get("logins", []):
        host = _host_of(e.get("hostname", "")) or (e.get("hostname", "") or "")
        lg = Login(
            browser="Firefox", profile=pr,
            origin=e.get("hostname", "") or "",
            realm=e.get("httpRealm") or e.get("formSubmitURL") or "",
            host=host,
            username="",                       # encrypted; not decoded
            username_field=e.get("usernameField", "") or "",
            date_created=_ff_time(e.get("timeCreated")),
            date_last_used=_ff_time(e.get("timeLastUsed")),
            date_password_changed=_ff_time(e.get("timePasswordChanged")),
            times_used=e.get("timesUsed", 0) or 0,
            has_password_blob=bool(e.get("encryptedPassword")),
            scheme=("https" if str(e.get("hostname", "")).startswith("https://")
                    else "http" if str(e.get("hostname", "")).startswith(
                        "http://") else ""),
            source_db=p)
        if e.get("encryptedUsername"):
            lg.username = "(encrypted)"
        _flag(lg)
        if primary_pw:
            lg.notable.append("store protected by a Primary Password "
                              "(values not recoverable without it)")
        out.append(lg)
    for host in data.get("disabledHosts") or data.get("nsILoginInfo:disabled",
                                                      []):
        lg = Login(browser="Firefox", profile=pr, origin=host,
                   host=_host_of(host) or host, blacklisted=True, source_db=p)
        _flag(lg)
        out.append(lg)
    return out


def _has_primary_password(key4: Path) -> bool | None:
    """Best effort: a default (no primary password) key4.db has a known
    global salt / check value.  We can only say 'maybe'."""
    try:
        con = sqlite3.connect(f"file:{key4}?mode=ro&immutable=1", uri=True)
        rows = con.execute("SELECT item1, item2 FROM metadata "
                            "WHERE id = 'password'").fetchall()
        con.close()
        if not rows:
            return None
        item2 = rows[0][1]
        # with no primary password the decrypted check string is
        # 'password-check\x02\x02'; the ciphertext length is small & fixed.
        return len(bytes(item2)) > 40
    except sqlite3.Error:
        return None
