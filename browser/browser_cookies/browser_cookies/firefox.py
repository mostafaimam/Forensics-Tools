"""Firefox / Tor Browser ``cookies.sqlite`` (plaintext values)."""

from __future__ import annotations

from browser_cookies import timeconv as _t
from browser_cookies.dbopen import connect, has_table, query
from browser_cookies.model import _SAMESITE, Cookie


def parse(db_path: str, browser: str, profile: str) -> list[Cookie]:
    out: list[Cookie] = []
    p = str(db_path)
    with connect(p) as con:
        if not has_table(con, "moz_cookies"):
            return out
        for r in query(con, "SELECT * FROM moz_cookies"):
            d = dict(r)
            val = d.get("value") or ""
            expiry = d.get("expiry") or 0
            out.append(Cookie(
                browser=browser, profile=profile,
                host=d.get("host", "") or "",
                name=d.get("name", "") or "",
                path=d.get("path", "/") or "/",
                created=_t.unix_s((d.get("creationTime") or 0) / 1_000_000),
                expires=_t.unix_s(expiry) if expiry else "",
                last_access=_t.unix_s((d.get("lastAccessed") or 0) / 1_000_000),
                secure=bool(d.get("isSecure")),
                http_only=bool(d.get("isHttpOnly")),
                samesite=_SAMESITE.get(d.get("sameSite", -1), "unspecified"),
                session=not expiry,
                value_len=len(str(val)), value=str(val), source_db=p))
    return out
