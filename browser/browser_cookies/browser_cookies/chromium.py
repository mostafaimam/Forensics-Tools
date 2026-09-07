"""Chromium-family ``Cookies`` store."""

from __future__ import annotations

from browser_cookies import timeconv as _t
from browser_cookies.dbopen import connect, has_table, query, table_columns
from browser_cookies.model import _SAMESITE, Cookie

# encrypted-value blobs start with these version prefixes
_ENC_PREFIX = (b"v10", b"v11", b"v20")


def parse(db_path: str, browser: str, profile: str) -> list[Cookie]:
    out: list[Cookie] = []
    p = str(db_path)
    with connect(p) as con:
        if not has_table(con, "cookies"):
            return out
        cols = table_columns(con, "cookies")
        name_col = "name"
        host_col = "host_key" if "host_key" in cols else "host"
        rows = query(con, f"SELECT * FROM cookies")
        for r in rows:
            d = dict(r)
            enc = d.get("encrypted_value") or b""
            vlen = 0
            if isinstance(enc, (bytes, bytearray)):
                vlen = max(0, len(enc) - (3 if enc[:3] in _ENC_PREFIX else 0))
            elif d.get("value"):
                vlen = len(str(d["value"]))
            has_exp = d.get("has_expires", d.get("is_persistent", 1))
            out.append(Cookie(
                browser=browser, profile=profile,
                host=d.get(host_col, "") or "",
                name=d.get(name_col, "") or "",
                path=d.get("path", "/") or "/",
                created=_t.chrome(d.get("creation_utc")),
                expires=_t.chrome(d.get("expires_utc")) if has_exp else "",
                last_access=_t.chrome(d.get("last_access_utc")),
                secure=bool(d.get("is_secure")),
                http_only=bool(d.get("is_httponly")),
                samesite=_SAMESITE.get(d.get("samesite", -1), "unspecified"),
                session=not bool(has_exp) or not d.get("expires_utc"),
                value_len=vlen, source_db=p))
    return out
