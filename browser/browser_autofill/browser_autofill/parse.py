"""Parse Chromium ``Web Data`` and Firefox ``formhistory.sqlite``."""

from __future__ import annotations

import re
from pathlib import Path

from browser_autofill import timeconv as _t
from browser_autofill.dbopen import connect, has_table, query, table_columns
from browser_autofill.model import Record

_SENSITIVE = re.compile(
    r"(pass|pwd|passwd|pin\b|cvv|cvc|csc|ssn|social|secret|security.?code|"
    r"card.?number|cc.?num|account.?number|routing|iban|sort.?code)", re.I)
_SEARCHY = re.compile(r"^(q|s|p|query|search|search_query|kw|keyword|term|"
                      r"wd|text|question)$", re.I)
_EMAILY = re.compile(r"mail")
_PHONEY = re.compile(r"(phone|tel|mobile|cell)")
_EMAIL_VAL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:1] + "*" * (len(value) - 2) + value[-1:]


def _browser(path: str) -> str:
    s = path.lower().replace("\\", "/")
    for needle, name in (("edge", "Edge"), ("brave", "Brave"),
                         ("opera", "Opera"), ("vivaldi", "Vivaldi"),
                         ("chromium", "Chromium"), ("firefox", "Firefox"),
                         ("mozilla", "Firefox")):
        if needle in s:
            return name
    return "Chrome" if "web data" in s or path.lower().endswith("web data") \
        else "Firefox" if "formhistory" in s else "Chrome"


def _profile(path: str) -> str:
    for seg in reversed(Path(path).parts[:-1]):
        low = seg.lower()
        if low.startswith(("profile", "default")) or ".default" in low \
                or "profile" in low:
            return seg
    return ""


def parse_web_data(db_path: str) -> list[Record]:
    out: list[Record] = []
    p = str(db_path)
    br, pr = _browser(p), _profile(p)
    with connect(p) as con:
        # ---- form-field history --------------------------------------
        if has_table(con, "autofill"):
            cols = table_columns(con, "autofill")
            for r in query(con, "SELECT * FROM autofill"):
                d = dict(r)
                name = d.get("name", "") or ""
                val = d.get("value", "") or ""
                sensitive = bool(_SENSITIVE.search(name))
                rec = Record(
                    browser=br, profile=pr, kind="form-field", name=name,
                    value=_mask(val) if sensitive else val,
                    first_used=_t.chrome(d.get("date_created"))
                    if "date_created" in cols else "",
                    last_used=_t.chrome(d.get("date_last_used"))
                    if "date_last_used" in cols else "",
                    count=d.get("count", 0) or 0, source_db=p)
                _flag_field(rec, name, val, sensitive)
                out.append(rec)

        # ---- address profiles ---------------------------------------
        out += _addresses(con, br, pr, p)

        # ---- payment cards (metadata only) -------------------------
        out += _cards(con, br, pr, p)
    return out


_ADDR_TABLES = ("autofill_profiles", "contact_info", "local_addresses")


def _addresses(con, br, pr, p) -> list[Record]:
    out: list[Record] = []
    for tbl in _ADDR_TABLES:
        if not has_table(con, tbl):
            continue
        cols = table_columns(con, tbl)
        for r in query(con, f"SELECT * FROM {tbl}"):
            d = dict(r)
            name = (d.get("full_name") or d.get("first_name", "")
                    or d.get("name", "") or "").strip()
            parts = [str(d.get(k, "")) for k in
                     ("company_name", "street_address", "address_line_1",
                      "city", "state", "zipcode", "postal_code",
                      "country_code", "country")
                     if d.get(k)]
            email = d.get("email", "")
            phone = d.get("number", "") or d.get("phone_number", "")
            detail = ", ".join(x for x in parts if x)
            if email:
                detail += f"  <{email}>"
            if phone:
                detail += f"  {phone}"
            rec = Record(browser=br, profile=pr, kind="address",
                         name=name or "(address profile)",
                         detail=detail.strip(", "),
                         last_used=_t.chrome(d.get("use_date"))
                         if "use_date" in cols else (
                             _t.chrome(d.get("date_modified"))
                             if "date_modified" in cols else ""),
                         count=d.get("use_count", 0) or 0, source_db=p)
            if email or phone:
                rec.notable.append("contact details in a saved address profile")
            out.append(rec)
        break                                       # first matching table only
    return out


_CARD_TABLES = ("credit_cards", "masked_credit_cards", "local_stored_cards",
                "server_card_metadata")


def _cards(con, br, pr, p) -> list[Record]:
    out: list[Record] = []
    for tbl in _CARD_TABLES:
        if not has_table(con, tbl):
            continue
        cols = table_columns(con, tbl)
        for r in query(con, f"SELECT * FROM {tbl}"):
            d = dict(r)
            holder = (d.get("name_on_card") or d.get("cardholder_name")
                      or "").strip()
            last4 = d.get("last_four") or d.get("last_four_digits") or ""
            if not last4:
                enc = d.get("card_number_encrypted")
                num = d.get("card_number") or ""
                if isinstance(num, str) and num.isdigit() and len(num) >= 4:
                    last4 = num[-4:]
            net = d.get("network") or d.get("type") or ""
            exp_m = d.get("expiration_month") or d.get("exp_month") or ""
            exp_y = d.get("expiration_year") or d.get("exp_year") or ""
            detail = " ".join(str(x) for x in (net, f"****{last4}" if last4
                                               else "", f"exp {exp_m}/{exp_y}"
                                               if exp_m else "") if x)
            out.append(Record(
                browser=br, profile=pr, kind="card",
                name=holder or "(card)", detail=detail.strip(),
                last_used=_t.chrome(d.get("use_date"))
                if "use_date" in cols else "",
                count=d.get("use_count", 0) or 0, source_db=p,
                notable=["payment-card metadata saved in the browser"]))
        break
    return out


def parse_formhistory(db_path: str) -> list[Record]:
    out: list[Record] = []
    p = str(db_path)
    pr = _profile(p)
    with connect(p) as con:
        if not has_table(con, "moz_formhistory"):
            return out
        for r in query(con, "SELECT * FROM moz_formhistory"):
            d = dict(r)
            name = d.get("fieldname", "") or ""
            val = d.get("value", "") or ""
            sensitive = bool(_SENSITIVE.search(name))
            rec = Record(
                browser="Firefox", profile=pr, kind="form-field", name=name,
                value=_mask(val) if sensitive else val,
                first_used=_t.webkit_us(d.get("firstUsed")),
                last_used=_t.webkit_us(d.get("lastUsed")),
                count=d.get("timesUsed", 0) or 0, source_db=p)
            _flag_field(rec, name, val, sensitive)
            out.append(rec)
    return out


def _flag_field(rec: Record, name: str, val: str, sensitive: bool) -> None:
    if sensitive:
        rec.notable.append(f"sensitive field name ({name}) - value masked")
    if _SEARCHY.match(name) or "search" in name.lower():
        rec.notable.append("search-box / query field")
    if _EMAILY.search(name) or _EMAIL_VAL.match(val):
        rec.notable.append("email address in form history")
    if _PHONEY.search(name):
        rec.notable.append("phone number in form history")
