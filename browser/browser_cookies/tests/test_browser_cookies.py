import csv
import json

import pytest

from browser_cookies.cli import main
from browser_cookies.discover import find
from browser_cookies.flags import flag, severity
from browser_cookies.model import Cookie
from browser_cookies.output import row
from browser_cookies.scan import scan

import _synth as s


def _chrome(tmp_path):
    cp = (tmp_path / "Users" / "rita" / "AppData" / "Local" / "Google"
          / "Chrome" / "User Data" / "Default" / "Network")
    cp.mkdir(parents=True)
    s.chrome_cookies(str(cp / "Cookies"), [
        {"host": ".google.com", "name": "SID", "created": "2026-08-10T09:00:00",
         "expires": "2027-08-10T09:00:00", "secure": 1, "httponly": 1,
         "value_len": 88},
        {"host": ".internal.corp.example", "name": "PHPSESSID",
         "created": "2026-08-14T08:00:00", "secure": 1, "httponly": 1},
        {"host": "185.43.99.42", "name": "id", "created": "2026-08-14T20:40:00",
         "expires": "2036-08-14T20:40:00"},
        {"host": ".doubleclick.net", "name": "IDE",
         "created": "2026-08-01T00:00:00", "expires": "2027-02-01T00:00:00"},
        {"host": "evil.ngrok-free.app", "name": "authcookie",
         "created": "2026-08-14T21:00:00", "expires": "2026-08-15T21:00:00"},
    ])
    return cp


def _firefox(tmp_path):
    fp = (tmp_path / "Users" / "rita" / "AppData" / "Roaming" / "Mozilla"
          / "Firefox" / "Profiles" / "q1.default-release")
    fp.mkdir(parents=True)
    s.firefox_cookies(str(fp / "cookies.sqlite"), [
        {"host": "example.org", "name": "prefs", "value": "theme=dark",
         "created": "2026-08-12T10:00:00", "expires": "2027-08-12T10:00:00"},
        {"host": "mail.example.com", "name": "JSESSIONID",
         "value": "AB12CD34EF56", "created": "2026-08-16T11:00:00",
         "secure": 1, "httponly": 1},
    ])
    return fp


def _safari(tmp_path):
    sp = tmp_path / "Users" / "rita" / "Library" / "Cookies"
    sp.mkdir(parents=True)
    s.safari_cookies(str(sp / "Cookies.binarycookies"), [
        {"host": "apple.com", "name": "s_vi", "value": "abc",
         "created": "2026-08-17T08:00:00", "expires": "2028-08-17T08:00:00",
         "secure": True},
        {"host": "icloud.com", "name": "X_APPLE_WEBAUTH_TOKEN", "value": "tok",
         "created": "2026-08-17T08:05:00", "secure": True, "httponly": True},
    ])
    return sp


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def test_discover(tmp_path):
    _chrome(tmp_path)
    _firefox(tmp_path)
    _safari(tmp_path)
    by_name = {p.path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]: p
               for p in find(str(tmp_path))}
    assert by_name["Cookies"].family == "chromium"
    assert by_name["cookies.sqlite"].family == "firefox"
    assert by_name["Cookies.binarycookies"].family == "safari"
    assert by_name["Cookies.binarycookies"].browser == "Safari"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def test_chrome_cookies(tmp_path):
    _chrome(tmp_path)
    res = scan([str(tmp_path)])
    ck = {c.name: c for c in res.cookies}
    assert ck["SID"].secure and ck["SID"].http_only
    assert ck["SID"].expires.startswith("2027-08-10")
    assert ck["SID"].created.startswith("2026-08-10")
    assert ck["SID"].value_len == 88
    assert ck["PHPSESSID"].session is True
    assert ck["IDE"].session is False


def test_firefox_cookies_values(tmp_path):
    _firefox(tmp_path)
    res = scan([str(tmp_path)])
    ck = {c.name: c for c in res.cookies}
    assert ck["prefs"].value == "theme=dark"           # plaintext, retained
    assert ck["prefs"].expires.startswith("2027-08-12")
    r = row(ck["prefs"], with_values=False)
    assert "value" not in r                            # hidden by default
    r2 = row(ck["prefs"], with_values=True)
    assert r2["value"] == "theme=dark"


def test_safari_binarycookies(tmp_path):
    _safari(tmp_path)
    res = scan([str(tmp_path)])
    ck = {c.name: c for c in res.cookies}
    assert set(ck) == {"s_vi", "X_APPLE_WEBAUTH_TOKEN"}
    assert ck["s_vi"].host == "apple.com" and ck["s_vi"].secure
    assert ck["X_APPLE_WEBAUTH_TOKEN"].http_only
    assert ck["s_vi"].expires.startswith("2028-08-17")


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

def _c(**kw):
    base = dict(browser="X", profile="p", host="example.com", name="c",
                path="/")
    base.update(kw)
    return Cookie(**base)


def test_flags():
    assert "session/auth-cookie" in flag(_c(name="JSESSIONID"))
    assert "session/auth-cookie" in flag(_c(name="__Secure-1PSID"))
    assert "ip-literal-host" in flag(_c(host="10.0.0.9"))
    assert "tunnel-host" in flag(_c(host="x.trycloudflare.com"))
    assert "punycode-host" in flag(_c(host="xn--pple-43d.com"))
    assert "host-prefix-violation" in flag(_c(name="__Host-x", secure=False))
    assert "secure-prefix-violation" in flag(_c(name="__Secure-x",
                                                secure=False))
    assert "expires->5y" in flag(_c(expires="2040-01-01T00:00:00Z"))
    assert flag(_c(name="prefs", host="example.com")) == []
    assert severity(flag(_c(host="1.2.3.4", name="sid"))) == "high"


def test_wal_safe(tmp_path):
    cp = _chrome(tmp_path)
    db = cp / "Cookies"
    before = db.stat().st_mtime_ns
    scan([str(tmp_path)])
    assert db.stat().st_mtime_ns == before


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_csv_json(tmp_path):
    _chrome(tmp_path)
    _firefox(tmp_path)
    out = tmp_path / "c.csv"
    js = tmp_path / "c.json"
    assert main([str(tmp_path), "--csv", str(out), "--json", str(js), "-q"]) == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 7
    assert "value" not in rows[0]
    assert any(r["severity"] == "high" for r in rows)
    assert json.loads(js.read_text())


def test_cli_with_values(tmp_path):
    _firefox(tmp_path)
    out = tmp_path / "v.csv"
    main([str(tmp_path), "--with-values", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert "value" in rows[0]
    assert any(r["value"] == "theme=dark" for r in rows)


def test_cli_filters(tmp_path):
    _chrome(tmp_path)
    _firefox(tmp_path)

    out = tmp_path / "a.csv"
    main([str(tmp_path), "--auth-only", "--csv", str(out), "-q"])
    a = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert a and all("session/auth-cookie" in r["notable"] for r in a)

    out2 = tmp_path / "s.csv"
    main([str(tmp_path), "--session-only", "--csv", str(out2), "-q"])
    ss = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert ss and all(r["session"] == "yes" for r in ss)

    out3 = tmp_path / "h.csv"
    main([str(tmp_path), "--host", "internal", "--csv", str(out3), "-q"])
    h = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert h and all("internal" in r["host"] for r in h)

    out4 = tmp_path / "hi.csv"
    main([str(tmp_path), "--notable-only", "--min-severity", "high",
          "--csv", str(out4), "-q"])
    hi = list(csv.DictReader(out4.open(encoding="utf-8-sig")))
    assert hi and all(r["severity"] == "high" for r in hi)


def test_cli_single_file(tmp_path):
    cp = _chrome(tmp_path)
    out = tmp_path / "one.csv"
    main([str(cp / "Cookies"), "--csv", str(out), "-q"])
    assert len(list(csv.DictReader(out.open(encoding="utf-8-sig")))) == 5


def test_cli_no_path():
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    cp = (tmp_path / "Chrome" / "Default" / "Network")
    cp.mkdir(parents=True)
    s.chrome_cookies(str(cp / "Cookies"), [
        {"host": "=cmd|calc", "name": "@SUM(1)",
         "created": "2026-08-10T09:00:00"}])
    out = tmp_path / "o.csv"
    main([str(tmp_path), "--csv", str(out), "-q"])
    raw = out.read_text(encoding="utf-8-sig")
    assert "'=cmd|calc" in raw and "'@SUM(1)" in raw
