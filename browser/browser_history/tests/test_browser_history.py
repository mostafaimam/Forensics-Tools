import csv
import json
import os

import pytest

from browser_history import timeconv
from browser_history.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from browser_history.discover import find
from browser_history.flags import flag_url, severity
from browser_history.output import row
from browser_history.scan import scan

import _synth as s

_C = "https://www.google.com/search?q=how+to+disable+defender"


def _chrome_profile(tmp_path):
    prof = (tmp_path / "Users" / "rita" / "AppData" / "Local" / "Google"
            / "Chrome" / "User Data" / "Default")
    prof.mkdir(parents=True)
    s.chrome_history(str(prof / "History"), visits=[
        {"url": _C, "title": "how to disable defender",
         "time": "2026-08-15T09:00:00", "transition": 1, "visit_count": 2},
        {"url": "https://mega.nz/file/AbCd", "title": "MEGA",
         "time": "2026-08-15T09:05:00", "transition": 0},
        {"url": "http://185.43.99.42/payload.exe", "title": "",
         "time": "2026-08-15T09:06:00", "transition": 0},
        {"url": "https://news.example.com/", "title": "News",
         "time": "2026-08-15T10:00:00", "transition": 0},
    ], downloads=[
        {"url": "http://185.43.99.42/payload.exe",
         "target": "C:/rita/payload.exe", "time": "2026-08-15T09:07:00",
         "bytes": 240128, "danger": 1, "referrer": "http://185.43.99.42/"},
    ], searches=[
        {"url": _C, "term": "how to disable defender",
         "time": "2026-08-15T09:00:00"},
    ])
    return prof


def _firefox_profile(tmp_path):
    fp = (tmp_path / "Users" / "rita" / "AppData" / "Roaming" / "Mozilla"
          / "Firefox" / "Profiles" / "abc.default-release")
    fp.mkdir(parents=True)
    s.firefox_places(str(fp / "places.sqlite"), visits=[
        {"url": "https://pastebin.com/raw/X", "title": "p",
         "time": "2026-08-16T12:00:00", "visit_type": 2},
        {"url": "https://example.org/", "title": "e",
         "time": "2026-08-16T13:00:00", "visit_type": 1},
    ], downloads=[
        {"url": "https://anonfiles.com/x/tool.zip",
         "target": "/home/rita/tool.zip", "time": "2026-08-16T12:05:00",
         "bytes": 9999},
    ], inputs=[{"input": "reverse shell", "url": "https://duckduckgo.com/?q=x"}])
    return fp


# --------------------------------------------------------------------------
# time conversions
# --------------------------------------------------------------------------

def test_time_conversions():
    assert timeconv.chrome(s.chrome_us("2026-08-15T09:00:00")) \
        == "2026-08-15T09:00:00Z"
    assert timeconv.webkit_us(s.firefox_us("2026-08-16T12:00:00")) \
        == "2026-08-16T12:00:00Z"
    assert timeconv.cocoa(s.cocoa_s("2026-08-17T08:00:00")) \
        == "2026-08-17T08:00:00Z"
    assert timeconv.chrome(0) == "" and timeconv.chrome(None) == ""
    assert timeconv.chrome(1) == ""            # year 1601, clamped out


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def test_discover_identifies_browsers(tmp_path):
    _chrome_profile(tmp_path)
    _firefox_profile(tmp_path)
    stores = {os.path.basename(x.path): x for x in find(str(tmp_path))}
    assert stores["History"].browser == "Chrome"
    assert stores["History"].family == "chromium"
    assert stores["places.sqlite"].browser == "Firefox"
    assert stores["places.sqlite"].family == "firefox"


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def test_chrome_visits_downloads_searches(tmp_path):
    _chrome_profile(tmp_path)
    res = scan([str(tmp_path)])
    kinds = [row(e)["kind"] for e in res.entries]
    assert kinds.count("visit") == 4
    assert kinds.count("download") == 1
    assert kinds.count("search") == 1
    typed = [e for e in res.entries if row(e)["typed"] == "yes"
             and row(e)["kind"] == "visit"]
    assert typed and typed[0].url == _C
    dl = next(e for e in res.entries if row(e)["kind"] == "download")
    assert "payload.exe" in dl.target_path and "240,128" in row(dl)["detail"]


def test_firefox_places(tmp_path):
    _firefox_profile(tmp_path)
    res = scan([str(tmp_path)])
    urls = {e.url for e in res.entries}
    assert "https://pastebin.com/raw/X" in urls
    assert any(row(e)["kind"] == "download" and "anonfiles" in e.url
               for e in res.entries)
    assert any(row(e)["kind"] == "search" and "reverse shell" in row(e)["title"]
               for e in res.entries)


def test_safari(tmp_path):
    sp = tmp_path / "Library" / "Safari"
    sp.mkdir(parents=True)
    s.safari_history(str(sp / "History.db"), visits=[
        {"url": "https://apple.com/", "title": "Apple",
         "time": "2026-08-17T08:00:00"},
        {"url": "https://icloud.com/", "title": "iCloud",
         "time": "2026-08-17T08:05:00", "redirect_destination": 1},
    ])
    res = scan([str(tmp_path)])
    assert res.stores == 1
    assert {e.url for e in res.entries} == {"https://apple.com/",
                                            "https://icloud.com/"}
    red = next(e for e in res.entries if e.url == "https://icloud.com/")
    assert red.transition == "redirect"


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

def test_flag_url():
    assert "ip-literal-host" in flag_url("http://10.0.0.5/a.exe")
    assert "executable-download" in flag_url("http://x/setup.exe")
    assert "script/installer-download" in flag_url("http://x/run.ps1")
    assert "punycode-host" in flag_url("http://xn--80ak6aa92e.com/")
    assert "paste-site" in flag_url("https://pastebin.com/raw/abcd")
    assert "file-uri" in flag_url("file:///C:/Users/a/secret.txt")
    assert "tunnel-service" in flag_url("https://x.ngrok-free.app/")
    assert severity(flag_url("http://1.2.3.4/x.ps1")) == "high"
    assert flag_url("https://en.wikipedia.org/wiki/Cat") == []


def test_wal_safe_readonly(tmp_path):
    """The evidence file's mtime must not change."""
    prof = _chrome_profile(tmp_path)
    db = prof / "History"
    before = db.stat().st_mtime_ns
    scan([str(tmp_path)])
    assert db.stat().st_mtime_ns == before


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_csv_json(tmp_path):
    _chrome_profile(tmp_path)
    _firefox_profile(tmp_path)
    out = tmp_path / "h.csv"
    js = tmp_path / "h.json"
    rc = main([str(tmp_path), "--csv", str(out), "--json", str(js), "-q"])
    assert rc == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) >= 8
    assert any(r["severity"] == "high" for r in rows)
    assert {r["browser"] for r in rows} >= {"Chrome", "Firefox"}
    assert json.loads(js.read_text())


def test_cli_filters(tmp_path):
    _chrome_profile(tmp_path)
    _firefox_profile(tmp_path)

    out = tmp_path / "typed.csv"
    main([str(tmp_path), "--typed-only", "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert rows and all(r["typed"] == "yes" for r in rows)

    out2 = tmp_path / "dl.csv"
    main([str(tmp_path), "--downloads-only", "--csv", str(out2), "-q"])
    d = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert d and all(r["kind"] == "download" for r in d)

    out3 = tmp_path / "n.csv"
    main([str(tmp_path), "--notable-only", "--min-severity", "high",
          "--csv", str(out3), "-q"])
    n = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert n and all(r["severity"] == "high" for r in n)

    out4 = tmp_path / "b.csv"
    main([str(tmp_path), "--browser", "firefox", "--csv", str(out4), "-q"])
    b = list(csv.DictReader(out4.open(encoding="utf-8-sig")))
    assert b and all(r["browser"] == "Firefox" for r in b)

    out5 = tmp_path / "g.csv"
    main([str(tmp_path), "--grep", "defender", "--csv", str(out5), "-q"])
    g = list(csv.DictReader(out5.open(encoding="utf-8-sig")))
    assert g and all("defender" in (r["url"] + r["title"]).lower() for r in g)


def test_cli_date_window(tmp_path):
    _chrome_profile(tmp_path)
    _firefox_profile(tmp_path)
    out = tmp_path / "w.csv"
    main([str(tmp_path), "--from", "2026-08-16", "--to", "2026-08-16",
          "--csv", str(out), "-q"])
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    dated = [r for r in rows if r["time"]]
    assert dated and all(r["time"].startswith("2026-08-16") for r in dated)


def test_cli_single_db(tmp_path):
    prof = _chrome_profile(tmp_path)
    out = tmp_path / "s.csv"
    main([str(prof / "History"), "--csv", str(out), "-q"])
    assert list(csv.DictReader(out.open(encoding="utf-8-sig")))


def test_cli_no_path():
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    prof = (tmp_path / "Chrome" / "Default")
    prof.mkdir(parents=True)
    s.chrome_history(str(prof / "History"), visits=[
        {"url": "https://x/=cmd", "title": "=cmd|' /c calc'!A1",
         "time": "2026-08-15T09:00:00", "transition": 0}])
    out = tmp_path / "o.csv"
    main([str(tmp_path), "--csv", str(out), "-q"])
    assert "'=cmd|" in out.read_text(encoding="utf-8-sig")
