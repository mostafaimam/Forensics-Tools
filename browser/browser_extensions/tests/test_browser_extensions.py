import csv
import json

import pytest

from browser_extensions.cli import main


def _recs(path):
    import json as _j
    d = _j.loads(open(path, encoding="utf-8").read())
    return d["records"] if isinstance(d, dict) and "records" in d else d
from browser_extensions.discover import find
from browser_extensions.flags import flag
from browser_extensions.model import Extension
from browser_extensions.permissions import host_breadth, score
from browser_extensions.scan import scan

import _synth as s

_UBLOCK = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
_EVIL = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _chrome(tmp_path):
    cp = (tmp_path / "Users" / "rita" / "AppData" / "Local" / "Google"
          / "Chrome" / "User Data" / "Default")
    cp.mkdir(parents=True)
    s.chrome_preferences(str(cp / "Preferences"), [
        {"id": _UBLOCK, "name": "uBlock Origin", "version": "1.55.0",
         "location": 1, "from_webstore": True,
         "permissions": ["storage", "tabs", "webRequest",
                         "webRequestBlocking"],
         "host_permissions": ["<all_urls>"], "content_scripts": 1,
         "background": "persistent", "install_time": "2026-01-10T09:00:00"},
        {"id": _EVIL, "name": "PriceHelper Deals", "version": "3.2.1",
         "location": 2, "from_webstore": False,
         "permissions": ["tabs", "cookies", "webRequest", "nativeMessaging",
                         "management"],
         "host_permissions": ["<all_urls>"], "content_scripts": 3,
         "background": "service_worker",
         "update_url": "https://updates.pricehelper.io/crx",
         "install_time": "2026-08-14T21:15:00"},
        {"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "name": "Dark Reader",
         "version": "4.9.0", "location": 1, "from_webstore": True,
         "permissions": ["storage", "alarms"],
         "host_permissions": ["<all_urls>"], "background": "event"},
        {"id": "cccccccccccccccccccccccccccccccc", "name": "Old Toolbar",
         "version": "1.0", "location": 3, "from_webstore": False, "state": 0,
         "disable_reasons": 128, "permissions": ["proxy", "debugger"],
         "host_permissions": ["*://*/*"]},
    ])
    return cp


def _firefox(tmp_path):
    fp = (tmp_path / "Users" / "rita" / "AppData" / "Roaming" / "Mozilla"
          / "Firefox" / "Profiles" / "q1.default-release")
    fp.mkdir(parents=True)
    s.firefox_extensions_json(str(fp / "extensions.json"), [
        {"id": "uBlock0@raymondhill.net", "name": "uBlock Origin",
         "version": "1.55.0", "location": "app-profile", "signedState": 2,
         "userPermissions": {"permissions": ["webRequest",
                                             "webRequestBlocking"],
                             "origins": ["<all_urls>"]},
         "installDate": "2026-02-01T00:00:00"},
        {"id": "{coupon-guid}", "name": "Coupon Saver", "version": "9.9.9",
         "location": "app-profile", "signedState": 0,
         "sourceURI": "https://coupon-saver.top/a.xpi",
         "updateURL": "https://coupon-saver.top/u.json",
         "userPermissions": {"permissions": ["tabs", "cookies",
                                             "nativeMessaging"],
                             "origins": ["<all_urls>"]},
         "installDate": "2026-08-16T13:00:00"},
    ])
    return fp


# --------------------------------------------------------------------------
# discovery & parsing
# --------------------------------------------------------------------------

def test_discover(tmp_path):
    _chrome(tmp_path)
    _firefox(tmp_path)
    fams = {st.family for st in find(str(tmp_path))}
    assert fams == {"chromium", "firefox"}


def test_chrome_parse(tmp_path):
    _chrome(tmp_path)
    exts = {e.name: e for e in scan([str(tmp_path)]).extensions}
    ub = exts["uBlock Origin"]
    assert ub.version == "1.55.0"
    assert ub.from_webstore and ub.enabled
    assert "<all_urls>" in ub.host_permissions
    assert "webRequestBlocking" in ub.api_permissions
    assert ub.background == "persistent"
    assert ub.install_time.startswith("2026-01-10")

    old = exts["Old Toolbar"]
    assert not old.enabled
    assert "not-verified" in old.disabled_reason


def test_firefox_parse(tmp_path):
    _firefox(tmp_path)
    exts = {e.name: e for e in scan([str(tmp_path)]).extensions}
    c = exts["Coupon Saver"]
    assert c.signed_state == "unsigned"
    assert c.update_url == "https://coupon-saver.top/u.json"
    assert "nativeMessaging" in c.api_permissions
    assert exts["uBlock Origin"].signed_state == "signed"


# --------------------------------------------------------------------------
# permissions & flags
# --------------------------------------------------------------------------

def test_host_breadth():
    assert host_breadth([]) == 0
    assert host_breadth(["https://mail.google.com/*"]) == 1
    assert host_breadth(["https://*/*"]) == 2
    assert host_breadth(["<all_urls>"]) == 3


def test_score():
    top, reasons = score(["webRequest", "webRequestBlocking"], ["<all_urls>"])
    assert top == 3
    assert any("every site" in r for r in reasons)
    assert score(["storage"], [])[0] == 0


def _e(**kw):
    base = dict(browser="Chrome", profile="p", ext_id="x", name="n",
                version="1", from_webstore=False)
    base.update(kw)
    return Extension(**base)


def test_flag_sideloaded_high():
    n, risk = flag(_e(install_source="sideload-registry",
                      api_permissions=["nativeMessaging", "cookies"],
                      host_permissions=["<all_urls>"]))
    assert risk == "high"
    assert any("sideloaded" in x for x in n)


def test_flag_unsigned_firefox_high():
    n, risk = flag(_e(browser="Firefox", install_source="user-installed",
                      signed_state="unsigned",
                      api_permissions=["tabs"], host_permissions=[]))
    assert risk == "high" and any("unsigned" in x for x in n)


def test_flag_webstore_broad_is_medium_not_high():
    n, risk = flag(_e(install_source="webstore", from_webstore=True,
                      api_permissions=["webRequest", "webRequestBlocking"],
                      host_permissions=["<all_urls>"]))
    assert risk == "medium"


def test_flag_first_party_clean():
    n, risk = flag(_e(ext_id="mhjfbmdgcfjbbpaeojofohoefgiehjai",
                      install_source="sideload-pref-download",
                      api_permissions=["tabs"],
                      host_permissions=["<all_urls>"]))
    assert risk == "low" and n == []


def test_flag_plain_extension_low():
    n, risk = flag(_e(install_source="webstore", from_webstore=True,
                      api_permissions=["storage", "alarms"],
                      host_permissions=[]))
    assert risk == "low" and n == []


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_csv_json(tmp_path):
    _chrome(tmp_path)
    _firefox(tmp_path)
    out = tmp_path / "e.csv"
    js = tmp_path / "e.json"
    assert main([str(tmp_path), "--csv", str(out), "--json", str(js), "-q"]) == 0
    rows = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert len(rows) == 6
    assert rows[0]["risk"] == "high"                # sorted risk-first
    assert any(r["name"] == "PriceHelper Deals" and r["risk"] == "high"
               for r in rows)
    assert json.loads(js.read_text())


def test_cli_filters(tmp_path):
    _chrome(tmp_path)
    _firefox(tmp_path)

    out = tmp_path / "s.csv"
    main([str(tmp_path), "--sideloaded-only", "--csv", str(out), "-q"])
    ss = list(csv.DictReader(out.open(encoding="utf-8-sig")))
    assert ss and not any(r["from_webstore"] == "yes" for r in ss)

    out2 = tmp_path / "h.csv"
    main([str(tmp_path), "--min-risk", "high", "--csv", str(out2), "-q"])
    hi = list(csv.DictReader(out2.open(encoding="utf-8-sig")))
    assert hi and all(r["risk"] == "high" for r in hi)

    out3 = tmp_path / "p.csv"
    main([str(tmp_path), "--perm", "nativeMessaging", "--csv", str(out3),
          "-q"])
    pm = list(csv.DictReader(out3.open(encoding="utf-8-sig")))
    assert pm and all("nativemessaging" in r["api_permissions"].lower()
                      for r in pm)

    out4 = tmp_path / "e.csv"
    main([str(tmp_path), "--enabled-only", "--csv", str(out4), "-q"])
    en = list(csv.DictReader(out4.open(encoding="utf-8-sig")))
    assert en and all(r["enabled"] == "yes" for r in en)


def test_cli_single_file(tmp_path):
    cp = _chrome(tmp_path)
    out = tmp_path / "one.csv"
    main([str(cp / "Preferences"), "--csv", str(out), "-q"])
    assert len(list(csv.DictReader(out.open(encoding="utf-8-sig")))) == 4


def test_cli_no_path():
    with pytest.raises(SystemExit):
        main([])


def test_csv_injection_guard(tmp_path):
    cp = tmp_path / "Chrome" / "Default"
    cp.mkdir(parents=True)
    s.chrome_preferences(str(cp / "Preferences"), [
        {"id": "d" * 32, "name": "=cmd|' /c calc'!A1", "location": 2,
         "from_webstore": False, "permissions": ["storage"]}])
    out = tmp_path / "o.csv"
    main([str(tmp_path), "--csv", str(out), "-q"])
    assert "'=cmd|" in out.read_text(encoding="utf-8-sig")
