from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from browser_autofill import output
from browser_autofill.analyze import analyze
from browser_autofill.cli import main

import _synth as S

D = datetime(2026, 11, 14, 9, 0, 0, tzinfo=timezone.utc)
D2 = datetime(2026, 11, 15, 9, 0, 0, tzinfo=timezone.utc)


def _by(res, name):
    return next(r for r in res.records if r.name == name)


def test_chromium_form_fields(tmp_path):
    wd = tmp_path / "Web Data"
    S.web_data(wd, fields=[
        ("email", "alice@example.com", D, D2, 4),
        ("q", "how to exfiltrate data", D, D2, 1),
        ("cardCvv", "737", D, D2, 1),
    ])
    res = analyze([str(wd)])
    by = {r.name: r for r in res.records}
    assert by["email"].value == "alice@example.com"
    assert "email address in form history" in ";".join(by["email"].notable)
    assert "search-box / query field" in ";".join(by["q"].notable)
    # sensitive value masked
    assert by["cardCvv"].value != "737" and by["cardCvv"].value.count("*") >= 1
    assert output.row(by["cardCvv"])["severity"] == "high"


def test_chromium_address_profile(tmp_path):
    wd = tmp_path / "Web Data"
    S.web_data(wd, profiles=[
        {"name": "Bob Jones", "street": "1 Main St", "city": "Springfield",
         "state": "IL", "zip": "62704", "email": "bob@corp.example",
         "phone": "+1-555-0100", "use_date": D2, "use_count": 7},
    ])
    res = analyze([str(wd)])
    addr = next(r for r in res.records if r.kind == "address")
    assert addr.name == "Bob Jones"
    assert "Springfield" in addr.detail and "bob@corp.example" in addr.detail
    assert addr.count == 7
    assert any("contact details" in x for x in addr.notable)


def test_chromium_card_metadata_only(tmp_path):
    wd = tmp_path / "Web Data"
    S.web_data(wd, cards=[
        {"holder": "B JONES", "last4": "4242", "network": "Visa",
         "month": 8, "year": 2029, "use_date": D2},
    ])
    res = analyze([str(wd)])
    card = next(r for r in res.records if r.kind == "card")
    assert card.name == "B JONES"
    assert "4242" in card.detail and "Visa" in card.detail
    # no full PAN anywhere
    blob = json.dumps([r.row() for r in res.records])
    assert "424242" not in blob
    assert any("payment-card metadata" in x for x in card.notable)


def test_firefox_formhistory(tmp_path):
    fh = tmp_path / "formhistory.sqlite"
    S.formhistory(fh, [
        ("searchbar-history", "vpn download", D, D2, 3),
        ("password", "hunter2", D, D2, 1),
    ])
    res = analyze([str(fh)])
    by = {r.name: r for r in res.records}
    assert by["searchbar-history"].browser == "Firefox"
    assert by["password"].value != "hunter2"
    assert any("sensitive field name" in x for x in by["password"].notable)


def test_folder_walk_merges_browsers(tmp_path):
    (tmp_path / "Chrome").mkdir()
    (tmp_path / "ff").mkdir()
    S.web_data(tmp_path / "Chrome" / "Web Data",
               fields=[("name", "Alice", D, D2, 2)])
    S.formhistory(tmp_path / "ff" / "formhistory.sqlite",
                  [("email", "a@b.c", D, D2, 1)])
    res = analyze([str(tmp_path)])
    assert res.stores == 2
    assert {r.browser for r in res.records} == {"Chrome", "Firefox"}


def test_cli_csv_json_filters(tmp_path):
    wd = tmp_path / "Web Data"
    S.web_data(wd, fields=[
        ("email", "x@y.z", D, D2, 1),
        ("comments", "hello", D, D2, 1),
    ], cards=[{"holder": "X", "last4": "1111", "use_date": D2}])
    csv_p = tmp_path / "a.csv"
    js_p = tmp_path / "a.json"
    rc = main([str(wd), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js_p.read_text())) == 3

    main([str(wd), "--kind", "card", "--json", str(js_p), "-q"])
    assert len(json.loads(js_p.read_text())) == 1

    main([str(wd), "--grep", "email", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())[0]["name"] == "email"


def test_csv_injection_guard():
    assert output._san("=1") == "'=1"
    assert output._san("alice") == "alice"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
