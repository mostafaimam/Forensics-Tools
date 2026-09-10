from __future__ import annotations

import json

import pytest

from macos_powerlog.parse import collect, list_tables, dump_table
from macos_powerlog import flags as _flags
from macos_powerlog.cli import main

import _synth as S


@pytest.fixture
def db(tmp_path):
    return S.build(str(tmp_path / "CurrentPowerlog.PLSQL"))


def test_collect_normalises(db):
    res = collect(db)
    kinds = {e.kind for e in res.events}
    assert kinds == {"app usage", "process", "camera", "location", "battery"}
    assert len(res.events) == 12
    safari = next(e for e in res.events if e.value == "com.apple.Safari")
    assert safari.kind == "app usage"
    assert safari.timestamp.startswith("2026-03-14T09:00")

    loc = next(e for e in res.events if e.value == "com.apple.Maps")
    assert loc.latitude == "37.33182" and loc.longitude == "-122.03118"


def test_ignores_unknown_tables(db):
    res = collect(db)
    assert "PLXPCAgent_Junk" not in res.matched_tables
    assert "PLXPCAgent_Junk" in list_tables(db)


def test_flags(db):
    res = collect(db)
    by = {}
    for e in res.events:
        by.setdefault(e.value, []).append(e)

    spy = by["com.acme.screenspy"][0]
    assert any("camera used by a non-media client" in n for n in spy.notable)
    assert _flags.severity(spy.notable) == "high"

    zsh = by["/bin/zsh"][0]
    assert any("shell / interpreter / net tool started (zsh)" in n
               for n in zsh.notable)

    impl = by["/private/tmp/impl"][0]
    assert any("user-writable path" in n for n in impl.notable)

    app = by["/Users/victim/.cache/app"][0]
    assert any("app bundle id is an absolute path" in n for n in app.notable)

    tracker = by["com.acme.tracker"][0]
    assert any("location fix recorded overnight" in n for n in tracker.notable)

    zoom = by["us.zoom.xos"][0]
    assert not zoom.notable


def test_cli_csv_json_filters(db, tmp_path):
    csv_p = tmp_path / "p.csv"
    js_p = tmp_path / "p.json"
    rc = main([db, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 12

    main([db, "--kind", "camera", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["kind"] == "camera" for r in got)

    main([db, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_list_and_dump(db, tmp_path, capsys):
    rc = main([db, "--list-tables"])
    assert rc == 0
    assert "PLCameraAgent_EventForward_Camera" in capsys.readouterr().out

    js_p = tmp_path / "t.json"
    rc = main([db, "--table", "PLBatteryAgent_EventBackward_Battery",
               "--json", str(js_p), "-q"])
    assert rc == 0
    got = json.loads(js_p.read_text())
    assert len(got) == 2 and "Level" in got[0]


def test_gz_input(db, tmp_path):
    import gzip
    gz = tmp_path / "Powerlog_2026-03-14.PLSQL.gz"
    with open(db, "rb") as fh, gzip.open(gz, "wb") as out:
        out.write(fh.read())
    js_p = tmp_path / "p.json"
    rc = main([str(gz), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 12


def test_csv_injection_guard():
    from macos_powerlog.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
