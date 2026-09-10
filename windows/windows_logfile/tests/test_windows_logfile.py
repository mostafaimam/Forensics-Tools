from __future__ import annotations

import json

import pytest

import _synth as S

from windows_logfile.logfile import parse
from windows_logfile.events import reconstruct
from windows_logfile.collect import collect
from windows_logfile.cli import main


def test_parse_records():
    lf = parse(S.build_logfile())
    assert lf.rstr_pages == 2
    assert lf.rcrd_pages == 1
    assert len(lf.records) == 6
    assert [r.lsn for r in lf.records] == [100, 110, 120, 130, 140, 150]
    assert lf.records[1].redo_name == "AddIndexEntryAllocation"


def test_events():
    evs = reconstruct(parse(S.build_logfile()).records, "x")
    by = {}
    for e in evs:
        by.setdefault(e.name or e.action, e)
    assert "evil.exe" in by
    assert by["evil.exe"].real_size == 45056
    assert by["evil.exe"].parent_mft == 5
    r = by["report.docx"]
    assert r.created == "2026-03-16T10:00:00Z"
    assert r.modified == "2026-03-16T08:00:00Z"


def test_flags(tmp_path):
    f = tmp_path / "$LogFile"
    f.write_bytes(S.build_logfile())
    res = collect([str(f)])
    by = {}
    for r in res.rows:
        by.setdefault(r["name"] or r["action"], []).append(r)

    evil = by["evil.exe"][0]
    assert "creation of an executable / script" in evil["notable"]

    wiped = [r for r in res.rows if r["name"] == "wiped.dat"]
    assert any("created and deleted within the log window" in r["notable"]
               for r in wiped)
    assert any(r["severity"] == "high" for r in wiped)

    rep = by["report.docx"][0]
    assert "timestomp" in rep["notable"]
    assert rep["severity"] == "high"


def test_cli_filters(tmp_path):
    f = tmp_path / "$LogFile"
    f.write_bytes(S.build_logfile())
    js = tmp_path / "l.json"
    csv = tmp_path / "l.csv"
    rc = main([str(f), "--csv", str(csv), "--json", str(js), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js.read_text())) == 6

    main([str(f), "--action", "deleted", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all("deleted" in r["action"] for r in got)

    main([str(f), "--min-severity", "high", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(f), "--grep", r"\.exe$", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and got[0]["name"] == "evil.exe"

    main([str(f), "--named-only", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["name"] for r in got)


def test_csv_injection_guard():
    from windows_logfile.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
