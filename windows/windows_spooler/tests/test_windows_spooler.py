from __future__ import annotations

import json

import pytest

import _synth as S

from windows_spooler.shd import parse_shd
from windows_spooler.spl import parse_spl
from windows_spooler.collect import collect
from windows_spooler.cli import main


def test_shd():
    j = parse_shd(S.build_shd(), "FP7.shd")
    assert j.job_id == 7
    assert j.user == "jsmith"
    assert j.machine == "\\\\WKS-42"
    assert j.document == "Q3 salary review - CONFIDENTIAL.docx"
    assert j.printer == "HP LaserJet on FILESRV"
    assert j.datatype == "RAW"
    assert j.processor == "winprint"
    assert j.submit_time == "2026-03-16T01:15:30Z"


def test_spl_formats():
    assert parse_spl(S.build_spl_xps(4), "x").pages == 4
    assert parse_spl(S.build_spl_xps(4), "x").fmt == "XPS/OpenXPS"
    assert parse_spl(S.build_spl_emf(3), "x").pages == 3
    assert parse_spl(S.build_spl_ps(), "x").fmt == "PostScript"


def test_collect_and_flags(tmp_path):
    d = tmp_path / "PRINTERS"
    d.mkdir()
    (d / "FP00007.shd").write_bytes(S.build_shd())
    (d / "FP00007.spl").write_bytes(S.build_spl_ps())
    res = collect([str(d)])
    assert len(res.rows) == 1
    r = res.rows[0]
    assert r["user"] == "jsmith"
    assert r["spl_format"] == "PostScript"
    assert r["spl_pages"] == 3
    assert "sensitive content" in r["notable"]
    assert "PostScript spool data" in r["notable"]
    assert r["severity"] == "medium"


def test_cli_extract_and_filters(tmp_path):
    d = tmp_path / "PRINTERS"
    d.mkdir()
    (d / "FP1.shd").write_bytes(S.build_shd(document="menu.pdf",
                                            user="bob"))
    (d / "FP1.spl").write_bytes(S.build_spl_emf(2))
    (d / "FP2.shd").write_bytes(S.build_shd(
        document="salary bands CONFIDENTIAL", user="mallory", job_id=2))
    (d / "FP2.spl").write_bytes(S.build_spl_xps(120))

    js = tmp_path / "s.json"
    csv = tmp_path / "s.csv"
    out = tmp_path / "out"
    rc = main([str(d), "--csv", str(csv), "--json", str(js),
               "--extract", str(out), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    assert len(json.loads(js.read_text())) == 2
    assert list(out.iterdir())

    main([str(d), "--format", "xps", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and got[0]["spl_format"] == "XPS/OpenXPS"

    main([str(d), "--min-severity", "medium", "--json", str(js), "-q"])
    got = json.loads(js.read_text())
    assert got and all(r["severity"] in ("medium", "high") for r in got)

    main([str(d), "--grep", "mallory", "--json", str(js), "-q"])
    assert json.loads(js.read_text())


def test_csv_injection_guard():
    from windows_spooler.tracelib import sanitize
    assert sanitize("=cmd|'/c'") == "'=cmd|'/c'"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
