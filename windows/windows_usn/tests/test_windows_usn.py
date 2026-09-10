from __future__ import annotations

import json

import pytest

from windows_usn import usnparse as U
from windows_usn.analyze import analyze, severity
from windows_usn.cli import main, _mft_paths

import _synth as S


def test_sequential_parse():
    recs = list(U.iter_sequential(S.build_stream()))
    assert len(recs) >= 25
    r0 = recs[0]
    assert r0.name == "notes.docx"
    assert "DATA_EXTEND" in r0.reason_names()
    assert r0.timestamp.year == 2026
    assert r0.file_entry == 200 and r0.file_sequence == 1


def test_operations_folded():
    recs = list(U.iter_sequential(S.build_stream()))
    ops = analyze(recs).operations
    by_name = {}
    for o in ops:
        by_name.setdefault(o.name, []).append(o)
    assert any(o.op == "create" for o in by_name["agent.exe"])
    assert any(o.op == "delete" for o in by_name["agent.exe"])
    rn = next(o for o in ops if o.op == "rename")
    assert rn.old_name == "report_draft.docx"
    assert rn.name == "report_final.docx"


def test_flags():
    recs = list(U.iter_sequential(S.build_stream()))
    ops = analyze(recs).operations
    agent_create = next(o for o in ops
                        if o.name == "agent.exe" and o.op == "create")
    j = " ".join(agent_create.notable)
    assert "executable / script created" in j
    assert "created and deleted within" in j
    assert severity(agent_create.notable) == "high"

    loader = next(o for o in ops if o.name == "loader.dll")
    assert any("attribute-only change" in n for n in loader.notable)

    deletes = [o for o in ops if o.op == "delete" and "cache_" in o.name]
    assert any("mass-delete burst" in n for o in deletes for n in o.notable)


def test_carving_recovers_records():
    stream = S.build_stream()
    # bury the record region in cluster-aligned noise
    blob = b"\xAA" * 512 + stream[512:] + b"\x00" * 200
    carved = list(U.iter_carved(blob))
    assert len(carved) >= 20
    assert all(c.carved for c in carved)
    assert any(c.name == "agent.exe" for c in carved)


def test_mft_path_resolution(tmp_path):
    mft = tmp_path / "MFT"
    mft.write_bytes(S.build_mft())
    paths = _mft_paths(mft)
    assert paths.get(100) == "Windows"
    assert paths.get(101) == "Windows\\Temp"


def test_cli_csv_json_filters(tmp_path):
    j = tmp_path / "J.bin"
    j.write_bytes(S.build_stream())
    mft = tmp_path / "MFT"
    mft.write_bytes(S.build_mft())
    csv_p = tmp_path / "u.csv"
    js_p = tmp_path / "u.json"
    rc = main([str(j), "--mft", str(mft), "--csv", str(csv_p),
               "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert data
    agent = next(r for r in data if r["name"] == "agent.exe"
                 and r["op"] == "create")
    assert agent["path"] == "Windows\\Temp\\agent.exe"

    main([str(j), "--op", "delete", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["op"] == "delete" for r in got)

    main([str(j), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_carve_mode(tmp_path):
    blob = b"\x99" * 128 + S.build_stream()
    p = tmp_path / "unalloc.bin"
    p.write_bytes(blob)
    js_p = tmp_path / "u.json"
    rc = main([str(p), "--carve", "--json", str(js_p), "-q"])
    assert rc == 0
    got = json.loads(js_p.read_text())
    assert got and all(r["carved"] == "yes" for r in got)


def test_csv_injection_guard():
    from windows_usn.tracelib import sanitize
    assert sanitize("-2+3") == "'-2+3"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
