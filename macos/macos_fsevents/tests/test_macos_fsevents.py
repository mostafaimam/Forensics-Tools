from __future__ import annotations

import json

import pytest

from macos_fsevents import fsevents as FSE
from macos_fsevents.collect import collect
from macos_fsevents.cli import main, _severity

import _synth as S


def test_parse_stream_v2():
    raw = S.build_log([("a/b.txt", 10, S.CREATED | S.FILE_EVENT, 42)],
                      version=2)
    recs = list(FSE.parse_stream(raw))
    assert len(recs) == 1
    r = recs[0]
    assert r.path == "a/b.txt" and r.event_id == 10 and r.node_id == 42
    assert "Created" in r.flag_names and "FileEvent" in r.flag_names
    assert r.version == 2


def test_parse_stream_v1():
    raw = S.build_log([("x", 5, S.MODIFIED, 0)], version=1)
    r = list(FSE.parse_stream(raw))[0]
    assert r.version == 1 and r.node_id == 0 and "Modified" in r.flag_names


def test_collect(tmp_path):
    S.build_volume(tmp_path / "mac")
    res = collect(str(tmp_path / "mac"))
    assert res.files == 3
    assert len(res.records) == 11
    ids = [r.event_id for r in res.records]
    assert ids == sorted(ids)
    by_path = {}
    for r in res.records:
        by_path.setdefault(r.path, []).append(r)
    assert len(by_path["private/tmp/.x/payload"]) == 2   # create + remove


def test_flags(tmp_path):
    S.build_volume(tmp_path / "mac")
    res = collect(str(tmp_path / "mac"))
    by = {}
    for r in res.records:
        by.setdefault(r.path, []).append(r)

    tcc = by["Library/Application Support/com.apple.TCC/TCC.db"][0]
    assert any("security / logging artefact was renamed" in n
               for n in tcc.notable)
    assert _severity(tcc.notable) == "high"

    hist = by["Users/victim/.zsh_history"][0]
    assert any("security / logging artefact was removed" in n
               for n in hist.notable)

    payload_rm = next(r for r in by["private/tmp/.x/payload"]
                      if "Removed" in r.flag_names)
    assert any("user-writable / temp path" in n for n in payload_rm.notable)

    mount = by["Volumes/USB"][0]
    assert any("volume mount event" in n for n in mount.notable)


def test_cli_csv_json_filters(tmp_path):
    S.build_volume(tmp_path / "mac")
    csv_p = tmp_path / "f.csv"
    js_p = tmp_path / "f.json"
    rc = main([str(tmp_path / "mac"), "--csv", str(csv_p),
               "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 11

    main([str(tmp_path / "mac"), "--flag", "Removed", "--json", str(js_p),
          "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("Removed" in r["flags"] for r in got)

    main([str(tmp_path / "mac"), "--grep", "TCC", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("TCC" in r["path"] for r in got)

    main([str(tmp_path / "mac"), "--min-severity", "high", "--json",
          str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_single_log_file(tmp_path):
    S.build_volume(tmp_path / "mac")
    f = tmp_path / "mac/.fseventsd/0000000000001388"
    js_p = tmp_path / "f.json"
    rc = main([str(f), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 5


def test_csv_injection_guard():
    from macos_fsevents.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
