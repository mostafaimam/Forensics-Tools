from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tracelib


def _args(**kw):
    p = argparse.ArgumentParser()
    tracelib.add_arguments(p)
    return p.parse_args([f"--{k.replace('_', '-')}={v}" if not isinstance(v, bool)
                         else f"--{k.replace('_', '-')}"
                         for k, v in kw.items() if v is not False])


def test_context_from_args_and_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACELIB_EXAMINER", "J. Doe")
    p = argparse.ArgumentParser()
    tracelib.add_arguments(p)
    a = p.parse_args(["--case-id", "CASE-42", "--evidence-id", "E-1"])
    ctx = tracelib.context(a, "demo_tool", "0.1.0")
    assert ctx.case_id == "CASE-42"
    assert ctx.evidence_id == "E-1"
    assert ctx.examiner == "J. Doe"          # from env
    assert ctx.enabled is True


def test_add_input_hashes_file(tmp_path):
    f = tmp_path / "evidence.bin"
    f.write_bytes(b"hello world")
    ctx = tracelib.RunContext("t", "1")
    rec = ctx.add_input(str(f))
    assert rec.exists and rec.size == 11
    assert rec.sha256 == tracelib.hash_bytes(b"hello world")
    assert rec.modified_utc.endswith("Z")


def test_add_missing_input(tmp_path):
    ctx = tracelib.RunContext("t", "1")
    rec = ctx.add_input(str(tmp_path / "nope"))
    assert rec.exists is False and rec.sha256 == ""


def test_warnings_and_counts():
    ctx = tracelib.RunContext("t", "1")
    ctx.partial("short-read", "record truncated", "offset 0x40")
    ctx.unsupported("v9-enterprise-ie", "skipped enterprise field")
    ctx.error("bad-magic", "not a pcap")
    c = ctx.counts()
    assert c == {"info": 0, "partial": 1, "unsupported": 1, "error": 1}
    assert "1 partial" in ctx.summary_line(10)
    assert "1 error(s)" in ctx.summary_line(10)


def test_write_csv_adds_provenance_columns(tmp_path):
    ctx = tracelib.RunContext("t", "1", case_id="C1", evidence_id="E1")
    out = tmp_path / "o.csv"
    tracelib.write_csv([{"a": "1", "source_db": "/x/History"}],
                       out, ["a"], ctx)
    text = out.read_bytes().decode("utf-8-sig")
    header = text.splitlines()[0].split(",")
    assert "evidence_source" in header
    assert "parser_confidence" in header
    assert "case_id" in header
    body = text.splitlines()[1]
    assert "/x/History" in body and "C1" in body


def test_write_csv_injection_guard(tmp_path):
    out = tmp_path / "o.csv"
    tracelib.write_csv([{"a": "=cmd()"}], out, ["a"], None)
    assert "'=cmd()" in out.read_bytes().decode("utf-8-sig")


def test_write_json_bare_list_by_default_with_provenance_fields(tmp_path):
    ctx = tracelib.RunContext("t", "1", case_id="C1")
    out = tmp_path / "o.json"
    tracelib.write_json([{"a": 1, "source": "in.txt"}], out, ctx,
                        confidence="high", tz="utc-native")
    doc = json.loads(out.read_text())
    assert isinstance(doc, list)                       # bare list, not wrapped
    assert doc[0]["evidence_source"] == "in.txt"
    assert doc[0]["parser_confidence"] == "high"
    assert doc[0]["tz_provenance"] == "utc-native"


def test_write_json_envelope_opt_in(tmp_path):
    ctx = tracelib.RunContext("t", "1", case_id="C1")
    out = tmp_path / "o.json"
    tracelib.write_json([{"a": 1}], out, ctx, envelope=True)
    doc = json.loads(out.read_text())
    assert doc["manifest"]["case_id"] == "C1"
    assert doc["records"][0]["a"] == 1


def test_write_json_no_provenance(tmp_path):
    ctx = tracelib.RunContext("t", "1", enabled=False)
    out = tmp_path / "o.json"
    tracelib.write_json([{"a": 1}], out, ctx)
    assert json.loads(out.read_text()) == [{"a": 1}]


def test_finish_writes_manifest_sidecar(tmp_path):
    ctx = tracelib.RunContext("demo", "0.2.0", case_id="CASE-9")
    inp = tmp_path / "e.bin"
    inp.write_bytes(b"A" * 32)
    ctx.add_input(str(inp))
    csv_out = tmp_path / "r.csv"
    tracelib.write_csv([{"x": "1"}], csv_out, ["x"], ctx)
    mpath = ctx.finish(outputs=[csv_out])
    assert mpath == str(csv_out) + ".manifest.json"
    m = json.loads(Path(mpath).read_text())
    assert m["schema"] == tracelib.SCHEMA
    assert m["tool"] == "demo" and m["case_id"] == "CASE-9"
    assert m["inputs"][0]["sha256"] == tracelib.hash_bytes(b"A" * 32)
    assert m["outputs"][0]["path"] == str(csv_out)
    assert m["outputs"][0]["sha256"]              # output hashed
    assert m["finished_utc"] >= m["started_utc"]


def test_finish_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    ctx = tracelib.RunContext("demo", "1", enabled=False)
    assert ctx.finish(outputs=[]) is None
    assert not list(tmp_path.glob("*.manifest.json"))


def test_limits_input_size(tmp_path):
    big = tmp_path / "big"
    big.write_bytes(b"0" * 5000)
    lim = tracelib.Limits(max_input_bytes=1000)
    with pytest.raises(tracelib.LimitExceeded):
        lim.check_paths([str(big)])


def test_limits_record_count():
    lim = tracelib.Limits(max_records=100)
    with pytest.raises(tracelib.LimitExceeded):
        for _ in range(200):
            lim.tick()


def test_limits_wall_clock(monkeypatch):
    lim = tracelib.Limits(wall_seconds=0.0)
    lim._start -= 10
    with pytest.raises(tracelib.LimitExceeded):
        lim.tick(4096)


def test_vocabularies():
    assert "recovered" in tracelib.CONFIDENCE
    assert "local-converted" in tracelib.TZ_PROVENANCE


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
