from __future__ import annotations

import json

import pytest

import _synth as S
import _qsynth as Q
import _hive_synth as H

from windows_defender.collect import collect
from windows_defender.quarantine import parse_entry
from windows_defender.cli import main


def test_quarantine_entry_roundtrip():
    raw = Q.build_entry()
    e = parse_entry(raw, "x")
    assert e.threat == "Trojan:Win32/Wacatac.B!ml"
    assert e.threat_id == 2147735503
    assert e.timestamp == "2026-03-16T10:15:00Z"
    assert e.resources and e.resources[0].path.endswith("invoice.exe")
    assert e.resources[0].sha1 == bytes(range(20)).hex()


def test_quarantine_dir(tmp_path):
    Q.write_quarantine(tmp_path / "Quarantine")
    res = collect([str(tmp_path)])
    q = [r for r in res.rows if r["kind"] == "quarantine"]
    assert q and q[0]["threat"] == "Trojan:Win32/Wacatac.B!ml"
    assert q[0]["severity"] == "high"
    assert "threat detected / quarantined" in q[0]["notable"]


def test_defender_evtx(tmp_path):
    p = tmp_path / "Microsoft-Windows-Windows Defender%4Operational.evtx"
    p.write_bytes(S.build_evtx())
    res = collect([str(p)])
    kinds = {r["kind"] for r in res.rows}
    assert "evtx-detection" in kinds
    assert "evtx-tamper" in kinds
    det = next(r for r in res.rows if r["kind"] == "evtx-detection"
               and r["event_id"] == "1116")
    assert det["threat"] == "Trojan:Win32/Wacatac.B!ml"
    assert det["time"] == "2026-03-16T10:15:00Z"
    tamper = next(r for r in res.rows if r["event_id"] == "5007")
    assert tamper["severity"] == "high"
    assert "tampering" in tamper["notable"]


def test_mplog(tmp_path):
    p = tmp_path / "MPLog-20260316-090000.log"
    p.write_text(S.MPLOG)
    res = collect([str(p)])
    dets = [r for r in res.rows if r["kind"] == "mplog-detection"]
    assert any(r["threat"] == "Trojan:Win32/Wacatac.B!ml" for r in dets)
    assert any(r["kind"] == "mplog-exclusion" for r in res.rows)
    procs = [r for r in res.rows if r["kind"] == "mplog-process"]
    assert procs and procs[0]["pid"] == "4512"


def test_software_hive(tmp_path):
    p = tmp_path / "SOFTWARE"
    p.write_bytes(H.build_software_hive())
    res = collect([str(p)])
    excl = [r for r in res.rows if r["kind"].startswith("exclusion")]
    paths = [r for r in excl if r["kind"] == "exclusion-paths"]
    assert {r["path"] for r in paths} == {
        "C:\\Users\\victim\\AppData\\Local\\Temp", "C:\\"}
    broad = next(r for r in paths if r["path"] == "C:\\")
    assert broad["severity"] == "high"
    settings = [r for r in res.rows if r["kind"] == "protection-setting"]
    assert any("DisableRealtimeMonitoring" in r["path"] for r in settings)
    assert any(r["severity"] == "high" for r in settings)


def test_cli_csv_json_filters(tmp_path):
    root = tmp_path / "Windows Defender"
    (root / "Support").mkdir(parents=True)
    (root / "Support" / "MPLog-20260316-090000.log").write_text(S.MPLOG)
    (root / "Microsoft-Windows-Windows Defender%4Operational.evtx"
     ).write_bytes(S.build_evtx())
    Q.write_quarantine(root / "Quarantine")
    (root / "SOFTWARE").write_bytes(H.build_software_hive())

    csv_p = tmp_path / "d.csv"
    js_p = tmp_path / "d.json"
    rc = main([str(root), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) >= 8

    main([str(root), "--min-severity", "high", "--json", str(js_p), "-q"])
    hi = json.loads(js_p.read_text())
    assert hi and all(r["severity"] == "high" for r in hi)

    main([str(root), "--kind", "quarantine", "--json", str(js_p), "-q"])
    q = json.loads(js_p.read_text())
    assert q and all(r["kind"] == "quarantine" for r in q)

    main([str(root), "--grep", "Wacatac", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())


def test_csv_injection_guard():
    from windows_defender.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
