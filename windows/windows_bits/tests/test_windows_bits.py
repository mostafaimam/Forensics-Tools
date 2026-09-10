from __future__ import annotations

import json

import pytest

import _synth as S

from windows_bits.carve import carve
from windows_bits.collect import collect
from windows_bits.cli import main


def test_carve_basic():
    files = carve(S.build_qmgr(), "qmgr.dat")
    urls = {f.url for f in files}
    assert "http://185.220.101.5/payload.exe" in urls
    assert "https://exfil.ooufhwef.top/upload" in urls
    assert any(f.dest.endswith("firefox.msi") for f in files)

    exe = next(f for f in files if f.url.endswith("payload.exe"))
    assert exe.dest == "C:\\Windows\\System32\\wu.exe"
    assert exe.job_name == "WindowsUpdate"
    assert exe.job_type == "download"
    assert exe.owner == "S-1-5-18"
    assert exe.ctime.startswith("2026-03-16")
    assert exe.tmp_file.endswith("BITA1B2.tmp")
    assert exe.download_size == 45056


def test_upload_job():
    files = carve(S.build_qmgr(), "x")
    up = next(f for f in files if "exfil" in f.url)
    assert up.job_type == "upload"
    assert up.owner.endswith("-1104")
    assert up.download_size == -1
    assert up.transfer_size == 1048576


def test_flags(tmp_path):
    p = tmp_path / "qmgr0.dat"
    p.write_bytes(S.build_qmgr())
    res = collect([str(p)])
    by_url = {r["url"]: r for r in res.rows}

    exe = by_url["http://185.220.101.5/payload.exe"]
    assert exe["severity"] == "high"
    j = exe["notable"]
    assert "raw IP" in j
    assert "system directory" in j
    assert "executable / script payload" in j

    up = by_url["https://exfil.ooufhwef.top/upload"]
    assert "upload job (possible exfiltration)" in up["notable"]
    assert "suspicious top-level domain in URL" in up["notable"]

    benign = by_url[
        "https://download-installer.cdn.mozilla.net/pub/firefox.msi"]
    assert benign["severity"] in ("none", "low", "medium")


def test_cli_csv_json_filters(tmp_path):
    d = tmp_path / "Downloader"
    d.mkdir()
    (d / "qmgr.db").write_bytes(S.build_qmgr())  # name-based discovery
    csv_p = tmp_path / "b.csv"
    js_p = tmp_path / "b.json"
    rc = main([str(d), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) >= 3

    main([str(d), "--type", "upload", "--json", str(js_p), "-q"])
    up = json.loads(js_p.read_text())
    assert up and all(r["type"] == "upload" for r in up)

    main([str(d), "--min-severity", "high", "--json", str(js_p), "-q"])
    hi = json.loads(js_p.read_text())
    assert hi and all(r["severity"] == "high" for r in hi)

    main([str(d), "--grep", r"payload\.exe", "--json", str(js_p), "-q"])
    assert json.loads(js_p.read_text())


def test_csv_injection_guard():
    from windows_bits.tracelib import sanitize
    assert sanitize("=HYPERLINK()") == "'=HYPERLINK()"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
