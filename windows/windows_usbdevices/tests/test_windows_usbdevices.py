from __future__ import annotations

import json

import pytest

from windows_usbdevices import registry as R
from windows_usbdevices import setupapi as SA
from windows_usbdevices.analyze import analyze
from windows_usbdevices.cli import main, _severity

import _synth as S


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "img"
    cfg = r / "Windows/System32/config"
    cfg.mkdir(parents=True)
    (cfg / "SYSTEM").write_bytes(S.build_system_hive())
    (cfg / "SOFTWARE").write_bytes(S.build_software_hive())
    inf = r / "Windows/INF"
    inf.mkdir(parents=True)
    (inf / "setupapi.dev.log").write_text(S.SETUPAPI_LOG)
    return r


def test_system_hive_parse():
    devs, _mm = R.from_system_hive(S.build_system_hive())
    assert len(devs) == 2
    k = devs[S.SERIAL_KINGSTON]
    assert k.vendor == "Kingston" and k.product == "DataTraveler"
    assert k.revision == "1.00"
    assert k.serial_synthetic is True
    assert k.friendly_name.startswith("Kingston DataTraveler")
    assert k.first_install.startswith("2026-03-01T14:00")
    assert k.last_removal.startswith("2026-03-01T14:30")
    assert k.vid == "0951" and k.pid == "1666"
    assert "E:" in k.drive_letters


def test_setupapi():
    fs = SA.first_seen(S.SETUPAPI_LOG)
    assert fs[S.SERIAL_SANDISK] == "2026-03-04T23:39:58Z"


def test_analyze_full(root):
    res = analyze([str(root)])
    assert res.have_system and res.have_software and res.have_setupapi
    by = {d.serial: d for d in res.devices}
    k = by[S.SERIAL_KINGSTON]
    assert k.volume_name == "KINGSTON (E:)"
    s = by[S.SERIAL_SANDISK]
    assert s.setupapi_first_seen == "2026-03-04T23:39:58Z"


def test_flags(root):
    res = analyze([str(root)])
    by = {d.serial: d for d in res.devices}
    assert any("no unique serial" in n for n in by[S.SERIAL_KINGSTON].notable)
    s = by[S.SERIAL_SANDISK]
    j = " ".join(s.notable)
    assert "connected only once" in j
    assert "outside business hours" in j


def test_known_good(root):
    res = analyze([str(root)], {"Kingston"})
    by = {d.serial: d for d in res.devices}
    assert any("not on the --known-good list" in n
               for n in by[S.SERIAL_SANDISK].notable)
    assert not any("known-good" in n for n in by[S.SERIAL_KINGSTON].notable)
    assert _severity(by[S.SERIAL_SANDISK].notable) == "high"


def test_cli_csv_json_filters(root, tmp_path):
    csv_p = tmp_path / "u.csv"
    js_p = tmp_path / "u.json"
    rc = main([str(root), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 2

    main([str(root), "--grep", "SanDisk", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("SanDisk" in r["vendor"] for r in got)

    main([str(root), "--known-good", "Kingston", "--min-severity", "high",
          "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all("SanDisk" in r["vendor"] for r in got)


def test_cli_system_hive_only(tmp_path):
    h = tmp_path / "SYSTEM"
    h.write_bytes(S.build_system_hive())
    js_p = tmp_path / "u.json"
    rc = main([str(h), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 2


def test_csv_injection_guard():
    from windows_usbdevices.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
