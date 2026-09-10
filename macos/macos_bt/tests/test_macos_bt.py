from __future__ import annotations

import json

import pytest

from macos_bt.parse import parse
from macos_bt import flags as _flags
from macos_bt.cli import main

import _synth as S


@pytest.fixture
def plist(tmp_path):
    return S.build(str(tmp_path / "com.apple.Bluetooth.plist"))


def _by_name(devs):
    return {d.name: d for d in devs}


def test_parse(plist):
    devs = parse(open(plist, "rb").read(), plist)
    assert len(devs) == 6
    by = _by_name(devs)
    phone = by["Victim's iPhone"]
    assert phone.is_paired and not phone.is_hid
    assert phone.device_type == "phone"
    assert phone.manufacturer == "Apple"
    assert phone.last_name_update.startswith("2026-03-13T09:00")

    kb = by["Magic Keyboard"]
    assert kb.is_paired and kb.is_hid
    assert kb.device_type == "peripheral" and kb.device_minor == "keyboard"

    pods = by["AirPods Pro"]
    assert pods.device_type == "audio/video"
    assert pods.device_minor == "headphones"
    assert pods.battery == "85"


def test_flags(plist):
    devs = parse(open(plist, "rb").read(), plist)
    by = _by_name(devs)

    kb = by["Magic Keyboard"]
    assert any("paired input device (keyboard)" in n for n in kb.notable)
    assert _flags.severity(kb.notable) == "high"

    hidk = by["HID Keyboard"]
    assert any("input device seen but not paired" in n for n in hidk.notable)

    spk = by["BT Speaker"]
    j = " ".join(spk.notable)
    assert "paired audio-input device (microphone)" in j
    assert "unrecognised manufacturer" in j

    # unnamed inquiry-only device
    ghost = next(d for d in devs if d.mac == "ff-ff-ff-66-66-66")
    assert any("seen once by inquiry" in n for n in ghost.notable)

    phone = by["Victim's iPhone"]
    assert not phone.notable


def test_cli_csv_json_filters(plist, tmp_path):
    csv_p = tmp_path / "b.csv"
    js_p = tmp_path / "b.json"
    rc = main([plist, "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    data = json.loads(js_p.read_text())
    assert len(data) == 6

    main([plist, "--paired-only", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["is_paired"] == "yes" for r in got)

    main([plist, "--type", "peripheral", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["device_type"] == "peripheral" for r in got)

    main([plist, "--min-severity", "high", "--json", str(js_p), "-q"])
    got = json.loads(js_p.read_text())
    assert got and all(r["severity"] == "high" for r in got)


def test_cli_mounted_volume(plist, tmp_path):
    vol = tmp_path / "mac"
    d = vol / "Library/Preferences"
    d.mkdir(parents=True)
    import shutil
    shutil.copy(plist, d / "com.apple.Bluetooth.plist")
    js_p = tmp_path / "b.json"
    rc = main([str(vol), "--json", str(js_p), "-q"])
    assert rc == 0
    assert len(json.loads(js_p.read_text())) == 6


def test_csv_injection_guard():
    from macos_bt.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
