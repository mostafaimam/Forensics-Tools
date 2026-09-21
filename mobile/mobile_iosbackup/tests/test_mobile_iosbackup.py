from __future__ import annotations

import json

import pytest

import _synth as S

from mobile_iosbackup.backup import find_backups, load_backup
from mobile_iosbackup.fileentry import decode
from mobile_iosbackup.collect import collect
from mobile_iosbackup.cli import main


def test_find_and_load_backup(tmp_path):
    backup = S.build_backup(tmp_path)
    found = find_backups(str(tmp_path))
    assert found == [backup]
    info = load_backup(backup)
    assert info.udid == "00008030-001A2D3E1234567X"
    assert info.device_name == "Test iPhone"
    assert info.is_encrypted is False


def test_decode_plain_file_blob():
    blob = S.plain_file_blob(size=555, mode=0o100644, uid=501)
    meta = decode(blob)
    assert meta.size == 555
    assert meta.file_type == "file"
    assert meta.uid == 501
    assert meta.birth.startswith("2025-01-01")


def test_decode_directory_mode():
    meta = decode(S.plain_file_blob(mode=0o40755))
    assert meta.file_type == "directory"


def test_decode_keyed_archive_blob():
    blob = S.keyed_archive_file_blob(size=999, mode=0o100644)
    meta = decode(blob)
    assert meta.size == 999
    assert meta.file_type == "file"


def test_collect_unencrypted_backup(tmp_path):
    S.build_backup(tmp_path)
    res = collect([str(tmp_path)])
    assert not res.warnings
    assert len(res.rows) == 3
    sms = next(r for r in res.rows if r["relative_path"].endswith("sms.db"))
    assert sms["domain"] == "HomeDomain"
    assert sms["on_disk"] is True
    assert sms["size"] == 40960
    assert sms["file_id_mismatch"] is False


def test_collect_missing_content_flagged(tmp_path):
    S.build_backup(tmp_path)
    res = collect([str(tmp_path)])
    missing = next(r for r in res.rows
                  if r["relative_path"] == "Library/Preferences/missing.plist")
    assert missing["on_disk"] is False


def test_collect_encrypted_backup_warns_and_skips(tmp_path):
    S.build_encrypted_backup(tmp_path)
    res = collect([str(tmp_path)])
    assert not res.rows
    assert any("encrypted" in w.lower() for w in res.warnings)


def test_collect_no_backup_warns(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    res = collect([str(empty)])
    assert not res.rows
    assert res.warnings


def test_file_id_computed_correctly(tmp_path):
    backup = S.build_backup(tmp_path)
    expected = S.file_id("HomeDomain", "Library/SMS/sms.db")
    on_disk = (backup / expected[:2] / expected).is_file()
    assert on_disk


def test_cli_csv_json(tmp_path):
    S.build_backup(tmp_path)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--csv", str(csv_p), "--json", str(js_p),
              "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert len(rows) == 3


def test_cli_domain_filter(tmp_path):
    S.build_backup(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--domain", "CameraRoll", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["domain"] == "CameraRollDomain" for r in rows)


def test_cli_extract_reconstructs_tree(tmp_path):
    S.build_backup(tmp_path)
    out_dir = tmp_path / "extracted"
    rc = main([str(tmp_path), "--extract-dir", str(out_dir), "-q"])
    assert rc == 0
    extracted = out_dir / "HomeDomain" / "Library" / "SMS" / "sms.db"
    assert extracted.is_file()
    assert extracted.read_bytes() == b"synthetic file content"
    # the missing (never-on-disk) entry must not appear
    assert not (out_dir / "HomeDomain" / "Library" / "Preferences" /
               "missing.plist").exists()


def test_cli_missing_only(tmp_path):
    S.build_backup(tmp_path)
    js_p = tmp_path / "out.json"
    rc = main([str(tmp_path), "--missing-only", "--json", str(js_p), "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(not r["on_disk"] for r in rows)


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/path"])
    assert rc == 2


def test_csv_injection_guard():
    from mobile_iosbackup.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
