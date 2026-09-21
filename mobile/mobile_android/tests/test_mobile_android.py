from __future__ import annotations

import json

import pytest

import _synth as S

from mobile_android.abformat import AbFormatError, parse_header
from mobile_android.extract import EncryptedBackupError, list_entries
from mobile_android.collect import collect
from mobile_android.cli import main


def test_parse_header_unencrypted(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p, compressed=True)
    header = parse_header(p.read_bytes())
    assert header.version == 5
    assert header.compressed is True
    assert header.encryption == "none"


def test_parse_header_bad_magic(tmp_path):
    p = tmp_path / "b.ab"
    S.build_bad_magic(p)
    with pytest.raises(AbFormatError):
        parse_header(p.read_bytes())


def test_list_entries_uncompressed(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p, compressed=False)
    entries, header = list_entries(str(p))
    assert not header.compressed
    names = {e.path for e in entries}
    assert "apps/com.example.app/f/notes.txt" in names


def test_list_entries_compressed_and_classified(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p, compressed=True)
    entries, _header = list_entries(str(p))
    by_path = {e.path: e for e in entries}
    f_entry = by_path["apps/com.example.app/f/notes.txt"]
    assert f_entry.package == "com.example.app"
    assert f_entry.category == "f"
    assert f_entry.entry_type == "file"
    db_entry = by_path["apps/com.example.app/db/app.db"]
    assert db_entry.category == "db"
    shared_entry = by_path["shared/0/Pictures/photo.jpg"]
    assert shared_entry.category == "shared"
    assert shared_entry.package == ""


def test_encrypted_backup_raises(tmp_path):
    p = tmp_path / "b.ab"
    S.build_encrypted_ab(p)
    with pytest.raises(EncryptedBackupError):
        list_entries(str(p))


def test_collect_encrypted_warns(tmp_path):
    p = tmp_path / "b.ab"
    S.build_encrypted_ab(p)
    res = collect(str(p))
    assert not res.rows
    assert any("encrypt" in w.lower() for w in res.warnings)


def test_collect_unencrypted(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p)
    res = collect(str(p))
    assert not res.warnings
    assert len(res.rows) == 5
    assert res.header["encryption"] == "none"


def test_cli_csv_json(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p)
    csv_p = tmp_path / "out.csv"
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--csv", str(csv_p), "--json", str(js_p), "-q"])
    assert rc == 0
    assert csv_p.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js_p.read_text())
    assert len(rows) == 5


def test_cli_package_filter(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p)
    js_p = tmp_path / "out.json"
    rc = main([str(p), "--package", "com.example", "--json", str(js_p),
              "-q"])
    assert rc == 0
    rows = json.loads(js_p.read_text())
    assert rows and all(r["package"] == "com.example.app" for r in rows)


def test_cli_extract_dir(tmp_path):
    p = tmp_path / "b.ab"
    S.build_ab(p)
    out_dir = tmp_path / "extracted"
    rc = main([str(p), "--extract-dir", str(out_dir), "-q"])
    assert rc == 0
    extracted = out_dir / "apps" / "com.example.app" / "f" / "notes.txt"
    assert extracted.is_file()
    assert extracted.read_bytes() == b"hello from the app"


def test_cli_encrypted_exit_code(tmp_path):
    p = tmp_path / "b.ab"
    S.build_encrypted_ab(p)
    rc = main([str(p), "-q"])
    assert rc == 1


def test_cli_not_found():
    rc = main(["/definitely/not/a/real/file.ab"])
    assert rc == 2


def test_csv_injection_guard():
    from mobile_android.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
