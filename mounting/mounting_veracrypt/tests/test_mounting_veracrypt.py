from __future__ import annotations

import json

import pytest

import _synth as S

from mounting_veracrypt.header import HeaderError, try_password
from mounting_veracrypt.sectors import decrypt_range
from mounting_veracrypt.cli import main


def test_unlock_roundtrip(tmp_path):
    path, offset = S.build_volume(tmp_path)
    hdr = try_password(path, S.PASSWORD, iterations=1000)
    assert hdr.magic == b"VERA"
    assert hdr.master_key_scope_offset == offset
    assert not hdr.is_hidden
    assert hdr.effective_sector_size == 512


def test_wrong_password_rejected(tmp_path):
    path, _off = S.build_volume(tmp_path)
    with pytest.raises(HeaderError):
        try_password(path, "not the password", iterations=1000)


def test_wrong_iterations_rejected(tmp_path):
    path, _off = S.build_volume(tmp_path)
    with pytest.raises(HeaderError):
        try_password(path, S.PASSWORD, iterations=999)


def test_tampered_crc_rejected(tmp_path):
    path, _off = S.build_volume(tmp_path, tamper_crc=True)
    with pytest.raises(HeaderError):
        try_password(path, S.PASSWORD, iterations=1000)


def test_truecrypt_magic_accepted(tmp_path):
    path, _off = S.build_volume(tmp_path, magic=b"TRUE")
    hdr = try_password(path, S.PASSWORD, iterations=1000)
    assert hdr.magic == b"TRUE"


def test_sha256_hash_supported(tmp_path):
    path, _off = S.build_volume(tmp_path, hash_name="sha256")
    hdr = try_password(path, S.PASSWORD, hash_name="sha256", iterations=1000)
    assert hdr.magic == b"VERA"


def test_hidden_volume_size_reported(tmp_path):
    path, _off = S.build_volume(tmp_path, hidden_volume_size=65536)
    hdr = try_password(path, S.PASSWORD, iterations=1000)
    assert hdr.is_hidden
    assert hdr.hidden_volume_size == 65536


def test_payload_decrypt(tmp_path):
    path, offset = S.build_volume(tmp_path, payload_sectors=3)
    hdr = try_password(path, S.PASSWORD, iterations=1000)
    plain = decrypt_range(hdr, path, offset, 512 * 3)
    assert plain[:22] == b"payload sector 0 data "
    assert plain[512:512 + 22] == b"payload sector 1 data "


def test_decrypt_requires_sector_alignment(tmp_path):
    path, offset = S.build_volume(tmp_path)
    hdr = try_password(path, S.PASSWORD, iterations=1000)
    with pytest.raises(ValueError):
        decrypt_range(hdr, path, offset + 1, 512)


def test_cli_info_and_decrypt(tmp_path):
    path, offset = S.build_volume(tmp_path, payload_sectors=2)

    js = tmp_path / "info.json"
    rc = main(["info", path, "--password", S.PASSWORD, "--iterations",
              "1000", "--json", str(js)])
    assert rc == 0
    info = json.loads(js.read_text())
    assert info["magic"] == "VERA"
    assert info["master_key_scope_offset"] == offset

    out = tmp_path / "plain.bin"
    rc = main(["decrypt", path, "--password", S.PASSWORD, "--iterations",
              "1000", "--length", "1024", "-o", str(out)])
    assert rc == 0
    assert out.read_bytes()[:15] == b"payload sector "

    rc = main(["decrypt", path, "--password", "nope", "--iterations",
              "1000", "--length", "512", "-o", str(tmp_path / "x.bin")])
    assert rc == 1


def test_csv_injection_guard():
    from mounting_veracrypt.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
