from __future__ import annotations

import hashlib
import json
import os

import pytest

import _synth as S

from analysis_dpapi import aes
from analysis_dpapi.masterkey import decrypt_masterkey, parse_file
from analysis_dpapi.blob import decrypt_blob, parse_blob
from analysis_dpapi.collect import run
from analysis_dpapi.cli import main


def test_aes_roundtrip():
    key = os.urandom(32)
    iv = os.urandom(16)
    pt = os.urandom(64)
    ct = aes.encrypt_cbc(key, iv, pt)
    assert aes.decrypt_cbc(key, iv, ct) == pt
    # NIST-ish vector: AES-128 ECB
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    c = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes.decrypt_ecb(k, c) == bytes.fromhex(
        "00112233445566778899aabbccddeeff")


def test_masterkey_decrypt():
    data, real = S.build_masterkey_file()
    mkf = parse_file(data)
    assert mkf.guid == S.MK_GUID
    key, scheme = decrypt_masterkey(mkf.masterkey, S.SID,
                                    password=S.PASSWORD)
    assert key == real
    assert "sha512" in scheme


def test_masterkey_wrong_secret():
    data, _ = S.build_masterkey_file()
    mkf = parse_file(data)
    with pytest.raises(ValueError):
        decrypt_masterkey(mkf.masterkey, S.SID, password="not the password")
    with pytest.raises(ValueError):
        decrypt_masterkey(mkf.masterkey, "S-1-5-21-9-9-9-9",
                          password=S.PASSWORD)


def test_masterkey_sha1_prekey():
    data, real = S.build_masterkey_file()
    mkf = parse_file(data)
    ph = hashlib.sha1(S.PASSWORD.encode("utf-16-le")).digest()
    key, _ = decrypt_masterkey(mkf.masterkey, S.SID, pwdhash=ph)
    assert key == real


def test_blob_decrypt_and_sign():
    _data, real = S.build_masterkey_file()
    blob = S.build_blob(real, b"DPAPI\x00\x11cookie encryption key here 32b")
    b, _ = parse_blob(blob, 0)
    assert b.mk_guid == S.MK_GUID
    d = decrypt_blob(b, real)
    assert d.plaintext == b"DPAPI\x00\x11cookie encryption key here 32b"
    assert d.signature_verified


def test_blob_with_entropy():
    _data, real = S.build_masterkey_file()
    ent = b"extra-entropy-value"
    blob = S.build_blob(real, b"wifi-psk-here", entropy=ent)
    b, _ = parse_blob(blob, 0)
    assert decrypt_blob(b, real, entropy=ent).plaintext == b"wifi-psk-here"
    # wrong / missing entropy -> garbage plaintext (no crash)
    assert decrypt_blob(b, real).plaintext != b"wifi-psk-here"


def test_scan(tmp_path):
    protect = tmp_path / "Protect" / S.SID
    protect.mkdir(parents=True)
    data, real = S.build_masterkey_file()
    (protect / S.MK_GUID).write_bytes(data)
    blobs = tmp_path / "Vault"
    blobs.mkdir()
    (blobs / "cred1.bin").write_bytes(
        S.build_blob(real, "P@ssw0rd-for-svc".encode("utf-16-le")))

    res = run(str(protect), [str(blobs)], sid=S.SID, password=S.PASSWORD)
    assert res.masterkeys and res.masterkeys[0].decrypted
    assert res.blobs and res.blobs[0].decrypted
    assert "P@ssw0rd-for-svc" in res.blobs[0].preview


def test_cli(tmp_path):
    protect = tmp_path / "Protect" / S.SID
    protect.mkdir(parents=True)
    data, real = S.build_masterkey_file()
    mkfile = protect / S.MK_GUID
    mkfile.write_bytes(data)
    blobs = tmp_path / "b"
    blobs.mkdir()
    (blobs / "c.bin").write_bytes(S.build_blob(real, b"top-secret-value"))

    rc = main(["masterkey", str(mkfile), "--sid", S.SID,
               "--password", S.PASSWORD])
    assert rc == 0

    js = tmp_path / "o.json"
    rc = main(["scan", str(protect), "--blobs", str(blobs), "--sid", S.SID,
               "--password", S.PASSWORD, "--json", str(js), "-q"])
    assert rc == 0
    rows = json.loads(js.read_text())
    assert any(r["type"] == "blob" and r["decrypted"] for r in rows)


def test_csv_injection_guard():
    from analysis_dpapi.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
