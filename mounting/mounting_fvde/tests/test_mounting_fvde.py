from __future__ import annotations

import hashlib
import plistlib

import pytest

from mounting_fvde import aes
from mounting_fvde.keywrap import KeyWrapError, unwrap, wrap
from mounting_fvde.corestorage import find_candidates, find_embedded_plists
from mounting_fvde.unlock import (UnlockError, decrypt_and_verify,
                                  derive_vek, xts_keys_from_vek)
from mounting_fvde.cli import main

# RFC 3394 Section 4.1 official test vector: wrap 128 bits of key data
# with a 128-bit KEK. A genuine known-answer test, not just round-trip
# self-consistency.
_RFC3394_KEK = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
_RFC3394_KEYDATA = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
_RFC3394_WRAPPED = bytes.fromhex(
    "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")


def test_rfc3394_known_answer_unwrap():
    assert unwrap(_RFC3394_KEK, _RFC3394_WRAPPED) == _RFC3394_KEYDATA


def test_rfc3394_known_answer_wrap():
    assert wrap(_RFC3394_KEK, _RFC3394_KEYDATA) == _RFC3394_WRAPPED


def test_rfc3394_roundtrip_32_byte_key():
    kek = bytes(range(16))
    key = bytes(range(32, 64))
    assert unwrap(kek, wrap(kek, key)) == key


def test_rfc3394_wrong_kek_rejected():
    kek = bytes(range(16))
    wrong_kek = bytes(range(1, 17))
    wrapped = wrap(kek, bytes(range(32, 64)))
    with pytest.raises(KeyWrapError):
        unwrap(wrong_kek, wrapped)


def test_find_embedded_plist():
    blob = plistlib.dumps({"a": 1}, fmt=plistlib.FMT_BINARY)
    data = b"junk-prefix" + blob + b"junk-suffix"
    hits = find_embedded_plists(data)
    assert len(hits) == 1
    assert hits[0][1] == {"a": 1}


def test_find_candidates_finds_key_shaped_blob():
    plausible = bytes(range(60))  # 60 bytes, inside the 32-256 range
    plist = plistlib.dumps({"CryptoUsers": [{"WrappedKEKStruct":
                                            plausible}]},
                          fmt=plistlib.FMT_BINARY)
    cands = find_candidates(plist)
    assert len(cands) == 1
    assert cands[0].length == 60
    assert cands[0].blob == plausible


def test_derive_vek_recovers_known_key():
    password = "correct horse battery staple"
    salt = b"\x01" * 16
    iterations = 10000
    vek = bytes(range(32))
    kek = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                              iterations, dklen=16)
    wrapped = wrap(kek, vek)
    recovered = derive_vek(password, salt, iterations, wrapped)
    assert recovered == vek


def test_derive_vek_wrong_password_rejected():
    salt = b"\x02" * 16
    wrapped = wrap(hashlib.pbkdf2_hmac("sha256", b"right", salt, 1000,
                                       dklen=16), bytes(range(32)))
    with pytest.raises(UnlockError):
        derive_vek("wrong", salt, 1000, wrapped)


def test_xts_keys_from_vek_splits_in_half():
    vek = bytes(range(32))
    k1, k2 = xts_keys_from_vek(vek)
    assert k1 == vek[:16]
    assert k2 == vek[16:]


def test_xts_keys_wrong_length_rejected():
    with pytest.raises(UnlockError):
        xts_keys_from_vek(b"\x00" * 16)


def _hfs_shaped_plaintext(nblocks=128) -> bytes:
    buf = bytearray(nblocks * 16)
    buf[1024:1026] = b"H+"
    return bytes(buf)


def test_decrypt_and_verify_recovers_hfs_magic():
    key1, key2 = bytes(range(16)), bytes(range(16, 32))
    plaintext = _hfs_shaped_plaintext()
    ciphertext = aes.xts_encrypt_sector(key1, key2, 0, plaintext)
    recovered = decrypt_and_verify(key1, key2, ciphertext)
    assert recovered[1024:1026] == b"H+"


def test_decrypt_and_verify_wrong_key_raises():
    key1, key2 = bytes(range(16)), bytes(range(16, 32))
    wrong_key1 = bytes(range(1, 17))
    plaintext = _hfs_shaped_plaintext()
    ciphertext = aes.xts_encrypt_sector(key1, key2, 0, plaintext)
    with pytest.raises(UnlockError):
        decrypt_and_verify(wrong_key1, key2, ciphertext)


def test_cli_info(tmp_path):
    plausible = bytes(range(40, 100))
    plist = plistlib.dumps({"CryptoUsers": [{"blob": plausible}]},
                          fmt=plistlib.FMT_BINARY)
    p = tmp_path / "EncryptedRoot.plist.wipekey"
    p.write_bytes(plist)
    rc = main(["info", str(p)])
    assert rc == 0


def test_cli_info_not_found():
    rc = main(["info", "/definitely/not/a/real/path"])
    assert rc == 2


def test_cli_unlock():
    password, salt, iterations = "hunter2", "0102030405060708" * 2, 5000
    kek = hashlib.pbkdf2_hmac("sha256", password.encode(),
                              bytes.fromhex(salt), iterations, dklen=16)
    wrapped = wrap(kek, bytes(range(32)))
    rc = main(["unlock", "--password", password, "--salt-hex", salt,
              "--iterations", str(iterations), "--wrapped-hex",
              wrapped.hex()])
    assert rc == 0


def test_cli_unlock_wrong_password():
    salt = "aa" * 16
    wrapped = wrap(hashlib.pbkdf2_hmac("sha256", b"right",
                                       bytes.fromhex(salt), 1000,
                                       dklen=16), bytes(range(32)))
    rc = main(["unlock", "--password", "wrong", "--salt-hex", salt,
              "--iterations", "1000", "--wrapped-hex", wrapped.hex()])
    assert rc == 1


def test_csv_injection_guard():
    from mounting_fvde.tracelib import sanitize
    assert sanitize("=cmd") == "'=cmd"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
