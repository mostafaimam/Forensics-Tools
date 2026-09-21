from __future__ import annotations

import json
import os

import pytest

import _synth as S

from memory_hashdump.bootkey import BootKeyError, derive_bootkey
from memory_hashdump.hive import RegistryHive
from memory_hashdump.samhash import compute_hashed_boot_key, decode_user_hashes
from memory_hashdump.collect import dump
from memory_hashdump.cli import main

BOOTKEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
HASHEDBOOTKEY = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
SALT = os.urandom(16)


def test_derive_bootkey_from_class_permutation():
    class_hex = S.bootkey_to_class_hex(BOOTKEY)
    system_bytes = S.build_system_hive(class_hex)
    hive = RegistryHive(system_bytes)
    got = derive_bootkey(hive)
    assert got == BOOTKEY


def test_derive_bootkey_missing_lsa_raises():
    b = S.HiveBuilder()
    root = b.nk("ROOT", flags=0x2C)
    hive = RegistryHive(b.build(root))
    with pytest.raises(BootKeyError):
        derive_bootkey(hive)


def test_compute_hashed_boot_key_legacy():
    f = S.build_f_value_legacy(BOOTKEY, HASHEDBOOTKEY, SALT)
    hbk = compute_hashed_boot_key(f, BOOTKEY)
    assert hbk.revision == 2
    assert hbk.key == HASHEDBOOTKEY


def test_decode_user_hashes_roundtrip():
    f = S.build_f_value_legacy(BOOTKEY, HASHEDBOOTKEY, SALT)
    hbk = compute_hashed_boot_key(f, BOOTKEY)
    rid = 1000
    lm = bytes.fromhex("aad3b435b51404eeaad3b435b51404ee")
    nt = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")
    v = S.build_v_value(rid, hbk.key, lm=lm, nt=nt)
    got_lm, got_nt = decode_user_hashes(v, rid, hbk)
    assert got_lm == lm
    assert got_nt == nt


def test_decode_user_hashes_different_rid_gives_wrong_hash():
    f = S.build_f_value_legacy(BOOTKEY, HASHEDBOOTKEY, SALT)
    hbk = compute_hashed_boot_key(f, BOOTKEY)
    nt = bytes.fromhex("0123456789abcdef0123456789abcdef")
    v = S.build_v_value(1000, hbk.key, lm=None, nt=nt)
    _lm, wrong_nt = decode_user_hashes(v, 1001, hbk)
    assert wrong_nt != nt


def test_full_dump_end_to_end(tmp_path):
    class_hex = S.bootkey_to_class_hex(BOOTKEY)
    system_bytes = S.build_system_hive(class_hex)
    f = S.build_f_value_legacy(BOOTKEY, HASHEDBOOTKEY, SALT)
    hbk = compute_hashed_boot_key(f, BOOTKEY)

    admin_nt = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    guest_nt = bytes.fromhex("31d6cfe0d16ae931b73c59d7e0c089c0")  # blank
    v_admin = S.build_v_value(500, hbk.key, lm=None, nt=admin_nt)
    v_guest = S.build_v_value(501, hbk.key, lm=None, nt=guest_nt)
    sam_bytes = S.build_sam_hive(f, [
        (500, "Administrator", v_admin),
        (501, "Guest", v_guest),
    ])

    system_path = tmp_path / "SYSTEM"
    sam_path = tmp_path / "SAM"
    system_path.write_bytes(system_bytes)
    sam_path.write_bytes(sam_bytes)

    res = dump(str(system_path), str(sam_path))
    assert not res.warnings
    assert res.revision == 2
    by_rid = {r["rid"]: r for r in res.rows}
    assert by_rid[500]["username"] == "Administrator"
    assert by_rid[500]["nt_hash"] == admin_nt.hex()
    assert by_rid[500]["nt_empty"] is False
    assert by_rid[501]["username"] == "Guest"
    assert by_rid[501]["nt_empty"] is True


def test_cli_end_to_end(tmp_path):
    class_hex = S.bootkey_to_class_hex(BOOTKEY)
    system_bytes = S.build_system_hive(class_hex)
    f = S.build_f_value_legacy(BOOTKEY, HASHEDBOOTKEY, SALT)
    hbk = compute_hashed_boot_key(f, BOOTKEY)
    v = S.build_v_value(500, hbk.key, lm=None,
                        nt=bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    sam_bytes = S.build_sam_hive(f, [(500, "Administrator", v)])

    system_path = tmp_path / "SYSTEM"
    sam_path = tmp_path / "SAM"
    system_path.write_bytes(system_bytes)
    sam_path.write_bytes(sam_bytes)

    js = tmp_path / "out.json"
    csv = tmp_path / "out.csv"
    rc = main(["--system", str(system_path), "--sam", str(sam_path),
              "--json", str(js), "--csv", str(csv), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert rows[0]["username"] == "Administrator"


def test_cli_missing_files():
    rc = main(["--system", "/no/such/system", "--sam", "/no/such/sam"])
    assert rc == 2


def test_csv_injection_guard():
    from memory_hashdump.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
