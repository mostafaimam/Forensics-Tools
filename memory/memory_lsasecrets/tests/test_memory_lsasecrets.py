from __future__ import annotations

import json

import pytest

import _synth as S

from memory_lsasecrets.hive import RegistryHive
from memory_lsasecrets.lsakey import LsaSecretError, decrypt_secret, \
    derive_lsa_key
from memory_lsasecrets.collect import dump
from memory_lsasecrets.cli import main

BOOTKEY = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
LSA_KEY = bytes.fromhex("aabbccddeeff00112233445566778899" * 2)[:32]


def test_derive_lsa_key_roundtrip():
    polek = S.build_polek_list_blob(BOOTKEY, LSA_KEY)
    got = derive_lsa_key(BOOTKEY, polek)
    assert got == LSA_KEY


def test_derive_lsa_key_wrong_bootkey_fails():
    polek = S.build_polek_list_blob(BOOTKEY, LSA_KEY)
    wrong = bytes(b ^ 0xFF for b in BOOTKEY)
    with pytest.raises(LsaSecretError):
        derive_lsa_key(wrong, polek)


def test_decrypt_secret_roundtrip():
    plaintext = "S3cr3tServiceAcctPassw0rd!".encode("utf-16-le") + b"\x00\x00"
    blob = S.build_secret_blob(LSA_KEY, plaintext)
    got = decrypt_secret(LSA_KEY, blob)
    assert got == plaintext


def test_decrypt_secret_wrong_key_fails():
    plaintext = b"hello secret"
    blob = S.build_secret_blob(LSA_KEY, plaintext)
    wrong_key = bytes(b ^ 0xFF for b in LSA_KEY)
    with pytest.raises(LsaSecretError):
        decrypt_secret(wrong_key, blob)


def test_full_dump_end_to_end(tmp_path):
    class_hex = S.bootkey_to_class_hex(BOOTKEY)
    system_bytes = S.build_system_hive(class_hex)
    polek = S.build_polek_list_blob(BOOTKEY, LSA_KEY)

    svc_password = "Sup3rSecretSvc!".encode("utf-16-le") + b"\x00\x00"
    svc_blob = S.build_secret_blob(LSA_KEY, svc_password)
    dpapi_blob = S.build_secret_blob(LSA_KEY, bytes(range(32)))
    security_bytes = S.build_security_hive(polek, [
        ("_SC_MyServiceAccount", svc_blob),
        ("DPAPI_SYSTEM", dpapi_blob),
    ])

    system_path = tmp_path / "SYSTEM"
    security_path = tmp_path / "SECURITY"
    system_path.write_bytes(system_bytes)
    security_path.write_bytes(security_bytes)

    res = dump(str(system_path), str(security_path))
    assert not res.warnings
    by_name = {r["name"]: r for r in res.rows}
    assert by_name["_SC_MyServiceAccount"]["value_text"] == "Sup3rSecretSvc!"
    assert by_name["_SC_MyServiceAccount"]["reversible"] is True
    assert by_name["_SC_MyServiceAccount"]["notable"] == \
        "service-account-password"
    assert by_name["DPAPI_SYSTEM"]["reversible"] is False
    assert by_name["DPAPI_SYSTEM"]["notable"] == "sensitive-secret"
    assert by_name["DPAPI_SYSTEM"]["value_hex"] == bytes(range(32)).hex()


def test_cli_end_to_end(tmp_path):
    class_hex = S.bootkey_to_class_hex(BOOTKEY)
    system_bytes = S.build_system_hive(class_hex)
    polek = S.build_polek_list_blob(BOOTKEY, LSA_KEY)
    svc_blob = S.build_secret_blob(
        LSA_KEY, "hunter2pass".encode("utf-16-le") + b"\x00\x00")
    security_bytes = S.build_security_hive(polek, [
        ("_SC_Backup", svc_blob),
    ])
    system_path = tmp_path / "SYSTEM"
    security_path = tmp_path / "SECURITY"
    system_path.write_bytes(system_bytes)
    security_path.write_bytes(security_bytes)

    js = tmp_path / "out.json"
    csv = tmp_path / "out.csv"
    rc = main(["--system", str(system_path), "--security", str(security_path),
              "--json", str(js), "--csv", str(csv), "-q"])
    assert rc == 0
    assert csv.read_bytes().startswith(b"\xef\xbb\xbf")
    rows = json.loads(js.read_text())
    assert rows[0]["value_text"] == "hunter2pass"

    js2 = tmp_path / "out2.json"
    rc = main(["--system", str(system_path), "--security", str(security_path),
              "--reversible-only", "--json", str(js2), "-q"])
    assert rc == 0
    rows2 = json.loads(js2.read_text())
    assert rows2 and all(r["reversible"] for r in rows2)


def test_cli_missing_files():
    rc = main(["--system", "/no/such/system", "--security", "/no/such/sec"])
    assert rc == 2


def test_no_polek_list_warns(tmp_path):
    class_hex = S.bootkey_to_class_hex(BOOTKEY)
    system_bytes = S.build_system_hive(class_hex)
    security_bytes = S.build_security_hive(b"", [])
    system_path = tmp_path / "SYSTEM"
    security_path = tmp_path / "SECURITY"
    system_path.write_bytes(system_bytes)
    security_path.write_bytes(security_bytes)
    res = dump(str(system_path), str(security_path))
    assert not res.rows
    assert res.warnings


def test_csv_injection_guard():
    from memory_lsasecrets.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
