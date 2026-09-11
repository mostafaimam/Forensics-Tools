from __future__ import annotations

import json

import pytest

import _synth as S

from mounting_bitlocker.fve import parse
from mounting_bitlocker.unlock import UnlockError, unlock_with_recovery_password
from mounting_bitlocker.sectors import decrypt_range
from mounting_bitlocker.recovery import parse_recovery_password
from mounting_bitlocker.cli import main

_IT = 200   # fast key-stretch for tests; production default is 0x100000


def test_recovery_password_decode():
    b = parse_recovery_password(S.RECOVERY_PASSWORD)
    assert len(b) == 16
    with pytest.raises(Exception):
        parse_recovery_password("000001-000002-000003-000004-000005-"
                                "000006-000007-000008")   # not /11


def test_parse_fve():
    blob, _vmk, _fvek = S.build_fve()
    fve = parse(blob)
    assert fve.volume_guid == str(S.VOL_GUID)
    assert fve.method == "aes-256-xts"
    assert len(fve.protectors) == 1
    assert fve.protectors[0].protector_type == "recovery password"
    assert fve.fvek_wrapped


def test_unlock_roundtrip():
    blob, vmk, fvek = S.build_fve()
    fve = parse(blob)
    u = unlock_with_recovery_password(fve, S.RECOVERY_PASSWORD,
                                      iterations=_IT)
    assert u.vmk == vmk
    assert u.fvek == fvek
    assert len(u.key1) == 32 and len(u.key2) == 32


def test_wrong_password_rejected():
    blob, _vmk, _fvek = S.build_fve()
    fve = parse(blob)
    wrong = "-".join(f"{(n * 11):06d}" for n in (9, 10, 11, 12, 13, 14, 15,
                                                 16))
    with pytest.raises(UnlockError):
        unlock_with_recovery_password(fve, wrong, iterations=_IT)


def test_tampered_vmk_rejected():
    blob, _vmk, _fvek = S.build_fve(tamper_vmk_tag=True)
    fve = parse(blob)
    with pytest.raises(UnlockError):
        unlock_with_recovery_password(fve, S.RECOVERY_PASSWORD,
                                      iterations=_IT)


def test_sector_decrypt(tmp_path):
    blob, vmk, fvek = S.build_fve()
    img_bytes, data_off = S.build_volume_image(blob, fvek, n_sectors=3)
    p = tmp_path / "vol.img"
    p.write_bytes(img_bytes)

    fve = parse(blob)
    u = unlock_with_recovery_password(fve, S.RECOVERY_PASSWORD,
                                      iterations=_IT)
    plain = decrypt_range(u, str(p), data_off, 512 * 3)
    assert plain[:20] == b"sector 0 plaintext d"
    assert plain[512:512 + 20] == b"sector 1 plaintext d"


def test_cli(tmp_path):
    blob, vmk, fvek = S.build_fve()
    img_bytes, data_off = S.build_volume_image(blob, fvek, n_sectors=2)
    p = tmp_path / "vol.img"
    p.write_bytes(img_bytes)

    rc = main(["info", str(p)])
    assert rc == 0

    js = tmp_path / "u.json"
    rc = main(["unlock", str(p), "--recovery-password", S.RECOVERY_PASSWORD,
               "--iterations", str(_IT), "--json", str(js)])
    assert rc == 0
    info = json.loads(js.read_text())
    assert info["fvek_hex"] == fvek.hex()

    out = tmp_path / "plain.bin"
    rc = main(["decrypt", str(p), "--recovery-password", S.RECOVERY_PASSWORD,
               "--iterations", str(_IT), "--data-offset", str(data_off),
               "--length", "1024", "-o", str(out)])
    assert rc == 0
    assert out.read_bytes()[:8] == b"sector 0"

    rc = main(["unlock", str(p), "--recovery-password",
               "000099-000099-000099-000099-000099-000099-000099-000099",
               "--iterations", str(_IT)])
    assert rc == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
