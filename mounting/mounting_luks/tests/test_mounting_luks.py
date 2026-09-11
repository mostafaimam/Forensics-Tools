from __future__ import annotations

import json

import pytest

import _synth as S

from mounting_luks.luks1 import LuksError, parse
from mounting_luks.unlock import UnlockError, unlock
from mounting_luks.sectors import decrypt_range
from mounting_luks.cli import main


def test_parse_header(tmp_path):
    img, mk, payload_off = S.build_volume()
    hdr = parse(img)
    assert hdr.uuid == "11111111-2222-3333-4444-555555555555"
    assert hdr.cipher_name == "aes"
    assert hdr.cipher_mode == "cbc-essiv:sha256"
    assert hdr.key_bytes == 32
    assert hdr.payload_byte_offset == payload_off
    active = [s for s in hdr.slots if s.active]
    assert len(active) == 1
    assert active[0].stripes == 64


def test_unlock_roundtrip(tmp_path):
    img, mk, _off = S.build_volume()
    p = tmp_path / "vol.img"
    p.write_bytes(img)
    hdr = parse(img)
    u = unlock(hdr, str(p), S.PASSPHRASE)
    assert u.master_key == mk
    assert u.slot_index == 0


def test_wrong_passphrase_rejected(tmp_path):
    img, _mk, _off = S.build_volume()
    p = tmp_path / "vol.img"
    p.write_bytes(img)
    hdr = parse(img)
    with pytest.raises(UnlockError):
        unlock(hdr, str(p), "not the passphrase")


def test_tampered_digest_rejected(tmp_path):
    img, _mk, _off = S.build_volume(tamper_digest=True)
    p = tmp_path / "vol.img"
    p.write_bytes(img)
    hdr = parse(img)
    with pytest.raises(UnlockError):
        unlock(hdr, str(p), S.PASSPHRASE)


def test_payload_decrypt(tmp_path):
    img, mk, payload_off = S.build_volume(payload_sectors=3)
    p = tmp_path / "vol.img"
    p.write_bytes(img)
    hdr = parse(img)
    plain = decrypt_range(hdr, mk, str(p), payload_off, 512 * 3)
    assert plain[:22] == b"payload sector 0 data "
    assert plain[512:512 + 22] == b"payload sector 1 data "


def test_luks2_detected(tmp_path):
    blob = bytearray(0x300)
    blob[0:6] = b"LUKS\xba\xbe"
    import struct
    struct.pack_into(">H", blob, 6, 2)
    p = tmp_path / "l2.img"
    p.write_bytes(bytes(blob))
    with pytest.raises(LuksError, match="LUKS2"):
        parse(bytes(blob))


def test_cli(tmp_path):
    img, mk, payload_off = S.build_volume(payload_sectors=2)
    p = tmp_path / "vol.img"
    p.write_bytes(img)

    rc = main(["info", str(p)])
    assert rc == 0

    js = tmp_path / "u.json"
    rc = main(["unlock", str(p), "--passphrase", S.PASSPHRASE,
               "--json", str(js)])
    assert rc == 0
    info = json.loads(js.read_text())
    assert info["master_key_hex"] == mk.hex()

    out = tmp_path / "plain.bin"
    rc = main(["decrypt", str(p), "--passphrase", S.PASSPHRASE,
               "--data-offset", str(payload_off), "--length", "1024",
               "-o", str(out)])
    assert rc == 0
    assert out.read_bytes()[:15] == b"payload sector "

    rc = main(["unlock", str(p), "--passphrase", "nope"])
    assert rc == 1


def test_csv_injection_guard():
    from mounting_luks.tracelib import sanitize
    assert sanitize("=1") == "'=1"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
