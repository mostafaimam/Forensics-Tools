"""Build a synthetic legacy qmgr.dat byte stream for the carver tests."""

from __future__ import annotations

import struct
import uuid
from datetime import datetime, timezone

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _ft(dt):
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


def _w(s: str) -> bytes:
    b = s.encode("utf-16-le")
    return struct.pack("<I", len(s)) + b


def _job(*, jtype, state, name, desc, jid):
    return (struct.pack("<III", jtype, 1, state) + jid.bytes_le
            + _w(name) + _w(desc))


def _file(dest, url, tmp, dsize, tsize, ct, mt):
    return (_w(dest) + _w(url) + _w(tmp)
            + struct.pack("<QQ", dsize, tsize)
            + struct.pack("<QQ", _ft(ct), _ft(mt)))


def build_qmgr() -> bytes:
    pad = b"\x2b" * 400          # 0x2b == '+', harmless filler
    ct = datetime(2026, 3, 16, 9, 0, 0, tzinfo=timezone.utc)
    mt = datetime(2026, 3, 16, 9, 5, 0, tzinfo=timezone.utc)

    out = bytearray(pad)

    # --- job 1: service-owned download of an EXE from a raw IP ---
    out += _job(jtype=0, state=6, name="WindowsUpdate",
                desc="update package", jid=uuid.UUID(
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    out += pad
    out += _w("S-1-5-18")
    out += pad
    out += _file("C:\\Windows\\System32\\wu.exe",
                 "http://185.220.101.5/payload.exe",
                 "C:\\Windows\\Temp\\BITA1B2.tmp",
                 45056, 45056, ct, mt)
    out += pad * 4

    # --- job 2: user-owned upload to a suspicious TLD ---
    out += _job(jtype=1, state=2, name="backup-sync",
                desc="", jid=uuid.UUID(
                    "11111111-2222-3333-4444-555555555555"))
    out += pad
    out += _w("S-1-5-21-1111111111-2222222222-3333333333-1104")
    out += pad
    out += _file("C:\\Users\\victim\\Documents\\clients.7z",
                 "https://exfil.ooufhwef.top/upload",
                 "C:\\Users\\victim\\AppData\\Local\\Temp\\BITC3D4.tmp",
                 0xFFFFFFFFFFFFFFFF, 1048576, ct, mt)
    out += pad * 4

    # --- job 3: benign https download to Downloads ---
    out += _job(jtype=0, state=6, name="Firefox Update",
                desc="", jid=uuid.UUID(
                    "99999999-8888-7777-6666-555555555555"))
    out += pad
    out += _w("S-1-5-21-1111111111-2222222222-3333333333-1104")
    out += pad
    out += _file("C:\\Users\\victim\\Downloads\\firefox.msi",
                 "https://download-installer.cdn.mozilla.net/pub/firefox.msi",
                 "C:\\Users\\victim\\Downloads\\BITE5F6.tmp",
                 78643200, 78643200, ct, mt)
    out += pad * 2
    return bytes(out)
