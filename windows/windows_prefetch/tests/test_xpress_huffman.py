import os
import random

import pytest

from windows_prefetch.xpress_huffman import decompress

_win = pytest.importorskip if os.name != "nt" else None
pytestmark = pytest.mark.skipif(
    os.name != "nt", reason="round-trip check needs Windows ntdll RTL compression"
)


def _compress(data: bytes, maximum: bool = False) -> bytes:
    import ctypes

    ntdll = ctypes.WinDLL("ntdll")
    fmt = ctypes.c_ushort(0x0004 | (0x0100 if maximum else 0))
    ws = ctypes.c_ulong(0)
    frag = ctypes.c_ulong(0)
    ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(ws), ctypes.byref(frag))
    out = ctypes.create_string_buffer(len(data) + 8192)
    final = ctypes.c_ulong(0)
    wsb = ctypes.create_string_buffer(ws.value)
    st = ntdll.RtlCompressBuffer(
        fmt, data, ctypes.c_ulong(len(data)), out, ctypes.c_ulong(len(out)),
        ctypes.c_ulong(4096), ctypes.byref(final), wsb,
    )
    assert st == 0, hex(st)
    return out.raw[:final.value]


_NAMED = {
    "single-byte": b"A",
    "text-repeat": b"the quick brown fox jumps over the lazy dog " * 40,
    "abc-repeat": b"ABCABCABC" * 5000,
    "zeros": b"\x00" * 20000,
    "byte-ramp": bytes(range(256)) * 30,
}


@pytest.mark.parametrize("name", list(_NAMED))
def test_named_roundtrips(name):
    raw = _NAMED[name]
    assert decompress(_compress(raw), len(raw)) == raw


def test_random_incompressible():
    raw = random.Random(1).randbytes(9000)
    assert decompress(_compress(raw), len(raw)) == raw


def test_multichunk_realistic():
    rnd = random.Random(7)
    parts = []
    for _ in range(400):
        parts.append(b"\\VOLUME{01}\\WINDOWS\\SYSTEM32\\")
        parts.append(bytes(rnd.choices(range(65, 91), k=rnd.randint(4, 18))))
        parts.append(b".DLL\x00\x00")
    raw = (b"".join(parts) + rnd.randbytes(20000))
    raw = (raw * 3)[:180000]
    assert decompress(_compress(raw), len(raw)) == raw


def test_fuzz_against_ntdll():
    fails = 0
    for seed in range(150):
        rnd = random.Random(seed)
        n = rnd.randint(1, 90000)
        parts = []
        for _ in range(rnd.randint(1, 6)):
            r = rnd.random()
            if r < 0.4:
                parts.append(rnd.randbytes(rnd.randint(1, 3000)))
            elif r < 0.7:
                parts.append(bytes([rnd.randint(0, 255)]) * rnd.randint(1, 4000))
            else:
                parts.append((b"tok%d " % rnd.randint(0, 20)) * rnd.randint(1, 500))
        raw = b"".join(parts)[:n] or b"x"
        try:
            if decompress(_compress(raw), len(raw)) != raw:
                fails += 1
        except Exception:
            fails += 1
    assert fails == 0
