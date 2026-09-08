"""Mutation-fuzz the SNSS Pickle reader and the LZ4 / mozLz4 decoders."""

from __future__ import annotations

from browser_sessions import chromium, fuzzlib
from browser_sessions.lz4 import (Lz4Error, lz4_block_decompress,
                                  mozlz4_decompress)

import _synth as S


def test_fuzz_snss(tmp_path):
    seed = S.snss([
        {"tab_id": 1, "window": 3, "index": 0, "last_active":
         __import__("datetime").datetime(2026, 1, 1,
                                         tzinfo=__import__("datetime").timezone.utc),
         "entries": [("https://example.com/", "Example"),
                     ("https://example.com/2", "Two")]},
        {"tab_id": 2, "pinned": True, "closed": True,
         "entries": [("https://mail.example.com/", "Mail")]},
    ])
    fuzzlib.fuzz(chromium.parse, [seed], iterations=500, seed=4,
                 accepts="path", tmp_path=tmp_path)


def test_fuzz_lz4_block():
    good = S._lz4_literals(b"the quick brown fox jumps " * 8)
    fuzzlib.fuzz(lz4_block_decompress, [good], iterations=800, seed=5,
                 allowed=fuzzlib.DEFAULT_ALLOWED + (Lz4Error,))


def test_fuzz_mozlz4():
    obj = S.sessionstore_obj([S.win([S.tab([("https://x/", "X")])])])
    fuzzlib.fuzz(mozlz4_decompress, [S.mozlz4(obj)], iterations=500, seed=6,
                 allowed=fuzzlib.DEFAULT_ALLOWED + (Lz4Error,))
