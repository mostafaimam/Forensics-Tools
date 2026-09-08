from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fuzzlib


def _good_parser(data: bytes):
    if len(data) < 4:
        raise ValueError("too short")
    n = struct.unpack_from(">H", data, 0)[0]
    n = min(n, len(data) - 2)               # bounded - never over-reads
    return data[2:2 + n]


def test_fuzz_passes_a_well_behaved_parser(tmp_path):
    seeds = [struct.pack(">H", 3) + b"abc", struct.pack(">H", 0)]
    done = fuzzlib.fuzz(_good_parser, seeds, iterations=200, seed=1)
    assert done == 200


def test_fuzz_catches_unexpected_exception():
    def buggy(data: bytes):
        return data.decode("ascii")        # UnicodeDecodeError is allowed...
    # ...so make it raise something that is NOT allowed
    def worse(data: bytes):
        raise RuntimeError("boom")
    with pytest.raises(fuzzlib.FuzzFailure):
        fuzzlib.fuzz(worse, [b"seed"], iterations=5, seed=1)


def test_fuzz_catches_a_hang():
    def hangs(data: bytes):
        if len(data) != 4:                  # only hang on some inputs
            return None
        time.sleep(5)
    with pytest.raises(fuzzlib.FuzzFailure):
        fuzzlib.fuzz(hangs, [b"1234"], iterations=50, seed=1,
                     per_call_seconds=0.3)


def test_fuzz_catches_runaway_allocation():
    def greedy(data: bytes):
        if len(data) >= 2:
            return b"\x00" * (400 * 1024 * 1024)
    with pytest.raises(fuzzlib.FuzzFailure):
        fuzzlib.fuzz(greedy, [b"abcd"], iterations=10, seed=1,
                     max_alloc_mb=64)


def test_fuzz_path_mode(tmp_path):
    def parse_path(p):
        return Path(p).read_bytes()[:8]
    done = fuzzlib.fuzz(parse_path, [b"hello world"], iterations=30, seed=2,
                        accepts="path", tmp_path=tmp_path)
    assert done == 30


def test_fuzz_drains_generators():
    calls = []

    def gen_parser(data: bytes):
        def g():
            calls.append(1)
            if len(data) == 7:
                raise RuntimeError("only reached when the generator runs")
            yield 1
        return g()
    with pytest.raises(fuzzlib.FuzzFailure):
        fuzzlib.fuzz(gen_parser, [b"1234567"], iterations=20, seed=1)
    assert calls                             # generator actually executed


def test_deterministic():
    log1, log2 = [], []
    fuzzlib.fuzz(lambda b: log1.append(bytes(b)), [b"abc"], iterations=40,
                 seed=99)
    fuzzlib.fuzz(lambda b: log2.append(bytes(b)), [b"abc"], iterations=40,
                 seed=99)
    assert log1 == log2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
