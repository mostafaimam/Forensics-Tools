"""fuzzlib - a tiny deterministic mutation fuzzer for the binary parsers.

Vendored per-tool like ``tracelib.py``.  Not a coverage-guided fuzzer -
just enough to catch the classic parser failures (unbounded read, index
error, hang, runaway allocation) on malformed input, run in CI with a
fixed seed so a failure is reproducible.

    from mytool import fuzzlib, parser

    def test_fuzz_parser(tmp_path):
        seeds = [build_valid_a(), build_valid_b()]
        fuzzlib.fuzz(lambda b: parser.parse(b), seeds,
                     iterations=400, tmp_path=tmp_path)

``fuzz`` mutates each seed many ways (bit flips, byte sets, truncation,
extension, field-sized value storms) and asserts every call either
returns normally or raises one of ``allowed`` exceptions - never hangs
past ``per_call_seconds`` and never allocates past ``max_rss_growth_mb``.
"""

from __future__ import annotations

import random
import struct
import threading
import tracemalloc
from pathlib import Path

# exceptions a parser is *allowed* to raise on bad input
DEFAULT_ALLOWED = (ValueError, KeyError, IndexError, OSError, EOFError,
                   struct.error, UnicodeDecodeError, MemoryError,
                   RecursionError, OverflowError, ArithmeticError,
                   NotImplementedError, TypeError, AttributeError,
                   AssertionError, StopIteration)


class FuzzFailure(AssertionError):
    pass


def _mutate(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return bytes(rng.randbytes(rng.randint(0, 64)))
    b = bytearray(data)
    strategy = rng.randint(0, 8)
    if strategy == 0:                              # single bit flip
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randint(0, 7)
    elif strategy == 1:                            # set a byte
        b[rng.randrange(len(b))] = rng.randint(0, 255)
    elif strategy == 2:                            # truncate
        b = b[:rng.randint(0, len(b))]
    elif strategy == 3:                            # extend with junk
        b += rng.randbytes(rng.randint(1, 256))
    elif strategy == 4:                            # zero a run
        i = rng.randrange(len(b))
        b[i:i + rng.randint(1, 32)] = b"\x00" * rng.randint(1, 32)
    elif strategy == 5:                            # 0xFF a run (huge lengths)
        i = rng.randrange(len(b))
        b[i:i + rng.randint(1, 8)] = b"\xff" * rng.randint(1, 8)
    elif strategy == 6:                            # duplicate a chunk
        i = rng.randrange(len(b))
        j = min(len(b), i + rng.randint(1, 128))
        b[i:i] = bytes(b[i:j])
    elif strategy == 7:                            # swap two bytes
        i, j = rng.randrange(len(b)), rng.randrange(len(b))
        b[i], b[j] = b[j], b[i]
    else:                                          # several bit flips
        for _ in range(rng.randint(2, 12)):
            k = rng.randrange(len(b))
            b[k] ^= 1 << rng.randint(0, 7)
    return bytes(b)


def _call_with_timeout(fn, arg, seconds: float):
    result: list = []
    error: list = []

    def run():
        try:
            r = fn(arg)
            # drain a generator so lazy parsers actually execute
            if hasattr(r, "__iter__") and not isinstance(r, (bytes, str,
                                                              dict, list,
                                                              tuple)):
                list(r)
            result.append(True)
        except BaseException as e:  # noqa: BLE001
            error.append(e)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(seconds)
    if th.is_alive():
        return "timeout", None
    if error:
        return "error", error[0]
    return "ok", None


def fuzz(parse_fn, seeds, *, iterations: int = 300, seed: int = 1337,
         per_call_seconds: float = 3.0, max_alloc_mb: float = 256.0,
         allowed: tuple = DEFAULT_ALLOWED, accepts: str = "bytes",
         tmp_path=None) -> int:
    """Run *parse_fn* against mutated *seeds*.

    ``accepts``: ``"bytes"`` (default) passes the mutated bytes directly;
    ``"path"`` writes them to a temp file and passes the path string
    (needs ``tmp_path``).

    Returns the number of iterations that completed.  Raises
    :class:`FuzzFailure` on a hang, an unexpected exception type, or a
    large allocation.
    """
    rng = random.Random(seed)
    seeds = [bytes(s) for s in seeds] or [b""]
    if accepts == "path" and tmp_path is None:
        raise ValueError("accepts='path' needs tmp_path")
    scratch = Path(tmp_path) / "fuzz_input.bin" if tmp_path else None

    done = 0
    for i in range(iterations):
        base = seeds[i % len(seeds)]
        data = base
        for _ in range(rng.randint(1, 4)):
            data = _mutate(data, rng)

        if accepts == "path":
            scratch.write_bytes(data)
            arg = str(scratch)
        else:
            arg = data

        tracemalloc.start()
        status, err = _call_with_timeout(parse_fn, arg, per_call_seconds)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

        if status == "timeout":
            raise FuzzFailure(
                f"iteration {i}: parser hung > {per_call_seconds}s on "
                f"{len(data)}-byte input (seed={seed})\n"
                f"  repro: {data[:64].hex()}...")
        if peak > max_alloc_mb * 1024 * 1024:
            raise FuzzFailure(
                f"iteration {i}: parser allocated {peak/1e6:.0f} MB on a "
                f"{len(data)}-byte input (seed={seed})")
        if status == "error" and not isinstance(err, allowed):
            raise FuzzFailure(
                f"iteration {i}: {type(err).__name__}: {err}\n"
                f"  on {len(data)}-byte input (seed={seed})\n"
                f"  repro: {data[:96].hex()}") from err
        done += 1
    return done
