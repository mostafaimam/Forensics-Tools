"""The LUKS anti-forensic information splitter (AFsplit / AFmerge, af_sha1).

Diffuses key material across `stripes` blocks so that a single stripe on
disk carries no usable fraction of the key - recovering it requires every
stripe.  ``af_merge`` is the read path (rebuild the key from the on-disk
striped material); ``af_split`` is its exact inverse, used only to build
test fixtures.
"""

from __future__ import annotations

import hashlib
import os
import struct

_DIGEST = 20   # SHA-1


def _af_hash(data: bytes, out_len: int) -> bytes:
    full, rem = divmod(out_len, _DIGEST)
    out = bytearray()
    for i in range(full):
        chunk = data[i * _DIGEST:(i + 1) * _DIGEST]
        out += hashlib.sha1(struct.pack(">I", i) + chunk).digest()
    if rem:
        chunk = data[full * _DIGEST:full * _DIGEST + rem]
        out += hashlib.sha1(struct.pack(">I", full) + chunk.ljust(
            rem, b"\x00")).digest()[:rem]
    return bytes(out)


def af_merge(split_data: bytes, stripes: int, block_size: int) -> bytes:
    if len(split_data) != stripes * block_size:
        raise ValueError("split_data length does not match stripes*"
                         "block_size")
    d = bytes(block_size)
    for i in range(stripes):
        chunk = split_data[i * block_size:(i + 1) * block_size]
        d = bytes(a ^ b for a, b in zip(d, chunk))
        if i < stripes - 1:
            d = _af_hash(d, block_size)
    return d


def af_split(key: bytes, stripes: int) -> bytes:
    """Inverse of af_merge - random stripes, with the last stripe chosen
    so merging reproduces `key`. Used only by the test fixtures."""
    block_size = len(key)
    out = bytearray()
    d = bytes(block_size)
    for i in range(stripes - 1):
        stripe = os.urandom(block_size)
        out += stripe
        d = bytes(a ^ b for a, b in zip(d, stripe))
        d = _af_hash(d, block_size)
    last = bytes(a ^ b for a, b in zip(d, key))
    out += last
    return bytes(out)
