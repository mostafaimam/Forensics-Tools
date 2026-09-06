from __future__ import annotations

import hashlib
from typing import Iterable

SUPPORTED = ("md5", "sha1", "sha256")


class MultiHasher:
    """Feed bytes once, get several digests out."""

    def __init__(self, algorithms: Iterable[str]) -> None:
        algs = [a.lower() for a in algorithms]
        bad = [a for a in algs if a not in SUPPORTED]
        if bad:
            raise ValueError(f"unsupported hash algorithm(s): {bad}")
        self._h = {a: hashlib.new(a) for a in algs}

    def update(self, data: bytes) -> None:
        for h in self._h.values():
            h.update(data)

    def hexdigests(self) -> dict[str, str]:
        return {a: h.hexdigest() for a, h in self._h.items()}
