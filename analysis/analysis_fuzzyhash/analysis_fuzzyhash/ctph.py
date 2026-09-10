"""Context-triggered piecewise hashing (the ssdeep construction)."""

from __future__ import annotations

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_MIN_BLOCKSIZE = 3
_SPAMSUM_LENGTH = 64
_HASH_INIT = 0x28021967
_HASH_PRIME = 0x01000193
_ROLL_WINDOW = 7


class _Roll:
    __slots__ = ("win", "h1", "h2", "h3", "n")

    def __init__(self):
        self.win = bytearray(_ROLL_WINDOW)
        self.h1 = self.h2 = self.h3 = 0
        self.n = 0

    def update(self, b: int) -> int:
        i = self.n % _ROLL_WINDOW
        self.h2 = (self.h2 - self.h1 + _ROLL_WINDOW * b) & 0xFFFFFFFF
        self.h1 = (self.h1 + b - self.win[i]) & 0xFFFFFFFF
        self.win[i] = b
        self.n += 1
        self.h3 = ((self.h3 << 5) & 0xFFFFFFFF) ^ b
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF


def _fnv(h: int, b: int) -> int:
    return ((h * _HASH_PRIME) & 0xFFFFFFFF) ^ b


def _guess_blocksize(n: int) -> int:
    bs = _MIN_BLOCKSIZE
    while bs * _SPAMSUM_LENGTH < n:
        bs *= 2
    return bs


def hash_bytes(data: bytes) -> str:
    n = len(data)
    if n == 0:
        return "3::"
    bs = _guess_blocksize(n)
    while True:
        sig1, sig2 = _digest(data, bs)
        if bs <= _MIN_BLOCKSIZE or len(sig1) >= _SPAMSUM_LENGTH // 2:
            return f"{bs}:{sig1}:{sig2}"
        bs = max(bs // 2, _MIN_BLOCKSIZE)


def _digest(data: bytes, bs: int) -> tuple[str, str]:
    roll = _Roll()
    h1 = h2 = _HASH_INIT
    out1: list[str] = []
    out2: list[str] = []
    for b in data:
        h1 = _fnv(h1, b)
        h2 = _fnv(h2, b)
        r = roll.update(b)
        if r % bs == bs - 1:
            out1.append(_B64[h1 % 64])
            h1 = _HASH_INIT
        if r % (bs * 2) == (bs * 2) - 1:
            out2.append(_B64[h2 % 64])
            h2 = _HASH_INIT
    out1.append(_B64[h1 % 64])
    out2.append(_B64[h2 % 64])
    return "".join(out1[:_SPAMSUM_LENGTH]), "".join(out2[:_SPAMSUM_LENGTH // 2])


# -- comparison --------------------------------------------------------

def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * lb
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != cb))
        prev = cur
    return prev[lb]


def _score_strings(s1: str, s2: str, bs: int) -> int:
    if s1 == s2:
        return 100 if len(s1) > 0 else 0
    d = _edit_distance(s1, s2)
    d = d * _SPAMSUM_LENGTH // (len(s1) + len(s2)) if (s1 or s2) else 0
    d = 100 * d // _SPAMSUM_LENGTH
    score = 100 - d
    # cap tiny-block matches the way ssdeep does
    cap = bs // _MIN_BLOCKSIZE * min(len(s1), len(s2))
    return max(0, min(score, cap if cap else score))


def compare(h1: str, h2: str) -> int:
    """Return a 0-100 similarity score between two CTPH digests."""
    try:
        b1, a1, c1 = h1.split(":")
        b2, a2, c2 = h2.split(":")
        bs1, bs2 = int(b1), int(b2)
    except ValueError:
        return 0
    if bs1 == bs2:
        return _score_strings(a1, a2, bs1)
    if bs1 == bs2 * 2:
        return _score_strings(c1, a2, bs2)
    if bs2 == bs1 * 2:
        return _score_strings(a1, c2, bs1)
    return 0
