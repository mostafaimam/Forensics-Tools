"""Tokeniser: text -> (token, position) stream, and varint position blobs."""

from __future__ import annotations

import re
from bisect import bisect_left

_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_GLUED_RE = re.compile(r"\S{2,}")
_PLAIN_RE = re.compile(r"[^\W_]+\Z", re.UNICODE)
MAX_TOKEN = 64
MAX_GLUED = 128


def tokens(text: str):
    """Yield (lowercased word token, 0-based position, char offset)."""
    pos = 0
    for m in _TOKEN_RE.finditer(text):
        tok = m.group(0).lower()
        if len(tok) > MAX_TOKEN:
            tok = tok[:MAX_TOKEN]
        yield tok, pos, m.start()
        pos += 1


def index_tokens(text: str):
    """Word tokens plus 'glued' runs (emails, IPs, paths, identifiers).

    A glued run shares the position of the word token it starts with, so word
    positions stay contiguous and phrase matching is unaffected.
    """
    words = list(tokens(text))
    yield from words
    if not words:
        return
    offsets = [off for _, _, off in words]
    for m in _GLUED_RE.finditer(text):
        run = m.group(0)
        if run.endswith((".", ",", ";", ":", ")", "]", '"', "'")):
            run = run.rstrip(".,;:)]\"'")
        run = run.lower()
        if len(run) < 2 or _PLAIN_RE.match(run) or \
                not any(c.isalnum() for c in run):
            continue
        run = run[:MAX_GLUED]
        i = bisect_left(offsets, m.start())
        pos = words[i][1] if i < len(words) else words[-1][1]
        yield run, pos, m.start()


def query_terms(text: str) -> list[str]:
    return [m.group(0).lower()[:MAX_TOKEN] for m in _TOKEN_RE.finditer(text)]


# -- varint-delta position blobs ------------------------------------
def encode_positions(positions: list[int]) -> bytes:
    out = bytearray()
    prev = 0
    for p in positions:
        delta = p - prev
        prev = p
        while delta >= 0x80:
            out.append((delta & 0x7F) | 0x80)
            delta >>= 7
        out.append(delta)
    return bytes(out)


def decode_positions(blob: bytes) -> list[int]:
    out = []
    cur = 0
    shift = 0
    val = 0
    for b in blob:
        val |= (b & 0x7F) << shift
        if b & 0x80:
            shift += 7
        else:
            cur += val
            out.append(cur)
            val = 0
            shift = 0
    return out
