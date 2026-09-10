"""Decode base64 / compressed PowerShell payloads found in a script."""

from __future__ import annotations

import base64
import binascii
import gzip
import re
import zlib

_ENC = re.compile(
    r"(?:-e(?:nc(?:odedcommand)?)?)\s+([A-Za-z0-9+/=]{16,})", re.I)
_B64_CALL = re.compile(
    r"FromBase64String\(\s*['\"]([A-Za-z0-9+/=\s]{16,})['\"]\s*\)", re.I)
_B64_LITERAL = re.compile(r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]")


def _b64(s: str) -> bytes | None:
    s = re.sub(r"\s+", "", s)
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad, validate=False)
    except (binascii.Error, ValueError):
        return None


def _maybe_inflate(raw: bytes) -> bytes:
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except OSError:
            pass
    for wbits in (-15, 15, 31):
        try:
            return zlib.decompress(raw, wbits)
        except zlib.error:
            continue
    return raw


def _as_text(raw: bytes) -> str:
    if len(raw) >= 2 and raw[1] == 0 and raw[0] != 0:
        return raw.decode("utf-16-le", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def decode_payloads(text: str, *, max_depth: int = 3) -> tuple[str, list[str]]:
    """Return (fully_expanded_text, [notes]).

    Any -EncodedCommand / FromBase64String / literal-looking base64 blob is
    decoded (and inflated) in place, recursively.
    """
    notes: list[str] = []
    seen: set[str] = set()

    def expand(s: str, depth: int) -> str:
        if depth > max_depth or s in seen:
            return s
        seen.add(s)
        changed = False

        def sub_enc(m):
            nonlocal changed
            raw = _b64(m.group(1))
            if raw is None or len(raw) < 4:
                return m.group(0)
            dec = _as_text(_maybe_inflate(raw))
            if not dec.strip() or not dec.isprintable() and "\n" not in dec:
                return m.group(0)
            changed = True
            notes.append("decoded a -EncodedCommand payload")
            return "\n<<< -EncodedCommand decoded >>>\n" + dec

        s2 = _ENC.sub(sub_enc, s)

        def sub_call(m):
            nonlocal changed
            raw = _b64(m.group(1))
            if raw is None or len(raw) < 4:
                return m.group(0)
            infl = _maybe_inflate(raw)
            dec = _as_text(infl)
            if not any(c.isalnum() for c in dec):
                return m.group(0)
            changed = True
            notes.append("decoded a FromBase64String blob"
                         + (" (compressed)" if infl is not raw else ""))
            return m.group(0) + "\n<<< FromBase64String decoded >>>\n" + dec

        s2 = _B64_CALL.sub(sub_call, s2)

        if changed:
            return expand(s2, depth + 1)
        return s2

    out = expand(text, 0)
    # de-dupe notes, keep order
    seen_n: set = set()
    notes = [n for n in notes if not (n in seen_n or seen_n.add(n))]
    return out, notes
