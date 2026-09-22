"""Generic printable-string carving, filtered to a light "looks
command-line-shaped" heuristic. Not tied to any specific process."""

from __future__ import annotations

import string

_PRINTABLE = set(string.printable) - set("\x0b\x0c")
_MIN_LEN, _MAX_LEN = 4, 260


def _looks_utf16(data: bytes) -> bool:
    if not data:
        return False
    return (data.count(0) / len(data)) > 0.2


def _looks_command_like(s: str) -> bool:
    if not (_MIN_LEN <= len(s) <= _MAX_LEN):
        return False
    if not (s[0].isalpha() or s[0] in "\\/.$%"):
        return False
    return (" " in s and any(c.isalpha() for c in s)) and \
        ("\\" in s or "/" in s or "-" in s or ".exe" in s.lower())


def _raw_strings(data: bytes, encodings) -> list[str]:
    out = []
    for enc in encodings:
        step = 1 if enc == "ascii" else 2
        current = []
        i = 0
        while i + step <= len(data):
            if enc == "ascii":
                ch = chr(data[i]) if data[i] < 128 else None
            else:
                unit = int.from_bytes(data[i:i + 2], "little")
                ch = chr(unit) if 0x20 <= unit < 0xD800 else \
                    ("\t" if unit in (9, 10, 13) else None)
            if ch is not None and (ch in _PRINTABLE or ch.isprintable()):
                current.append(ch)
            else:
                if len(current) >= _MIN_LEN:
                    out.append("".join(current))
                current = []
            i += step
        if len(current) >= _MIN_LEN:
            out.append("".join(current))
    return out


def carve_command_like(data: bytes) -> list[str]:
    encodings = ("ascii", "utf-16-le") if _looks_utf16(data) else ("ascii",)
    return [s for s in _raw_strings(data, encodings) if
           _looks_command_like(s)]
