"""memory_yara - scan a memory image with YARA-style rules.

A bundled, from-scratch matcher for a practical subset of the YARA rule
language: text and hex-byte string patterns (with the common
modifiers and hex wildcards/jump ranges), a small regex-string form,
and boolean/counting conditions (``and``/``or``/``not``, ``N of
(...)``, ``any of them``, ``#id`` counts, ``filesize``). This is not
full YARA compatibility - see the README for exactly which parts of the
grammar are and are not supported - but it needs no `yara-python` and
no network access to a signature service.

v0.1 scans the image's raw **physical** memory only; resolving a hit to
the owning process or kernel module (mentioned in the original spec
stub) is deferred - see the README.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
