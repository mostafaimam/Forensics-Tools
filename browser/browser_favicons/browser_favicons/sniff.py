"""Guess an image extension from its magic bytes."""

from __future__ import annotations


def ext_for(data: bytes) -> str:
    if not data:
        return ".bin"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\x00\x00\x01\x00"):
        return ".ico"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"BM"):
        return ".bmp"
    head = data[:256].lstrip()
    if head.startswith((b"<?xml", b"<svg")):
        return ".svg"
    return ".bin"
