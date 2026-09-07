"""Classify a private executable region from its first bytes."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

# byte patterns that commonly start injected code / shellcode
_PROLOGUES = (
    b"\x55\x8b\xec",              # push ebp; mov ebp, esp        (x86)
    b"\x55\x89\xe5",              # push ebp; mov ebp, esp  (gcc x86)
    b"\x48\x89\x5c\x24",          # mov [rsp+x], rbx              (x64)
    b"\x48\x83\xec",              # sub rsp, imm8                 (x64)
    b"\x40\x53",                  # push rbx (rex)                (x64)
    b"\x4c\x8b\xdc",              # mov r11, rsp                  (x64)
    b"\xfc\x48\x83\xe4\xf0",      # cld; and rsp, -16    (MSF x64 stager)
    b"\xfc\xe8",                  # cld; call ...        (MSF x86 stager)
    b"\xe8\x00\x00\x00\x00",      # call $+5  (get EIP/RIP)
    b"\x60\x9c",                  # pushad; pushfd
    b"\xeb",                      # short jmp at byte 0
    b"\x90\x90\x90\x90",          # nop sled
)


@dataclass
class Finding:
    verdict: str                 # pe | shellcode | unbacked-exec | rwx-data
    detail: str
    entropy: float
    first_bytes: bytes
    hexdump: str
    zeroed: bool


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def hexdump(data: bytes, base: int = 0, rows: int = 4) -> str:
    out = []
    for r in range(rows):
        chunk = data[r * 16:r * 16 + 16]
        if not chunk:
            break
        hexs = " ".join(f"{x:02x}" for x in chunk).ljust(47)
        ascii_ = "".join(chr(x) if 0x20 <= x < 0x7f else "." for x in chunk)
        out.append(f"{base + r * 16:#010x}  {hexs}  {ascii_}")
    return "\n".join(out)


def _looks_pe(head: bytes) -> tuple[bool, str]:
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False, ""
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if 0x40 <= e_lfanew <= 0x400 and head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
        machine = struct.unpack_from("<H", head, e_lfanew + 4)[0]
        arch = {0x8664: "x64", 0x14c: "x86", 0xaa64: "arm64"}.get(
            machine, f"machine 0x{machine:x}")
        return True, f"PE header present ({arch})"
    return True, "MZ magic without a valid PE header (hollowed / corrupt)"


def classify(region_head: bytes, base: int, protection_name: str) -> Finding:
    head = region_head or b""
    ent = shannon(head[:0x400])
    zeroed = not any(head[:0x40])
    dump = hexdump(head, base)

    is_pe, why = _looks_pe(head)
    if is_pe:
        return Finding("pe", why, ent, head[:16], dump, zeroed)

    if zeroed:
        return Finding("unbacked-exec",
                       "executable region, header not paged in",
                       ent, head[:16], dump, True)

    hits = [p for p in _PROLOGUES if head[:64].find(p) != -1
            and (head[:1] == p[:1] or p in head[:16])]
    if hits or (0.5 < ent < 6.5 and any(head[:16])):
        note = ("code-like prologue bytes at region start"
                if hits else "executable, non-PE, moderate entropy")
        return Finding("shellcode", note, ent, head[:16], dump, False)

    if protection_name == "EXECUTE_READWRITE" and ent >= 7.0:
        return Finding("rwx-data",
                       "RWX region, high-entropy (packed / encrypted payload?)",
                       ent, head[:16], dump, False)

    return Finding("unbacked-exec", "private executable region",
                   ent, head[:16], dump, False)
