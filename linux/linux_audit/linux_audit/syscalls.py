"""Minimal syscall-number -> name tables for the common architectures.

Only the syscalls that matter for a review are listed; anything else is
rendered as ``syscall=<n>``.  ``arch=`` in an audit record is a hex AUDIT
arch token (e.g. ``c000003e`` = x86_64).
"""

from __future__ import annotations

_ARCH = {
    "c000003e": "x86_64",
    "40000003": "i386",
    "c00000b7": "aarch64",
    "40000028": "arm",
    "c0000015": "ppc64le",
}

# x86_64
_X86_64 = {
    0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap", 10: "mprotect",
    41: "socket", 42: "connect", 43: "accept", 49: "bind", 50: "listen",
    56: "clone", 57: "fork", 58: "vfork", 59: "execve", 62: "kill",
    82: "rename", 83: "mkdir", 84: "rmdir", 87: "unlink", 88: "symlink",
    90: "chmod", 91: "fchmod", 92: "chown", 101: "ptrace", 105: "setuid",
    106: "setgid", 113: "setreuid", 133: "mknod", 165: "mount", 166: "umount2",
    175: "init_module", 176: "delete_module", 260: "fchownat", 261: "futimesat",
    263: "unlinkat", 265: "linkat", 267: "readlinkat", 268: "fchmodat",
    322: "execveat", 313: "finit_module", 101 + 0: "ptrace",
}
# aarch64
_AARCH64 = {
    56: "openat", 57: "close", 63: "read", 64: "write", 122: "sched_setaffinity",
    198: "socket", 203: "connect", 200: "bind", 201: "listen", 202: "accept",
    220: "clone", 221: "execve", 129: "kill", 34: "mkdirat", 35: "unlinkat",
    36: "symlinkat", 37: "linkat", 38: "renameat", 53: "fchmodat",
    54: "fchownat", 226: "mprotect", 105: "init_module", 106: "delete_module",
    273: "finit_module", 281: "execveat", 117: "ptrace",
}
_I386 = {
    1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 11: "execve",
    102: "socketcall", 120: "clone", 358: "execveat", 26: "ptrace",
}

_TABLES = {"x86_64": _X86_64, "aarch64": _AARCH64, "arm": _AARCH64,
           "i386": _I386, "ppc64le": _X86_64}


def arch_name(token: str) -> str:
    return _ARCH.get((token or "").lower(), token or "")


def syscall_name(arch_token: str, number) -> str:
    try:
        n = int(number)
    except (TypeError, ValueError):
        return str(number)
    arch = arch_name(arch_token)
    return _TABLES.get(arch, _X86_64).get(n, f"syscall#{n}")
