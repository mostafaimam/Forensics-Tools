r"""Path helpers: Windows long-path support, forensic variable expansion.

Design notes / pain points addressed here:

* Windows MAX_PATH (260 chars): many collectors silently fail on deep paths.
  We normalise every absolute Windows path to the ``\\?\`` extended-length
  form before touching the filesystem.
* Path variables: ``%SystemDrive%``-style tokens are resolved from the
  *running* system (or from an explicitly supplied source root when collecting
  from a mounted image), never hard-coded to ``C:``.
* User-profile fan-out: ``%UserProfiles%`` / ``%Home%`` expand to every real
  user profile so per-user artefacts are collected for all accounts.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

_VAR_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")


def current_os() -> str:
    if IS_WINDOWS:
        return "windows"
    if IS_MAC:
        return "macos"
    if IS_LINUX:
        return "linux"
    return "unknown"


def long_path(p: str | os.PathLike[str]) -> str:
    r"""Return a filesystem-safe string for *p*.

    On Windows this prepends the ``\\?\`` (or ``\\?\UNC\``) prefix for absolute
    paths so the Win32 API skips MAX_PATH normalisation. On POSIX it is a no-op.
    """
    s = os.fspath(p)
    if not IS_WINDOWS:
        return s
    if s.startswith("\\\\?\\") or s.startswith("\\??\\"):
        return s
    # Only extended-length-prefix fully-qualified paths.
    if s.startswith("\\\\"):  # UNC \\server\share
        return "\\\\?\\UNC\\" + s[2:]
    drive, tail = os.path.splitdrive(s)
    if drive and (tail.startswith("\\") or tail.startswith("/")):
        return "\\\\?\\" + os.path.normpath(s)
    return s


def strip_long_prefix(p: str) -> str:
    for pref in ("\\\\?\\UNC\\", "\\\\?\\"):
        if p.startswith(pref):
            rest = p[len(pref):]
            return ("\\\\" + rest) if pref.endswith("UNC\\") else rest
    return p


@dataclass(frozen=True)
class HostContext:
    """Resolved system locations used to expand target variables.

    When *source_root* is set (collecting from a mounted image / another volume)
    all variables are re-based under it.
    """

    system_drive: str
    system_root: str
    program_data: str
    users_dir: str
    user_profiles: tuple[str, ...]
    source_root: str | None = None

    @property
    def variables(self) -> dict[str, str]:
        return {
            "systemdrive": self.system_drive,
            "systemroot": self.system_root,
            "windir": self.system_root,
            "programdata": self.program_data,
            "allusersprofile": self.program_data,
            "users": self.users_dir,
        }


def _rebase(path: str, source_root: str | None) -> str:
    """Re-root *path* under *source_root*. Idempotent: a path already inside
    *source_root* is returned unchanged."""
    if not source_root:
        return path
    npath = os.path.normpath(path)
    nroot = os.path.normpath(source_root)
    if npath == nroot or npath.startswith(nroot + os.sep):
        return path
    drive, tail = os.path.splitdrive(npath)
    tail = tail.lstrip("\\/")
    return os.path.join(source_root, tail)


def detect_host_context(source_root: str | None = None) -> HostContext:
    """Discover system locations. *source_root* points at a mounted image root."""
    if IS_WINDOWS:
        sys_drive = os.environ.get("SystemDrive", "C:") + "\\"
        sys_root = os.environ.get("SystemRoot", sys_drive + "Windows")
        program_data = os.environ.get("ProgramData", sys_drive + "ProgramData")
        users_dir = os.path.join(sys_drive, "Users")
    elif IS_MAC:
        sys_drive = "/"
        sys_root = "/System"
        program_data = "/Library"
        users_dir = "/Users"
    else:
        sys_drive = "/"
        sys_root = "/etc"
        program_data = "/var"
        users_dir = "/home"

    sys_drive = _rebase(sys_drive, source_root)
    sys_root = _rebase(sys_root, source_root)
    program_data = _rebase(program_data, source_root)
    users_dir = _rebase(users_dir, source_root)

    profiles: list[str] = []
    skip = {
        "windows": {"public", "default", "default user", "all users",
                    "defaultappdata"},
        "macos": {"shared"},
        "linux": set(),
    }[current_os()]
    try:
        with os.scandir(long_path(users_dir)) as it:
            for entry in it:
                if entry.name.lower() in skip:
                    continue
                try:
                    if entry.is_dir(follow_symlinks=False):
                        profiles.append(strip_long_prefix(entry.path))
                except OSError:
                    continue
    except OSError:
        pass

    if current_os() == "linux":
        root_home = _rebase("/root", source_root)
        if os.path.isdir(long_path(root_home)) and root_home not in profiles:
            profiles.append(root_home)

    return HostContext(
        system_drive=sys_drive,
        system_root=sys_root,
        program_data=program_data,
        users_dir=users_dir,
        user_profiles=tuple(sorted(profiles)),
        source_root=source_root,
    )


class UnknownVariableError(ValueError):
    pass


def expand_path(raw: str, ctx: HostContext) -> list[str]:
    """Expand a target path spec into zero or more concrete paths.

    ``%UserProfiles%`` (and POSIX ``%Home%``) fan the spec out across every
    profile. All other ``%VAR%`` tokens are substituted from *ctx*.
    """
    spec = raw.replace("/", os.sep) if IS_WINDOWS else raw

    profile_token = None
    for token in ("%UserProfiles%", "%Home%"):
        if token.lower() in spec.lower():
            profile_token = token
            break

    bases: list[tuple[str, str]]
    if profile_token:
        bases = [(profile_token, prof) for prof in ctx.user_profiles]
    else:
        bases = [("", "")]

    out: list[str] = []
    for token, value in bases:
        work = spec
        if token:
            work = re.sub(re.escape(token), value.replace("\\", "\\\\"),
                          work, flags=re.IGNORECASE)

        def _sub(m: re.Match[str]) -> str:
            name = m.group(1).lower()
            try:
                return ctx.variables[name]
            except KeyError:
                raise UnknownVariableError(m.group(0))

        work = _VAR_RE.sub(_sub, work)
        work = _rebase(work, ctx.source_root) if not profile_token else work
        out.append(os.path.normpath(work))
    return out
