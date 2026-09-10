"""Heuristic flags for a launchd job."""

from __future__ import annotations

import re

_WRITABLE = re.compile(
    r"^/(tmp|private/tmp|var/tmp|var/folders|Users/[^/]+|Users/Shared|"
    r"Library/Caches|private/var/tmp)/", re.I)
_INLINE = re.compile(r"\b(sh|bash|zsh|dash)\b\s+-[a-z]*c\b|"
                     r"\bosascript\b\s+-e\b|\bpython[0-9.]*\b\s+-c\b|"
                     r"\bperl\b\s+-e\b|\bruby\b\s+-e\b|\beval\b", re.I)
_CRADLE = re.compile(r"\b(curl|wget|nscurl)\b[^|;&]*[|;&]\s*(sudo\s+)?"
                     r"(sh|bash|zsh|python[0-9.]*|osascript|ruby|perl)\b",
                     re.I)
_ENCODED = re.compile(r"\bbase64\s+(-D|--decode|-d)\b|\becho\s+[A-Za-z0-9+/]"
                      r"{40,}=*\s*\|\s*base64|\\x[0-9a-f]{2}|\bxxd\s+-r\b",
                      re.I)
_SCRIPTY = re.compile(r"\.(sh|bash|zsh|command|scpt|applescript|py|pl|rb|"
                      r"js|jxa)($|\s)", re.I)
_APPLE_LABEL = re.compile(r"^com\.apple\.", re.I)


def flag(j) -> list[str]:
    out: list[str] = []
    prog = j.program or ""
    cmd = j.command_line or ""

    if prog and _WRITABLE.match(prog):
        out.append(f"program in a user-writable path ({prog})")
    if _CRADLE.search(cmd):
        out.append("download / execute cradle in the command")
    elif _INLINE.search(cmd):
        out.append("inline shell / interpreter in the command")
    if _ENCODED.search(cmd):
        out.append("encoded / obfuscated payload in the command")
    if _SCRIPTY.search(prog) or (j.arguments and _SCRIPTY.search(
            " ".join(j.arguments[:2]))):
        out.append("runs a shell / AppleScript / interpreter script")

    for k in j.env:
        if k.upper().startswith("DYLD_") or k.upper() == "LD_PRELOAD":
            out.append(f"sets a dynamic-loader variable ({k}) - dylib "
                       f"injection")
            break

    if j.label and j.filename and not j.disabled:
        stem = j.filename.rsplit(".plist", 1)[0]
        if stem and j.label != stem and stem not in j.label:
            out.append(f"Label '{j.label}' does not match the plist file "
                       f"name '{j.filename}'")
    if _APPLE_LABEL.match(j.label or "") and j.scope != "apple":
        out.append("Label masquerades as an Apple job (com.apple.*) but is "
                   "not under /System/Library")

    _standard = prog.lower().startswith(
        ("/usr/", "/system/", "/applications/", "/library/apple/"))
    if j.run_at_load and j.keep_alive and not j.disabled \
            and j.scope != "apple" and not _standard:
        out.append("RunAtLoad + KeepAlive respawner from a non-standard "
                   "program path")
    if j.scope == "system-daemon" and (j.run_as in ("", "root")) and \
            prog and _WRITABLE.match(prog):
        out.append("root daemon executes from a user-writable path")
    if j.stdout_path.startswith(("/tmp/", "/private/tmp/")) or \
            j.stderr_path.startswith(("/tmp/", "/private/tmp/")):
        out.append("stdout / stderr redirected to /tmp")
    if j.world_writable:
        out.append("the job plist is group/other-writable")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "program in a user-writable path": "high",
    "download / execute cradle in the command": "high",
    "inline shell / interpreter in the command": "medium",
    "encoded / obfuscated payload in the command": "high",
    "runs a shell / AppleScript / interpreter script": "low",
    "sets a dynamic-loader variable": "high",
    "Label '": "medium",
    "Label masquerades as an Apple job": "high",
    "RunAtLoad + KeepAlive respawner from a non-standard": "low",
    "root daemon executes from a user-writable path": "high",
    "stdout / stderr redirected to /tmp": "low",
    "the job plist is group/other-writable": "high",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
