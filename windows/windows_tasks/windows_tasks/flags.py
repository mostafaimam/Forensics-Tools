"""Heuristic flags for a joined task record."""

from __future__ import annotations

import re

_LOLBIN = re.compile(
    r"\b(mshta|rundll32|regsvr32|wscript|cscript|powershell|pwsh|"
    r"certutil|bitsadmin|msbuild|installutil|regasm|regsvcs|"
    r"cmstp|msiexec|wmic|forfiles|conhost|hh|ieexec|"
    r"scriptrunner|explorer|verclsid)\b", re.I)
_WRITABLE = re.compile(
    r"(\\users\\|\\appdata\\|\\temp\\|\\tmp\\|\\programdata\\|\\public\\|"
    r"\\downloads\\|\\\$recycle\.bin\\|\\perflogs\\)", re.I)
_ENCODED = re.compile(r"-e(nc(odedcommand)?)?\b\s+[A-Za-z0-9+/=]{16,}|"
                      r"\bfrombase64string\b|\b-w\s+hidden\b|"
                      r"\biex\b|\binvoke-expression\b|\[char\]|"
                      r"\bdownloadstring\b|\bdownloadfile\b", re.I)
_UNC = re.compile(r"(^|[\s\"'=])\\\\[^\\]+\\")
_SYSTEM_SIDS = {"s-1-5-18", "system", "localsystem", "s-1-5-19", "s-1-5-20"}
_MS_PREFIX = re.compile(r"^\\Microsoft\\Windows\\", re.I)


def flag(rec) -> list[str]:
    """rec: a dict-like task row (see output.row)."""
    out: list[str] = []
    cmd = rec.get("command_line", "") or ""
    actions = rec.get("actions", "") or cmd
    path = rec.get("task_path", "") or rec.get("uri", "")
    run_as = (rec.get("run_as", "") or "").lower()
    run_level = (rec.get("run_level", "") or "").lower()

    if _LOLBIN.search(actions):
        m = _LOLBIN.search(actions)
        out.append(f"living-off-the-land binary in the action ({m.group(1)})")
    if _WRITABLE.search(actions):
        out.append("action runs from a user-writable path")
    if _UNC.search(actions):
        out.append("action runs from a UNC path")
    if _ENCODED.search(actions):
        out.append("encoded / obfuscated command line")
    if "comhandler" in (rec.get("action_kinds", "") or "").lower() or \
            actions.startswith("COM "):
        out.append("ComHandler action (in-process COM object, not an exe)")

    if rec.get("hidden") in (True, "yes", "true"):
        out.append("task is hidden")

    if path and not _MS_PREFIX.match(path) and path.count("\\") <= 2:
        out.append(f"registered outside \\Microsoft\\Windows ({path})")

    if run_as in _SYSTEM_SIDS and _WRITABLE.search(actions):
        out.append("runs as SYSTEM from a user-writable path")
    if run_level == "highestavailable" and _WRITABLE.search(actions):
        out.append("elevated (HighestAvailable) task from a user-writable path")

    if rec.get("registry_only") in (True, "yes"):
        out.append("registry-only task (TaskCache entry with no XML on disk)")
    if rec.get("xml_only") in (True, "yes"):
        out.append("XML-only task (no TaskCache registry entry)")
    if rec.get("tree_missing") in (True, "yes"):
        out.append("in TaskCache\\Tasks but absent from the Tree (hidden from "
                   "schtasks / Task Scheduler UI)")

    if not (rec.get("author") or "").strip() and path and \
            not _MS_PREFIX.match(path):
        out.append("no author recorded")

    name = (rec.get("name", "") or "")
    if re.search(r"(update|adobe|google|microsoft|windows|onedrive|defender)",
                 name, re.I) and path and not _MS_PREFIX.match(path):
        out.append("Microsoft-looking name registered outside "
                   "\\Microsoft\\Windows")

    seen: set = set()
    return [n for n in out if not (n in seen or seen.add(n))]


_SEV = {
    "living-off-the-land binary": "high",
    "action runs from a user-writable path": "high",
    "action runs from a UNC path": "high",
    "encoded / obfuscated command line": "high",
    "ComHandler action": "medium",
    "task is hidden": "medium",
    "registered outside": "medium",
    "runs as SYSTEM from a user-writable path": "high",
    "elevated (HighestAvailable) task from a user-writable path": "high",
    "registry-only task": "high",
    "XML-only task": "low",
    "in TaskCache\\Tasks but absent from the Tree": "high",
    "no author recorded": "low",
    "Microsoft-looking name registered outside": "high",
}


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
