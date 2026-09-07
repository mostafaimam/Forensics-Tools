"""Heuristic flags over a recovered command line."""

from __future__ import annotations

import ntpath
import re

_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_URL_RE = re.compile(r"https?://|ftp://|\\\\[^\\]+\\", re.I)

# lolbins that are almost always suspicious with a network / decode argument
_LOLBINS = {
    "certutil": (r"-urlcache|-decode|-encode|-f\s+-split", "certutil misuse"),
    "bitsadmin": (r"/transfer|/addfile|/create", "bitsadmin transfer"),
    "regsvr32": (r"/i:?\s*http|scrobj\.dll|/s\s+/n\s+/u", "regsvr32 sct/url"),
    "mshta": (r"http|javascript:|vbscript:", "mshta remote/script"),
    "rundll32": (r"javascript:|http|,\s*#?\d+\s*$", "rundll32 script/ordinal"),
    "wmic": (r"process\s+call\s+create|/node:", "wmic remote exec"),
    "msiexec": (r"/i\s+http|/quiet.*http", "msiexec remote package"),
    "cmstp": (r"\.inf|/s", "cmstp inf"),
    "installutil": (r"/logfile=.*/logtoconsole", "installutil proxy exec"),
    "msbuild": (r"\.xml|\.csproj|\.proj", "msbuild inline task"),
    "regasm": (r"/u|\.dll", "regasm proxy exec"),
    "regsvcs": (r"\.dll", "regsvcs proxy exec"),
    "mavinject": (r"/injectrunning|\d+\s+\S+\.dll", "mavinject dll inject"),
    "forfiles": (r"/c\s", "forfiles command exec"),
    "pcalua": (r"-a\s", "pcalua proxy exec"),
    "verclsid": (r"/s\s+/c", "verclsid proxy exec"),
    "dnscmd": (r"/config.*serverlevelplugindll", "dnscmd dll load"),
    "wuauclt": (r"/updatedeploymentprovider|/runhandlercomserver", "wuauclt dll"),
    "odbcconf": (r"/a\s|regsvr", "odbcconf proxy exec"),
}

_PS_NAMES = ("powershell.exe", "powershell", "pwsh.exe", "pwsh")


def _argv0(cmdline: str) -> str:
    s = cmdline.strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[1:end] if end != -1 else s[1:]
    return s.split()[0] if s.split() else ""


def flag(image_path: str, command_line: str) -> list[str]:
    out: list[str] = []
    cl = command_line or ""
    low = cl.lower()
    exe = ntpath.basename(_argv0(cl)).lower() or ntpath.basename(
        image_path).lower()

    # PowerShell
    if exe in _PS_NAMES or "powershell" in low or "pwsh" in low:
        if re.search(r"\s-e(nc(odedcommand)?|c)\b|\s-e\s", low):
            out.append("powershell-encoded")
        if re.search(r"-w(indowstyle)?\s+(hidden|1)\b|-w\s+h", low):
            out.append("powershell-hidden")
        if re.search(r"-nop(rofile)?\b", low):
            out.append("powershell-noprofile")
        if re.search(r"-e(xec(utionpolicy)?)?\s+bypass|-ep\s+bypass", low):
            out.append("powershell-bypass")
        if re.search(r"\b(iex|invoke-expression|downloadstring|downloadfile|"
                     r"frombase64string|invoke-webrequest|net\.webclient|"
                     r"start-bitstransfer)\b", low):
            out.append("powershell-download-exec")

    # generic LOLBins
    for name, (pat, label) in _LOLBINS.items():
        if (exe.startswith(name) or f"\\{name}" in low
                or low.startswith(name)) and re.search(pat, low):
            out.append(label)

    # base64 blob on the command line
    m = _B64_RE.search(cl)
    if m and len(m.group(0)) >= 60:
        out.append("base64-blob")

    # a URL / UNC path on a non-browser command line
    if _URL_RE.search(cl) and exe not in (
            "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
            "brave.exe", "opera.exe", "curl.exe", "wget.exe"):
        out.append("url-in-cmdline")

    # the executable itself runs from a user-writable directory
    _uw = re.compile(r"\\(users|appdata|temp|programdata|downloads|public|"
                     r"perflogs|\$recycle\.bin)\\", re.I)
    if _uw.search(image_path or "") or _uw.search(_argv0(cl)):
        out.append("user-writable-path")

    # argv0 basename disagrees with the real image (masquerade / hollow)
    a0 = ntpath.basename(_argv0(cl)).lower()
    ip = ntpath.basename(image_path or "").lower()
    if a0 and ip and a0 != ip and a0.endswith(".exe") and ip.endswith(".exe"):
        out.append("argv0-mismatch")

    # unusually long command line
    if len(cl) > 1500:
        out.append("very-long-cmdline")

    return out


_SEVERITY = {
    "powershell-encoded": 3, "powershell-download-exec": 3, "base64-blob": 3,
    "certutil misuse": 3, "bitsadmin transfer": 3, "regsvr32 sct/url": 3,
    "mshta remote/script": 3, "wmic remote exec": 3, "mavinject dll inject": 3,
    "msbuild inline task": 3, "dnscmd dll load": 3,
    "argv0-mismatch": 3,
    "powershell-hidden": 2, "powershell-bypass": 2, "url-in-cmdline": 2,
    "rundll32 script/ordinal": 2, "msiexec remote package": 2,
    "cmstp inf": 2, "installutil proxy exec": 2, "user-writable-path": 2,
    "regasm proxy exec": 2, "regsvcs proxy exec": 2, "verclsid proxy exec": 2,
    "forfiles command exec": 2, "pcalua proxy exec": 2, "odbcconf proxy exec": 2,
    "wuauclt dll": 2, "very-long-cmdline": 2,
    "powershell-noprofile": 1,
}


def severity(notable: list[str]) -> str:
    if not notable:
        return "none"
    top = max(_SEVERITY.get(n, 1) for n in notable)
    return {3: "high", 2: "medium", 1: "low"}[top]
