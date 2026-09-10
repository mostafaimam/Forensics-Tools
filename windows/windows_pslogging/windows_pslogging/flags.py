"""Heuristic flags for a (decoded) PowerShell script."""

from __future__ import annotations

import re

_RULES = [
    ("download / execute cradle", "high", re.compile(
        r"\b(Net\.WebClient|Invoke-WebRequest|iwr\b|Invoke-RestMethod|irm\b|"
        r"DownloadString|DownloadFile|DownloadData|Start-BitsTransfer|"
        r"bitsadmin|certutil\b.*-urlcache|\bcurl\b|\bwget\b|"
        r"System\.Net\.Http)", re.I)),
    ("AMSI / ETW bypass string", "high", re.compile(
        r"(amsiInitFailed|AmsiUtils|AmsiScanBuffer|"
        r"System\.Management\.Automation\.Amsi|"
        r"\[Ref\]\.Assembly\.GetType|EtwEventWrite|"
        r"PSEtwLogProvider|amsiContext)", re.I)),
    ("reflective / in-memory assembly load", "high", re.compile(
        r"(\[Reflection\.Assembly\]::Load|\[System\.Reflection\.Assembly\]|"
        r"\bAdd-Type\b.*-TypeDefinition|VirtualAlloc|"
        r"System\.Runtime\.InteropServices\.Marshal|GetDelegateForFunction"
        r"Pointer|WriteProcessMemory|CreateRemoteThread)", re.I)),
    ("hidden window / no profile / EP bypass", "medium", re.compile(
        r"(-W(indowStyle)?\s+hidden|-nop\b|-NoProfile|"
        r"-Exec(utionPolicy)?\s+Bypass|-noni|-NonInteractive|"
        r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{16,})", re.I)),
    ("reverse shell / raw socket", "high", re.compile(
        r"(Net\.Sockets\.TCPClient|Net\.Sockets\.UDPClient|"
        r"System\.Net\.Sockets|\bGetStream\(\)|"
        r"\$client\s*=\s*New-Object\s+Net\.Sockets)", re.I)),
    ("credential / LSASS access", "high", re.compile(
        r"(Invoke-Mimikatz|mimikatz|sekurlsa|Get-Credential|"
        r"MiniDumpWriteDump|comsvcs\.dll.*MiniDump|lsass\.dmp|"
        r"Out-Minidump|Invoke-NinjaCopy|Get-KeystrokeInput|"
        r"GetAsyncKeyState|SharpHound|Invoke-BloodHound|"
        r"Get-DomainUser|Invoke-Kerberoast|Rubeus)", re.I)),
    ("obfuscation markers", "medium", re.compile(
        r"(\-join\s*\(|\[char\[\]\]|\[string\]\[char\]|"
        r"-f\s*['\"]|\$\{[a-z]{1,3}\}|`e`|`\$|"
        r"\[Convert\]::ToChar|-replace\s+['\"][^'\"]{1,3}['\"]\s*,)", re.I)),
    ("IEX / dynamic execution", "medium", re.compile(
        r"(Invoke-Expression|\bIEX\b|\biex\b|"
        r"&\s*\(\s*\$|\.Invoke\(\)|ScriptBlock\]::Create)", re.I)),
    ("persistence via scheduled task / WMI / registry Run", "high",
     re.compile(r"(schtasks\b.*/create|Register-ScheduledTask|"
                r"New-ScheduledTask|__EventFilter|CommandLineEventConsumer|"
                r"Set-ItemProperty.*(CurrentVersion\\Run|Winlogon)|"
                r"New-Service\b|sc\.exe\s+create)", re.I)),
    ("clears event logs / history", "high", re.compile(
        r"(Clear-EventLog|wevtutil\s+cl\b|Remove-Item.*ConsoleHost_history|"
        r"Clear-History|Set-PSReadlineOption.*-HistorySaveStyle\s+SaveNothing)",
        re.I)),
]


def flag(text: str) -> list[str]:
    out: list[str] = []
    for name, _sev, rx in _RULES:
        if rx.search(text):
            m = rx.search(text)
            snippet = re.sub(r"\s+", " ", m.group(0))[:60]
            out.append(f"{name} ({snippet})")
    # heavy backtick / concatenation density
    if text and (text.count("`") + text.count("+")) / max(len(text), 1) > 0.03:
        out.append("high concatenation / escape-character density "
                   "(obfuscation)")
    return out


_SEV = {name: sev for name, sev, _ in _RULES}
_SEV["high concatenation / escape-character density"] = "medium"


def severity(notable) -> str:
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    top = "none"
    for n in notable:
        for k, v in _SEV.items():
            if n.startswith(k) and order[v] > order[top]:
                top = v
    return top
