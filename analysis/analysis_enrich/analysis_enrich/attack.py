"""Bundled MITRE ATT&CK technique map for the patterns the suite emits."""

from __future__ import annotations

import re

# (compiled pattern, [(technique id, name), ...])
_MAP = [
    (r"schtasks\b.*/create|Register-ScheduledTask|New-ScheduledTask|"
     r"windows_tasks",
     [("T1053.005", "Scheduled Task")]),
    (r"__EventFilter|CommandLineEventConsumer|FilterToConsumerBinding|"
     r"windows_wmi",
     [("T1546.003", "WMI Event Subscription")]),
    (r"\bInjectDll\b|RedirectEXE|\.sdb\b|windows_sdb",
     [("T1546.011", "Application Shimming")]),
    (r"CurrentVersion\\\\Run|Winlogon\\\\Shell|Userinit|windows_bam",
     [("T1547.001", "Registry Run Keys / Startup Folder")]),
    (r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{16,}|FromBase64String",
     [("T1059.001", "PowerShell"), ("T1027", "Obfuscated Files or "
                                    "Information")]),
    (r"\bpowershell(?:\.exe)?\b|windows_pslogging",
     [("T1059.001", "PowerShell")]),
    (r"\bcmd(?:\.exe)?\b\s+/c|\bcmd(?:\.exe)?\b\s+/k",
     [("T1059.003", "Windows Command Shell")]),
    (r"\b(wscript|cscript)\b|\.vbs\b|\.jse?\b",
     [("T1059.005", "Visual Basic"), ("T1059.007", "JavaScript")]),
    (r"\bmshta\b|\.hta\b", [("T1218.005", "Mshta")]),
    (r"\brundll32\b", [("T1218.011", "Rundll32")]),
    (r"\bregsvr32\b", [("T1218.010", "Regsvr32")]),
    (r"Net\.WebClient|Invoke-WebRequest|DownloadString|DownloadFile|"
     r"Start-BitsTransfer|bitsadmin|certutil\b.*-urlcache|windows_bits",
     [("T1105", "Ingress Tool Transfer")]),
    (r"AmsiUtils|amsiInitFailed|AmsiScanBuffer|ETW.*bypass|EtwEventWrite",
     [("T1562.001", "Disable or Modify Tools")]),
    (r"DisableRealtimeMonitoring|DisableAntiSpyware|Add-MpPreference.*"
     r"Exclusion|windows_defender.*(tamper|exclusion)",
     [("T1562.001", "Disable or Modify Tools")]),
    (r"wevtutil\s+cl|Clear-EventLog|event\s*1102|log\s+was\s+cleared",
     [("T1070.001", "Clear Windows Event Logs")]),
    (r"fsutil\s+usn\s+deletejournal|Clear-History|ConsoleHost_history",
     [("T1070", "Indicator Removal")]),
    (r"\bsdelete\b|cipher\s+/w|\bbleachbit\b|secure\s*delete",
     [("T1485", "Data Destruction"), ("T1070.004", "File Deletion")]),
    (r"timestomp|\$SI.*\$FN|SetFileTime|zeroed sub-second",
     [("T1070.006", "Timestomp")]),
    (r"Invoke-Mimikatz|sekurlsa|lsadump|MiniDumpWriteDump|comsvcs\.dll.*"
     r"MiniDump|lsass\.dmp",
     [("T1003.001", "LSASS Memory")]),
    (r"\bntdsutil\b|\bNTDS\.dit\b|DCSync|GetNCChanges",
     [("T1003.006", "DCSync")]),
    (r"Invoke-Kerberoast|Rubeus.*kerberoast|\bGetUserSPNs\b",
     [("T1558.003", "Kerberoasting")]),
    (r"reg\s+save.*SAM|reg\s+save.*SYSTEM|\\\\SAM\b.*\\\\SYSTEM",
     [("T1003.002", "Security Account Manager")]),
    (r"\bwhoami\b|\bnltest\b|net\s+group\b|net\s+localgroup|"
     r"Get-ADUser|Get-DomainUser|net\s+user\b",
     [("T1087", "Account Discovery")]),
    (r"\bnetstat\b|\bipconfig\b|\barp\s+-a\b|Get-NetTCPConnection",
     [("T1049", "System Network Connections Discovery")]),
    (r"\bvssadmin\b.*delete\s+shadows|Win32_ShadowCopy.*Delete|"
     r"wmic\s+shadowcopy\s+delete",
     [("T1490", "Inhibit System Recovery")]),
    (r"New-Service\b|sc\.exe\s+create|windows_srvc|7045",
     [("T1543.003", "Windows Service")]),
    (r"\brdp\b|3389|mstsc|windows_sum.*remote desktop",
     [("T1021.001", "Remote Desktop Protocol")]),
    (r"\\\\[^\s\\]+\\(C\$|ADMIN\$|IPC\$)|net\s+use\s+\\\\",
     [("T1021.002", "SMB/Windows Admin Shares")]),
    (r"\bPsExec\b|\bpaexec\b|\bwinexe\b",
     [("T1569.002", "Service Execution")]),
    (r"quarantine|MOTW|Zone\.Identifier|windows_recycle",
     [("T1553.005", "Mark-of-the-Web Bypass")]),
    (r"\.rar\b|\.7z\b|\.zip\b.*password|Compress-Archive.*-Password|"
     r"rar\.exe\s+a\s+-p",
     [("T1560.001", "Archive via Utility")]),
]

_COMPILED = [(re.compile(p, re.I), t) for p, t in _MAP]


def tag(text: str) -> list[tuple[str, str]]:
    hits: dict[str, str] = {}
    for rx, techs in _COMPILED:
        if rx.search(text):
            for tid, name in techs:
                hits[tid] = name
    return sorted(hits.items())
