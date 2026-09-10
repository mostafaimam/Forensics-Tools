"""Synthetic .wer report files."""

from __future__ import annotations

# EventTime 133560000000000000 -> 2024-01-08ish; use a 2026 value
_T = 133_845_408_000_000_000       # ~2025-03

CRASH_EVIL = """\
Version=1
EventType=APPCRASH
EventTime={t}
Consent=1
ReportIdentifier=6f0b2c11-evil
ReportStatus=268435456
Response.type=4
FriendlyEventName=Stopped working
AppPath=C:\\Users\\victim\\AppData\\Local\\Temp\\svch0st.exe
TargetAppId=W:0000abcd
Sig[0].Name=Application Name
Sig[0].Value=svch0st.exe
Sig[1].Name=Application Version
Sig[1].Value=0.0.0.0
Sig[2].Name=Application Timestamp
Sig[2].Value=00000000
Sig[3].Name=Fault Module Name
Sig[3].Value=vbscript.dll
Sig[4].Name=Fault Module Version
Sig[4].Value=5.812.10240.16384
Sig[6].Name=Exception Code
Sig[6].Value=c0000005
Sig[7].Name=Exception Offset
Sig[7].Value=0002a1b2
DynamicSig[1].Name=OS Version
DynamicSig[1].Value=10.0.19045.2.0.0.256.48
DynamicSig[2].Name=Locale ID
DynamicSig[2].Value=1033
LoadedModule[0]=C:\\Users\\victim\\AppData\\Local\\Temp\\svch0st.exe
LoadedModule[1]=C:\\Windows\\SYSTEM32\\ntdll.dll
LoadedModule[2]=C:\\Windows\\SysWOW64\\vbscript.dll
""".format(t=_T)

BEX_REPORT = """\
Version=1
EventType=BEX64
EventTime={t}
Consent=1
ReportIdentifier=aa11-bex
AppPath=C:\\Program Files\\Acme\\reader.exe
Sig[0].Name=Application Name
Sig[0].Value=reader.exe
Sig[1].Name=Application Version
Sig[1].Value=21.1.0.0
Sig[3].Name=Fault Module Name
Sig[3].Value=acmecore.dll
Sig[7].Name=Exception Code
Sig[7].Value=c0000409
""".format(t=_T)

HANG_BENIGN = """\
Version=1
EventType=APPHANG
EventTime={t}
Consent=1
ReportIdentifier=bb22-hang
AppPath=C:\\Windows\\explorer.exe
Sig[0].Name=Application Name
Sig[0].Value=explorer.exe
Sig[1].Name=Application Version
Sig[1].Value=10.0.19045.3803
""".format(t=_T)


def utf16(text: str) -> bytes:
    return b"\xff\xfe" + text.replace("\n", "\r\n").encode("utf-16-le")


def write_store(root):
    q = root / "ReportQueue" / "AppCrash_svch0st_1"
    q.mkdir(parents=True)
    (q / "Report.wer").write_bytes(utf16(CRASH_EVIL))
    a = root / "ReportArchive" / "AppHang_explorer_2"
    a.mkdir(parents=True)
    (a / "Report.wer").write_bytes(utf16(HANG_BENIGN))
    (root / "reader.wer").write_bytes(utf16(BEX_REPORT))
    return root
