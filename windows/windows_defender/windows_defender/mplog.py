"""Parser for Defender ``MPLog-*.log`` support logs.

MPLog is a semi-structured text log written by the Defender engine.  It has
no single grammar; this parser pulls the lines that carry forensic value:

* detections            - ``DETECTIONEVENT`` / ``DETECTION`` / ``THREAT``
* process activity      - ``ProcessImageName:`` RTP performance rows and
                          ``Lowfi:`` / ``EMS`` scan lines that name an image
* exclusion use         - ``EXCLUSION`` lines
* on-demand scan spans  - ``BEGIN``/``END`` blocks

Everything else is ignored.  Each returned record keeps the raw line so an
analyst can go back to it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
_FILE = re.compile(r"(?:file|path|Path|ImagePath):\s*"
                   r"([A-Za-z]:\\[^\s,\"]+|\\Device\\[^\s,\"]+|\\\\[^\s,\"]+)")
_PROC = re.compile(r"ProcessImageName:\s*([^,]+),\s*Pid:\s*(\d+)", re.I)
_LOWFI = re.compile(r"Lowfi:\s*\[?(.+?)\]?\s*$", re.I)
_THREAT = re.compile(r"\b(?:Threat|ThreatName|detection)\b[:=]?\s*"
                     r"([A-Za-z]+:[A-Za-z0-9_/.\-]+)")
_DETNAME = re.compile(r"\b([A-Za-z][A-Za-z0-9]*:"
                      r"(?:Win32|Win64|MSIL|Script|PowerShell|HTML|O97M|"
                      r"X97M|Linux|AndroidOS|MacOS|Python|Java|Behavior|"
                      r"PUA)/[A-Za-z0-9_.!\-]+)")


@dataclass
class MpEntry:
    time: str
    kind: str          # detection | process | lowfi | exclusion | scan
    threat: str
    path: str
    pid: str
    detail: str
    source: str

    def row(self) -> dict:
        return {
            "kind": f"mplog-{self.kind}", "time": self.time,
            "threat": self.threat, "path": self.path, "pid": self.pid,
            "detail": self.detail[:400], "source": self.source,
        }


def _norm_ts(t: str) -> str:
    if not t:
        return ""
    t = t.replace(" ", "T")
    t = re.sub(r"(\.\d+)Z?$", "", t)
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", t):
        return t + "Z"
    return t + ("" if t.endswith("Z") else "Z")


def parse_mplog(text: str, source: str) -> list[MpEntry]:
    out: list[MpEntry] = []
    cur_ts = ""
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = _TS.search(s)
        if m and s.startswith(m.group(1)[:4]):
            cur_ts = _norm_ts(m.group(1))
        ts = _norm_ts(m.group(1)) if m else cur_ts

        up = s.upper()
        fm = _FILE.search(s)
        path = fm.group(1) if fm else ""
        tm = _DETNAME.search(s) or _THREAT.search(s)
        threat = tm.group(1) if tm else ""

        if "DETECTIONEVENT" in up or up.startswith("DETECTION") or \
                "DETECTIONADDED" in up or (threat and "THREAT" in up):
            out.append(MpEntry(ts, "detection", threat, path, "", s, source))
        elif "EXCLUSION" in up and ("added" in s.lower() or "config" in s.lower()
                                    or "path" in s.lower()):
            out.append(MpEntry(ts, "exclusion", "", path, "", s, source))
        else:
            pm = _PROC.search(s)
            if pm:
                out.append(MpEntry(ts, "process", threat,
                                   pm.group(1).strip(), pm.group(2), s, source))
                continue
            lm = _LOWFI.search(s)
            if lm:
                lpath = path
                if not lpath:
                    fm2 = _FILE.search(lm.group(1))
                    lpath = fm2.group(1) if fm2 else ""
                out.append(MpEntry(ts, "lowfi", threat, lpath, "", s, source))
            elif up.startswith("BEGIN ") or up.startswith("END "):
                out.append(MpEntry(ts, "scan", "", "", "", s, source))
            elif threat:
                out.append(MpEntry(ts, "detection", threat, path, "", s,
                                   source))
    return out
