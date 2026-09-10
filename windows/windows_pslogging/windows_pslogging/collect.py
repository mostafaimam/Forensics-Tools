"""Discover EVTX + transcripts under a path and build script records."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from windows_pslogging import decode as _decode
from windows_pslogging import flags as _flags
from windows_pslogging.evtx import EvtxError, parse_evtx

_PS_CHANNELS = ("Microsoft-Windows-PowerShell/Operational",
                "Windows PowerShell", "PowerShellCore/Operational")
_EVTX_NAMES = re.compile(
    r"(Microsoft-Windows-PowerShell.*Operational|Windows PowerShell|"
    r"PowerShellCore.*Operational)\.evtx$", re.I)
_TRANSCRIPT = re.compile(r"PowerShell_transcript\..*\.txt$", re.I)


@dataclass
class Script:
    kind: str                  # scriptblock | module | classic | transcript
    time: str
    computer: str
    user: str
    host_app: str
    event_id: str
    scriptblock_id: str
    path: str                  # on-disk script path if known
    text: str                  # decoded
    raw_text: str
    fragments: int
    decode_notes: list
    source: str
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "time": self.time, "kind": self.kind, "event_id": self.event_id,
            "computer": self.computer, "user": self.user,
            "host_app": self.host_app, "path": self.path,
            "scriptblock_id": self.scriptblock_id,
            "fragments": self.fragments,
            "decoded": ";".join(self.decode_notes),
            "text": self.text[:20000],
            "source": self.source, "notable": ";".join(self.notable),
        }


@dataclass
class Result:
    scripts: list = field(default_factory=list)
    evtx_files: int = 0
    transcripts: int = 0
    events_4104: int = 0
    events_4103: int = 0
    errors: list = field(default_factory=list)


def _norm_time(t: str) -> str:
    if not t:
        return ""
    t = t.replace(" ", "T")
    t = re.sub(r"\.0+Z$", "Z", t)
    t = re.sub(r"(\.\d+?)0+Z$", r"\1Z", t)
    if not t.endswith("Z") and re.search(r"T\d\d:\d\d:\d\d$", t):
        t += "Z"
    return t


def _sysver(text: str) -> str:
    m = re.search(r"psversion\s*[:=]\s*([\d.]+)", text, re.I)
    return m.group(1) if m else ""


def _from_evtx(data: bytes, source: str, res: Result):
    frags: dict[str, list[tuple[int, str]]] = {}
    frag_meta: dict[str, dict] = {}
    try:
        events = list(parse_evtx(data))
    except EvtxError as e:
        res.errors.append(f"{source}: {e}")
        return

    for r in events:
        d = {k.split("/")[-1] if k else k: v for k, v in r.data.items()}
        eid = str(r.event_id)
        if eid == "4104":
            res.events_4104 += 1
            sbid = str(d.get("ScriptBlockId", "") or "")
            try:
                num = int(d.get("MessageNumber", "1") or 1)
                total = int(d.get("MessageTotal", "1") or 1)
            except ValueError:
                num, total = 1, 1
            frags.setdefault(sbid, []).append(
                (num, str(d.get("ScriptBlockText", "") or "")))
            etime = r.time_created_utc or r.timestamp_utc
            meta = frag_meta.setdefault(sbid, {
                "time": etime, "_num": num,
                "computer": r.computer, "user": r.user_id,
                "path": str(d.get("Path", "") or ""), "total": total})
            # anchor the record time to the earliest fragment (message 1)
            if num < meta.get("_num", num + 1):
                meta["_num"] = num
                meta["time"] = etime
        elif eid == "4103":
            res.events_4103 += 1
            ctx = str(d.get("ContextInfo", "") or "")
            payload = str(d.get("Payload", "") or "")
            host = _kv(ctx, "Host Application") or _kv(ctx, "Host Name")
            user = _kv(ctx, "User")
            body = "\n".join(x for x in (
                _kv(ctx, "Command Name"), payload,
                str(d.get("CommandInvocation", "") or "")) if x)
            _add_script(res, "module", r, "4103", "", host, user,
                        str(d.get("CommandPath", "") or ""), body, source)
        elif eid in ("400", "403", "500", "501", "600"):
            ctx = str(d.get("param3", "") or d.get("Payload", "") or "")
            host = _kv(ctx, "HostApplication") or _kv(ctx, "Host Application")
            body = str(d.get("param2", "") or d.get("Payload", "") or ctx)
            _add_script(res, "classic", r, eid, "", host, "", "", body,
                        source)

    for sbid, parts in frags.items():
        parts.sort()
        raw = "".join(p[1] for p in parts)
        meta = frag_meta.get(sbid, {})
        text, notes = _decode.decode_payloads(raw)
        sc = Script(
            kind="scriptblock", time=_norm_time(meta.get("time", "")),
            computer=meta.get("computer", ""), user=meta.get("user", ""),
            host_app="", event_id="4104", scriptblock_id=sbid,
            path=meta.get("path", ""), text=text, raw_text=raw,
            fragments=len(parts), decode_notes=notes, source=source)
        sc.notable = _flags.flag(text)
        res.scripts.append(sc)


def _kv(block: str, key: str) -> str:
    m = re.search(rf"^\s*{re.escape(key)}\s*[:=]\s*(.+?)\s*$", block, re.M | re.I)
    return m.group(1).strip() if m else ""


def _add_script(res, kind, r, eid, sbid, host, user, path, body, source):
    text, notes = _decode.decode_payloads(body)
    sc = Script(kind=kind,
                time=_norm_time(r.time_created_utc or r.timestamp_utc),
                computer=r.computer, user=user or r.user_id, host_app=host,
                event_id=eid, scriptblock_id=sbid, path=path, text=text,
                raw_text=body, fragments=1, decode_notes=notes, source=source)
    sc.notable = _flags.flag(text)
    res.scripts.append(sc)


def _from_transcript(text: str, source: str, res: Result):
    hdr = {}
    for key in ("Username", "RunAs User", "Machine", "Host Application",
                "Process ID", "PSVersion", "Start time", "Configuration Name"):
        v = _kv(text, key)
        if v:
            hdr[key] = v
    body = re.split(r"\*+\s*\n", text, maxsplit=1)
    payload = body[-1] if len(body) > 1 else text
    dec, notes = _decode.decode_payloads(payload)
    t = ""
    m = re.search(r"(\d{8}|\d{4}-?\d\d-?\d\d)[ T]?(\d\d[:]?\d\d[:]?\d\d)",
                  hdr.get("Start time", ""))
    if m:
        d8, tt = m.group(1).replace("-", ""), m.group(2).replace(":", "")
        t = f"{d8[:4]}-{d8[4:6]}-{d8[6:8]}T{tt[:2]}:{tt[2:4]}:{tt[4:6]}Z"
    sc = Script(kind="transcript", time=t,
                computer=hdr.get("Machine", ""),
                user=hdr.get("Username", "") or hdr.get("RunAs User", ""),
                host_app=hdr.get("Host Application", ""), event_id="",
                scriptblock_id="", path=source, text=dec, raw_text=payload,
                fragments=1, decode_notes=notes, source=source)
    sc.notable = _flags.flag(dec)
    res.scripts.append(sc)


def collect(paths) -> Result:
    res = Result()
    for path in paths:
        p = Path(path)
        targets: list[Path] = []
        if p.is_file():
            targets = [p]
        else:
            for f in p.rglob("*"):
                if not f.is_file():
                    continue
                if _EVTX_NAMES.search(f.name) or _TRANSCRIPT.search(f.name):
                    targets.append(f)
        for f in targets:
            try:
                data = f.read_bytes()
            except OSError as e:
                res.errors.append(f"{f}: {e}")
                continue
            if _TRANSCRIPT.search(f.name):
                res.transcripts += 1
                _from_transcript(data.decode("utf-8", "replace"), str(f), res)
            else:
                res.evtx_files += 1
                _from_evtx(data, str(f), res)

    res.scripts.sort(key=lambda s: (s.time or "", s.kind))
    return res
