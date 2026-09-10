"""Line-level parser + event assembly for auditd logs."""

from __future__ import annotations

import binascii
import gzip
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from linux_audit import syscalls as _sc

_HEADER = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\S+)\s+"
    r"msg=audit\((?P<epoch>\d+)\.(?P<ms>\d+):(?P<serial>\d+)\):\s*(?P<body>.*)$")
# key=value  |  key="quoted value"  |  key='quoted'
_KV = re.compile(r"""(\w[\w-]*)=(?:"([^"]*)"|'([^']*)'|(\S+))""")
_AUID_UNSET = {"4294967295", "-1", "unset", "4294967295"}


def _read_lines(path: Path):
    try:
        if path.suffix == ".gz":
            data = gzip.decompress(path.read_bytes())
        else:
            data = path.read_bytes()
    except OSError:
        return
    for ln in data.decode("utf-8", "replace").splitlines():
        ln = ln.strip()
        if ln:
            yield ln


def _maybe_hex(v: str) -> str:
    """auditd hex-encodes any value with spaces / specials; decode it."""
    if len(v) >= 2 and len(v) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", v):
        try:
            raw = binascii.unhexlify(v)
        except binascii.Error:
            return v
        # proctitle / cmdline use NUL as the arg separator
        txt = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        if txt and all(31 < ord(c) or c in " \t" for c in txt):
            return txt
    return v


def _fields(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _KV.finditer(body):
        key = m.group(1)
        val = next(g for g in m.groups()[1:] if g is not None)
        out[key] = val
    return out


@dataclass
class Record:
    rtype: str
    fields: dict
    raw: str = ""


@dataclass
class Event:
    ts: str = ""
    epoch: float = 0.0
    serial: str = ""
    node: str = ""
    types: list = field(default_factory=list)
    action: str = ""            # execve | login | user-cmd | avc | ...
    success: str = ""
    exe: str = ""
    comm: str = ""
    command: str = ""           # reconstructed EXECVE / proctitle / USER_CMD
    cwd: str = ""
    paths: list = field(default_factory=list)
    key: str = ""
    uid: str = ""
    auid: str = ""
    pid: str = ""
    ppid: str = ""
    ses: str = ""
    syscall: str = ""
    actor: str = ""             # acct / user for USER_* records
    addr: str = ""              # decoded SOCKADDR / hostname for USER_*
    result: str = ""
    summary: str = ""
    notable: list = field(default_factory=list)
    log_file: str = ""

    def row(self) -> dict:
        return {
            "ts": self.ts, "serial": self.serial, "action": self.action,
            "success": self.success or self.result, "syscall": self.syscall,
            "exe": self.exe, "comm": self.comm, "command": self.command,
            "cwd": self.cwd, "paths": ";".join(self.paths[:8]), "key": self.key,
            "uid": self.uid, "auid": self.auid, "pid": self.pid,
            "ppid": self.ppid, "ses": self.ses, "actor": self.actor,
            "addr": self.addr, "types": ",".join(self.types),
            "summary": self.summary, "log_file": self.log_file,
            "notable": ";".join(self.notable),
        }


def _iso(epoch: float) -> str:
    try:
        return (datetime.fromtimestamp(epoch, timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    except (ValueError, OverflowError, OSError):
        return ""


def _decode_sockaddr(hexstr: str) -> str:
    try:
        raw = binascii.unhexlify(hexstr)
    except (binascii.Error, ValueError):
        return ""
    if len(raw) < 2:
        return ""
    fam = struct.unpack_from("<H", raw, 0)[0]
    if fam == 2 and len(raw) >= 8:            # AF_INET
        port = struct.unpack_from(">H", raw, 2)[0]
        ip = ".".join(str(b) for b in raw[4:8])
        return f"{ip}:{port}"
    if fam == 10 and len(raw) >= 28:          # AF_INET6
        port = struct.unpack_from(">H", raw, 2)[0]
        groups = struct.unpack_from(">8H", raw, 8)
        ip = ":".join(f"{g:x}" for g in groups)
        return f"[{ip}]:{port}"
    if fam == 1:                              # AF_UNIX
        return "unix:" + raw[2:].split(b"\x00")[0].decode("utf-8", "replace")
    return f"family {fam}"


def parse_line(line: str) -> Record | None:
    m = _HEADER.match(line)
    if not m:
        return None
    f = _fields(m.group("body"))
    # USER_* records nest a second field blob inside msg='...'
    inner = f.get("msg", "")
    if inner and "=" in inner and not inner.isdigit():
        for k, v in _fields(inner).items():
            f.setdefault(k, v)
    f["_epoch"] = m.group("epoch")
    f["_ms"] = m.group("ms")
    f["_serial"] = m.group("serial")
    if m.group("node"):
        f["_node"] = m.group("node")
    return Record(rtype=m.group("type"), fields=f, raw=line)


def _execve_command(f: dict) -> str:
    args = []
    i = 0
    while f"a{i}" in f:
        args.append(_maybe_hex(f[f"a{i}"]))
        i += 1
    return " ".join(args)


def assemble(records: list[Record], log_file: str = "") -> list[Event]:
    by_id: dict[tuple, list[Record]] = {}
    order: list[tuple] = []
    for r in records:
        key = (r.fields.get("_epoch"), r.fields.get("_ms"),
               r.fields.get("_serial"))
        if key not in by_id:
            by_id[key] = []
            order.append(key)
        by_id[key].append(r)

    events: list[Event] = []
    for key in order:
        recs = by_id[key]
        ep = float(f"{key[0]}.{key[1]}") if key[0] else 0.0
        ev = Event(epoch=ep, ts=_iso(ep), serial=key[2] or "",
                   log_file=log_file)
        ev.types = sorted({r.rtype for r in recs})
        merged: dict[str, str] = {}
        for r in recs:
            if r.fields.get("_node"):
                ev.node = r.fields["_node"]
            if r.rtype == "SYSCALL":
                s = r.fields
                ev.syscall = _sc.syscall_name(s.get("arch", ""),
                                              s.get("syscall", ""))
                ev.success = s.get("success", "")
                ev.exe = _maybe_hex(s.get("exe", ""))
                ev.comm = _maybe_hex(s.get("comm", ""))
                ev.key = _maybe_hex(s.get("key", "")).strip('"')
                ev.uid = s.get("uid", "")
                ev.auid = s.get("auid", "")
                ev.pid = s.get("pid", "")
                ev.ppid = s.get("ppid", "")
                ev.ses = s.get("ses", "")
            elif r.rtype == "EXECVE":
                ev.command = _execve_command(r.fields)
            elif r.rtype == "CWD":
                ev.cwd = _maybe_hex(r.fields.get("cwd", ""))
            elif r.rtype == "PATH":
                nm = _maybe_hex(r.fields.get("name", ""))
                if nm:
                    ev.paths.append(nm)
            elif r.rtype == "PROCTITLE":
                if not ev.command:
                    ev.command = _maybe_hex(r.fields.get("proctitle", ""))
            elif r.rtype == "SOCKADDR":
                ev.addr = _decode_sockaddr(r.fields.get("saddr", ""))
            elif r.rtype.startswith("USER") or r.rtype in (
                    "CRED_ACQ", "CRED_DISP", "LOGIN", "ADD_USER", "DEL_USER",
                    "ADD_GROUP", "DEL_GROUP", "CHGRP_ID", "ROLE_ASSIGN",
                    "ROLE_REMOVE", "ACCT_LOCK", "GRP_MGMT"):
                s = r.fields
                ev.actor = (s.get("acct", "") or s.get("id", "")
                            or s.get("user", "")).strip('"')
                ev.addr = ev.addr or s.get("addr", "") or s.get("hostname", "")
                ev.result = s.get("res", "") or s.get("result", "")
                ev.auid = ev.auid or s.get("auid", "")
                ev.uid = ev.uid or s.get("uid", "")
                if not ev.command and s.get("cmd"):
                    ev.command = _maybe_hex(s["cmd"])
                if not ev.key and s.get("op"):
                    ev.key = s["op"].strip('"')
            elif r.rtype == "AVC":
                merged["avc"] = r.fields.get("denied", "") or r.raw
                ev.result = "denied"
            elif r.rtype == "CONFIG_CHANGE":
                ev.key = ev.key or (r.fields.get("op", "")
                                    or "config-change").strip('"')
                ev.result = r.fields.get("res", "")

        ev.action = _classify(ev)
        ev.summary = _summarise(ev, merged)
        events.append(ev)
    return events


def _classify(ev: Event) -> str:
    t = set(ev.types)
    if "EXECVE" in t or ev.syscall in ("execve", "execveat"):
        return "execve"
    if "USER_CMD" in t:
        return "user-cmd"
    if {"USER_AUTH", "USER_ACCT", "USER_LOGIN", "CRED_ACQ"} & t:
        return "auth"
    if "LOGIN" in t:
        return "login"
    if {"ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "GRP_MGMT",
            "ROLE_ASSIGN", "ROLE_REMOVE", "ACCT_LOCK"} & t:
        return "account-change"
    if "AVC" in t:
        return "selinux-denial"
    if "CONFIG_CHANGE" in t:
        return "audit-config"
    if {"SERVICE_START", "SERVICE_STOP"} & t:
        return "service"
    if {"SYSTEM_BOOT", "SYSTEM_SHUTDOWN", "SYSTEM_RUNLEVEL"} & t:
        return "system"
    if ev.syscall in ("connect", "bind"):
        return "network"
    if {"ANOM_ABEND", "ANOM_PROMISCUOUS", "SECCOMP"} & t:
        return "anomaly"
    return (ev.syscall or (ev.types[0].lower() if ev.types else "event"))


def _summarise(ev: Event, merged: dict) -> str:
    if ev.action == "execve":
        base = ev.command or ev.exe or ev.comm
        return f"{base}" + (f"  (cwd {ev.cwd})" if ev.cwd else "")
    if ev.action in ("auth", "login", "user-cmd", "account-change"):
        who = ev.actor or ev.auid or ev.uid
        r = ev.result or ev.success
        bits = [b for b in (who, ev.command, ev.addr, r) if b]
        return " ".join(bits)
    if ev.action == "selinux-denial":
        return merged.get("avc", "SELinux denial")
    if ev.action == "audit-config":
        return f"audit rule change ({ev.key})"
    if ev.action == "network":
        return f"{ev.comm or ev.exe} -> {ev.addr or '?'}"
    return " ".join(b for b in (ev.syscall, ev.exe, ",".join(ev.types)) if b)
