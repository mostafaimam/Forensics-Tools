"""Turn interesting log lines into structured security events."""

from __future__ import annotations

import re
from dataclasses import dataclass

from linux_syslog.parser import LogRecord


@dataclass
class Event:
    timestamp: object
    category: str          # ssh | sudo | su | session | cron | account | pam
    action: str
    result: str = ""       # success | failure | ""
    user: str = ""
    target_user: str = ""
    source_ip: str = ""
    source_port: str = ""
    tty: str = ""
    command: str = ""
    detail: str = ""
    host: str = ""
    tag: str = ""
    source_file: str = ""
    line_no: int = 0


def _base(rec: LogRecord, **kw) -> Event:
    return Event(timestamp=rec.timestamp, host=rec.host, tag=rec.tag,
                 source_file=rec.source_file, line_no=rec.line_no, **kw)


# each rule: (tag matches, compiled regex on message, handler(rec, match)->Event)
_RULES: list = []


def _rule(tags, pattern):
    rx = re.compile(pattern)
    tagset = tags if isinstance(tags, tuple) else (tags,)

    def deco(fn):
        _RULES.append((tagset, rx, fn))
        return fn
    return deco


# ---- sshd ---------------------------------------------------------------
@_rule("sshd", r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")
def _ssh_ok(rec, m):
    return _base(rec, category="ssh", action="login", result="success",
                 user=m.group(2), source_ip=m.group(3), source_port=m.group(4),
                 detail=f"method={m.group(1)}")


@_rule("sshd", r"^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)")
def _ssh_fail(rec, m):
    return _base(rec, category="ssh", action="login", result="failure",
                 user=m.group(3), source_ip=m.group(4), source_port=m.group(5),
                 detail=f"method={m.group(1)}"
                 + ("; invalid user" if m.group(2) else ""))


@_rule("sshd", r"^Invalid user (\S+) from (\S+)(?: port (\d+))?")
def _ssh_invalid(rec, m):
    return _base(rec, category="ssh", action="invalid-user", result="failure",
                 user=m.group(1), source_ip=m.group(2),
                 source_port=m.group(3) or "")


@_rule("sshd", r"^(?:Disconnected from|Connection closed by|Connection reset by) "
               r"(?:authenticating |invalid )?(?:user (\S+) )?(\S+) port (\d+)"
               r"(?:.*\[preauth\])?")
def _ssh_disc(rec, m):
    pre = "[preauth]" in rec.message
    return _base(rec, category="ssh",
                 action="disconnect" + ("-preauth" if pre else ""),
                 user=m.group(1) or "", source_ip=m.group(2),
                 source_port=m.group(3))


@_rule("sshd", r"maximum authentication attempts exceeded for (invalid user )?"
               r"(\S+) from (\S+) port (\d+)")
def _ssh_maxauth(rec, m):
    return _base(rec, category="ssh", action="max-auth-attempts",
                 result="failure", user=m.group(2), source_ip=m.group(3),
                 source_port=m.group(4))


@_rule("sshd", r"message repeated (\d+) times: \[ Failed (\S+) for "
               r"(invalid user )?(\S+) from (\S+) port (\d+)")
def _ssh_repeat(rec, m):
    return _base(rec, category="ssh", action="login", result="failure",
                 user=m.group(4), source_ip=m.group(5), source_port=m.group(6),
                 detail=f"repeated {m.group(1)}x")


# ---- sudo --------------------------------------------------------------
@_rule("sudo", r"^\s*(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ;(?: GROUP=\S+ ;)?"
               r"(?: TSID=\S+ ;)? COMMAND=(.*)$")
def _sudo_run(rec, m):
    return _base(rec, category="sudo", action="run", result="success",
                 user=m.group(1), tty=m.group(2), target_user=m.group(4),
                 command=m.group(5), detail=f"pwd={m.group(3)}")


@_rule("sudo", r"^\s*(\S+) : (\d+) incorrect password attempt")
def _sudo_badpw(rec, m):
    return _base(rec, category="sudo", action="auth", result="failure",
                 user=m.group(1), detail=f"{m.group(2)} incorrect attempts")


@_rule("sudo", r"^\s*(\S+) : (user NOT in sudoers|command not allowed|"
               r"\d+ incorrect password attempts?|user not allowed to execute)")
def _sudo_deny(rec, m):
    return _base(rec, category="sudo", action="denied", result="failure",
                 user=m.group(1), detail=m.group(2))


# ---- su ----------------------------------------------------------------
@_rule(("su", "su-l"), r"(?:pam_unix\(su(?:-l)?:auth\): )?authentication failure;"
                       r".*?(?:ruser=(\S+))?.*?(?:user=(\S+))?$")
def _su_fail(rec, m):
    return _base(rec, category="su", action="auth", result="failure",
                 user=(m.group(1) or "").strip("<>") or "",
                 target_user=(m.group(2) or ""), detail=rec.message[:200])


@_rule(("su", "su-l"),
       r"(?:\+|-) (\S+) (\S+):(\S+)$|Successful su for (\S+) by (\S+)|"
       r"FAILED su for (\S+) by (\S+)")
def _su_switch(rec, m):
    if m.group(1) is not None:
        ok = rec.message.startswith("+")
        return _base(rec, category="su", action="switch",
                     result="success" if ok else "failure",
                     user=m.group(2), target_user=m.group(3), tty=m.group(1))
    if m.group(4) is not None:
        return _base(rec, category="su", action="switch", result="success",
                     target_user=m.group(4), user=m.group(5))
    return _base(rec, category="su", action="switch", result="failure",
                 target_user=m.group(6), user=m.group(7))


# ---- systemd-logind / sessions --------------------------------------
@_rule(("systemd-logind", "systemd"),
       r"New session (\S+) of user (\S+)\.")
def _sess_new(rec, m):
    return _base(rec, category="session", action="open",
                 user=m.group(2), detail=f"session {m.group(1)}")


@_rule(("systemd-logind", "systemd"), r"Removed session (\S+)\.")
def _sess_rm(rec, m):
    return _base(rec, category="session", action="close",
                 detail=f"session {m.group(1)}")


@_rule(("systemd-logind", "systemd"),
       r"Session (\S+) logged out\. Waiting for processes to exit\.")
def _sess_logout(rec, m):
    return _base(rec, category="session", action="logout",
                 detail=f"session {m.group(1)}")


# ---- cron ------------------------------------------------------------
@_rule(("CRON", "cron", "crond"),
       r"pam_unix\(cron:session\): session (opened|closed) for user (\S+)")
def _cron_sess(rec, m):
    return _base(rec, category="cron", action=f"session-{m.group(1)}",
                 user=m.group(2))


@_rule(("CRON", "cron", "crond"), r"^\((\S+)\) CMD \((.*)\)$")
def _cron_cmd(rec, m):
    return _base(rec, category="cron", action="run", user=m.group(1),
                 command=m.group(2))


# ---- login (tty) ---------------------------------------------------
@_rule("login", r"FAILED LOGIN .*FROM (\S+) FOR (\S+)")
def _login_fail(rec, m):
    return _base(rec, category="session", action="tty-login", result="failure",
                 user=m.group(2), source_ip=m.group(1))


@_rule("login", r"ROOT LOGIN\s+on '(\S+)'")
def _login_root(rec, m):
    return _base(rec, category="session", action="tty-login", result="success",
                 user="root", tty=m.group(1))


# ---- account management --------------------------------------------
@_rule("useradd", r"new user: name=(\S+?),? UID=(\d+),? GID=(\d+),? "
                  r"home=(\S+?),? shell=(\S+)")
def _useradd(rec, m):
    return _base(rec, category="account", action="user-add", target_user=m.group(1),
                 detail=f"uid={m.group(2)} gid={m.group(3)} shell={m.group(5)}")


@_rule("userdel", r"delete user '(\S+)'")
def _userdel(rec, m):
    return _base(rec, category="account", action="user-delete",
                 target_user=m.group(1))


@_rule("usermod", r"(add '(\S+)' to group '(\S+)'|change user '(\S+)' password)")
def _usermod(rec, m):
    if m.group(2):
        return _base(rec, category="account", action="group-add",
                     target_user=m.group(2), detail=f"group={m.group(3)}")
    return _base(rec, category="account", action="passwd-change",
                 target_user=m.group(4))


@_rule(("passwd", "chpasswd"), r"password (?:changed|updated) for (\S+)")
def _passwd(rec, m):
    return _base(rec, category="account", action="passwd-change",
                 target_user=m.group(1))


@_rule(("groupadd", "groupdel"), r"(new group|group removed): name=(\S+?),?")
def _group(rec, m):
    act = "group-add" if m.group(1) == "new group" else "group-delete"
    return _base(rec, category="account", action=act, target_user=m.group(2))


# ---- generic PAM ---------------------------------------------------
_PAM_RE = re.compile(
    r"pam_unix\(([\w-]+):(auth|session|account)\): (authentication failure|"
    r"session opened|session closed|account expired|"
    r"check pass; user unknown|\d+ more authentication failures)"
    r"(.*)$")
_PAM_KV = re.compile(r"(\brhost|\bruser|\buser|\btty|\blogname)=(\S+)")


@_rule(None, r"pam_unix\(")
def _pam(rec, m):
    pm = _PAM_RE.search(rec.message)
    if not pm:
        return None
    svc, phase, what, rest = pm.groups()
    kv = dict(_PAM_KV.findall(rest))
    result = "failure" if "failure" in what or "unknown" in what \
        or "expired" in what else ("success" if "opened" in what else "")
    action = {"authentication failure": "auth-failure",
              "session opened": "session-open",
              "session closed": "session-close"}.get(what, what)
    return _base(rec, category="pam", action=f"{svc}:{action}", result=result,
                 user=kv.get("user", kv.get("logname", "")),
                 source_ip=kv.get("rhost", ""), tty=kv.get("tty", ""),
                 detail=what if action == what else "")


def extract(rec: LogRecord) -> Event | None:
    if rec.timestamp is None or not rec.message:
        return None
    tag = rec.tag
    base_tag = tag.split("(")[0] if tag else ""
    for tagset, rx, fn in _RULES:
        if tagset[0] is not None and base_tag not in tagset and tag not in tagset:
            continue
        m = rx.search(rec.message)
        if m:
            ev = fn(rec, m)
            if ev is not None:
                return ev
    return None
