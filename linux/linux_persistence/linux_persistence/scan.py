"""The persistence-vector sweep."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---- suspicious-content patterns -----------------------------------------
_CRADLE = re.compile(r"\b(curl|wget|fetch)\b[^|;&]*[|;&]\s*(sudo\s+)?"
                     r"(bash|sh|dash|zsh|python[0-9.]*|perl|ruby)\b", re.I)
_INLINE = re.compile(r"\b(bash|sh|dash|nc|ncat|socat|python[0-9.]*|perl)\b"
                     r"\s+-[a-z]*(c|e|i)\b", re.I)
_ENCODED = re.compile(r"\bbase64\s+-d\b|\bxxd\s+-r\b|\beval\b|\\x[0-9a-f]{2}"
                      r"|`[^`]+`|\$\([^)]+\)", re.I)
_REVSHELL = re.compile(r"/dev/tcp/|/dev/udp/|bash\s+-i|mkfifo|"
                       r"0<&\d|>&\s*/dev/tcp", re.I)
_WRITABLE_PATH = re.compile(r"(/tmp/|/var/tmp/|/dev/shm/|/home/[^/\s:]+/|"
                            r"/run/user/\d+/)")
_LD_HIJACK = re.compile(r"\bLD_PRELOAD\b|\bLD_LIBRARY_PATH\b|\bLD_AUDIT\b")

_SEV_ORDER = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4}


@dataclass
class Finding:
    mechanism: str
    path: str
    line_no: int = 0
    payload: str = ""
    mtime: str = ""
    owner_uid: str = ""
    world_writable: bool = False
    verdict: str = "info"
    why: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "mechanism": self.mechanism, "path": self.path,
            "line": self.line_no or "", "payload": self.payload,
            "mtime": self.mtime, "owner_uid": self.owner_uid,
            "world_writable": "yes" if self.world_writable else "",
            "verdict": self.verdict, "why": ";".join(self.why),
        }


@dataclass
class Result:
    findings: list = field(default_factory=list)
    files_seen: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def _stat(p: Path):
    try:
        st = p.stat()
        mt = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        ww = os.name != "nt" and bool(st.st_mode & stat.S_IWOTH)
        return mt, str(st.st_uid if os.name != "nt" else ""), ww
    except OSError:
        return "", "", False


def _read(p: Path) -> list[str] | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _content_flags(text: str) -> list[str]:
    out = []
    if _REVSHELL.search(text):
        out.append("reverse-shell pattern")
    if _CRADLE.search(text):
        out.append("download / execute cradle")
    if _INLINE.search(text):
        out.append("inline interpreter (-c / -e / -i)")
    if _ENCODED.search(text):
        out.append("encoded / indirected payload")
    if _WRITABLE_PATH.search(text):
        out.append("references a user-writable path")
    return out


def _verdict(why: list[str], world_writable: bool) -> str:
    if any(w in ("reverse-shell pattern", "download / execute cradle")
           for w in why):
        return "high"
    if world_writable:
        return "high"
    if any(w.startswith(("inline interpreter", "encoded", "loader"))
           for w in why):
        return "medium"
    if why:
        return "low"
    return "info"


# ---- per-mechanism collectors ------------------------------------------

_SHELL_SYS = ["etc/profile", "etc/bash.bashrc", "etc/zsh/zshrc",
              "etc/zsh/zprofile", "etc/csh.login"]
_SHELL_USER = [".bashrc", ".bash_profile", ".bash_login", ".profile",
               ".zshrc", ".zprofile", ".zlogin", ".bash_logout",
               ".bash_aliases", ".kshrc"]


def _emit(res: Result, mech: str, p: Path, *, whole_file=False,
          line_patterns=None):
    lines = _read(p)
    if lines is None:
        return
    res.files_seen.append(str(p))
    mt, uid, ww = _stat(p)
    joined = "\n".join(lines)
    if whole_file:
        why = _content_flags(joined)
        if why or ww:
            payload = _first_signal(lines) or (lines[0][:200] if lines else "")
            f = Finding(mech, str(p), 0, payload, mt, uid, ww)
            f.why = why + (["world-writable config"] if ww else [])
            f.verdict = _verdict(f.why, ww)
            res.findings.append(f)
        return
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        why = _content_flags(s)
        if line_patterns:
            for rx, tag in line_patterns:
                if rx.search(s):
                    why.append(tag)
        if not why and not ww:
            continue
        f = Finding(mech, str(p), i, s[:200], mt, uid, ww,
                    why=why + (["world-writable config"] if ww else []))
        f.verdict = _verdict(f.why, ww)
        res.findings.append(f)


def _first_signal(lines):
    for ln in lines:
        if _content_flags(ln.strip()):
            return ln.strip()[:200]
    return ""


def _glob(root: Path, *rels):
    for r in rels:
        yield from sorted(root.glob(r))


def scan(root_str: str) -> Result:
    res = Result()
    root = Path(root_str)

    # shell rc / profile
    for rel in _SHELL_SYS:
        p = root / rel
        if p.is_file():
            _emit(res, "shell-rc", p)
    for p in _glob(root, "etc/profile.d/*"):
        if p.is_file():
            _emit(res, "profile.d", p)
    for home in _home_dirs(root):
        for name in _SHELL_USER:
            p = home / name
            if p.is_file():
                _emit(res, "shell-rc", p)

    # /etc/environment
    p = root / "etc/environment"
    if p.is_file():
        _emit(res, "environment", p, line_patterns=[(_LD_HIJACK,
              "loader variable set in /etc/environment")])

    # dynamic loader
    p = root / "etc/ld.so.preload"
    if p.is_file():
        lines = _read(p) or []
        res.files_seen.append(str(p))
        mt, uid, ww = _stat(p)
        for i, ln in enumerate(lines, 1):
            s = ln.strip()
            if not s or s.startswith("#"):
                continue
            why = ["ld.so.preload entry (loads into every dynamically-linked "
                   "process)"]
            why += _content_flags(s)
            f = Finding("ld.so.preload", str(p), i, s, mt, uid, ww, why=why)
            f.verdict = "high"
            res.findings.append(f)
    for p in [root / "etc/ld.so.conf"] + list(_glob(root,
                                                    "etc/ld.so.conf.d/*")):
        if p.is_file():
            _emit(res, "ld.so.conf", p, line_patterns=[(_WRITABLE_PATH,
                  "library path under a writable directory")])

    # rc.local / init scripts
    for rel in ("etc/rc.local", "etc/rc.d/rc.local", "etc/init.d/boot.local"):
        p = root / rel
        if p.is_file():
            _emit(res, "rc.local", p, whole_file=True)
    for p in _glob(root, "etc/init.d/*"):
        if p.is_file() and p.name not in ("skeleton", "README"):
            _emit(res, "init.d", p, whole_file=True)

    # motd
    for p in _glob(root, "etc/update-motd.d/*"):
        if p.is_file():
            _emit(res, "update-motd.d", p, whole_file=True)

    # xinetd / inetd
    for p in [root / "etc/xinetd.conf", root / "etc/inetd.conf"] + \
            list(_glob(root, "etc/xinetd.d/*")):
        if p.is_file():
            _emit(res, "xinetd", p, line_patterns=[
                (re.compile(r"\bserver\s*=\s*(\S+)"), "inetd service binary")])
            for f in res.findings:
                if f.path == str(p) and "references a user-writable path" \
                        in f.why and f.verdict in ("info", "low"):
                    f.verdict = "medium"

    # PAM
    for p in _glob(root, "etc/pam.d/*"):
        if p.is_file():
            _scan_pam(res, p)

    # kernel modules
    for p in [root / "etc/modules"] + list(_glob(
            root, "etc/modules-load.d/*", "etc/modprobe.d/*")):
        if p.is_file():
            _emit(res, "kernel-module", p, line_patterns=[
                (re.compile(r"^\s*install\s+\S+\s+.*(/bin/|/tmp/|\bsh\b|"
                            r"\bbash\b|curl|wget)"),
                 "modprobe install= runs a command"),
                (re.compile(r"^\s*install\s+\S+\s+/bin/(true|false)\b"),
                 "module disabled via 'install ... /bin/true'")])

    # udev
    for p in _glob(root, "etc/udev/rules.d/*", "lib/udev/rules.d/*",
                   "run/udev/rules.d/*"):
        if p.is_file():
            _emit(res, "udev-rule", p, line_patterns=[
                (re.compile(r'RUN[+{]', re.I), "udev RUN{} action"),
                (re.compile(r'PROGRAM\s*==?', re.I), "udev PROGRAM action")])
            for f in res.findings:
                if f.path == str(p) and f.verdict in ("info", "low"):
                    if any("RUN{}" in w or "PROGRAM" in w for w in f.why):
                        f.verdict = "medium"
                    if "references a user-writable path" in f.why:
                        f.verdict = "high"

    # sudoers
    for p in [root / "etc/sudoers"] + list(_glob(root, "etc/sudoers.d/*")):
        if p.is_file():
            _scan_sudoers(res, p)

    # systemd generators + light system-unit pass
    for p in _glob(root, "etc/systemd/system-generators/*",
                   "usr/local/lib/systemd/system-generators/*"):
        if p.is_file():
            lines = _read(p) or []
            res.files_seen.append(str(p))
            mt, uid, ww = _stat(p)
            why = ["non-standard systemd generator (runs at every daemon-reload"
                   " as root)"] + _content_flags("\n".join(lines))
            f = Finding("systemd-generator", str(p), 0,
                        _first_signal(lines) or (lines[0][:200] if lines
                                                 else ""),
                        mt, uid, ww, why=why)
            f.verdict = "high"
            res.findings.append(f)

    res.findings.sort(key=lambda f: (-_SEV_ORDER[f.verdict], f.mechanism,
                                     f.path))
    return res


def _home_dirs(root: Path):
    out = []
    if (root / "root").is_dir():
        out.append(root / "root")
    if (root / "home").is_dir():
        out += [d for d in (root / "home").iterdir() if d.is_dir()]
    return out


_PAM_STD = {"pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_env.so",
            "pam_limits.so", "pam_systemd.so", "pam_loginuid.so",
            "pam_keyinit.so", "pam_namespace.so", "pam_selinux.so",
            "pam_mail.so", "pam_motd.so", "pam_lastlog.so", "pam_nologin.so",
            "pam_securetty.so", "pam_faildelay.so", "pam_pwquality.so",
            "pam_faillock.so", "pam_cracklib.so", "pam_rootok.so",
            "pam_wheel.so", "pam_group.so", "pam_tty_audit.so",
            "pam_umask.so", "pam_gnome_keyring.so", "pam_ecryptfs.so",
            "pam_krb5.so", "pam_sss.so", "pam_ldap.so", "pam_winbind.so",
            "pam_access.so", "pam_time.so", "pam_exec.so", "pam_succeed_if.so",
            "pam_google_authenticator.so", "pam_u2f.so", "pam_fprintd.so",
            "pam_cap.so", "pam_localuser.so", "pam_mkhomedir.so",
            "pam_gdm.so", "pam_kwallet5.so"}


def _scan_pam(res: Result, p: Path):
    lines = _read(p)
    if lines is None:
        return
    res.files_seen.append(str(p))
    mt, uid, ww = _stat(p)
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        m = re.search(r"(pam_[\w.]+\.so|/\S+\.so)", s)
        if not m:
            continue
        mod = m.group(1)
        why = []
        if mod.startswith("/") or _WRITABLE_PATH.search(mod):
            why.append(f"PAM module by absolute / non-standard path ({mod})")
        elif mod not in _PAM_STD:
            why.append(f"unrecognised PAM module ({mod})")
        if "pam_exec.so" in s:
            why.append("pam_exec.so runs an external program on auth")
        if ww:
            why.append("world-writable config")
        if not why:
            continue
        f = Finding("pam", str(p), i, s[:200], mt, uid, ww, why=why)
        f.verdict = "high" if (mod.startswith("/") or "pam_exec" in s) \
            else _verdict(why, ww)
        res.findings.append(f)


def _scan_sudoers(res: Result, p: Path):
    lines = _read(p)
    if lines is None:
        return
    res.files_seen.append(str(p))
    mt, uid, ww = _stat(p)
    for i, ln in enumerate(lines, 1):
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("Defaults"):
            if "!authenticate" in s:
                f = Finding("sudoers", str(p), i, s[:200], mt, uid, ww,
                            why=["Defaults !authenticate (sudo without a "
                                 "password prompt)"])
                f.verdict = "high"
                res.findings.append(f)
            continue
        why = []
        nopass = "NOPASSWD" in s
        grants_all = bool(re.search(r"=\s*\([^)]*\)\s*(NOPASSWD:\s*)?ALL\s*$",
                                    s))
        shell_cmd = bool(re.search(
            r"(/bin/(ba)?sh|/bin/dash|/usr/bin/(python[0-9.]*|perl|env|vi|"
            r"vim|nano|less|more|man|find|awk|tee|tar|systemctl|apt|dpkg|"
            r"docker|nmap))\b", s))
        if nopass:
            why.append("NOPASSWD rule")
        if nopass and grants_all:
            why.append("grants NOPASSWD access to ALL commands")
        if nopass and shell_cmd:
            why.append("NOPASSWD on a command that can spawn a shell")
        if _WRITABLE_PATH.search(s):
            why.append("references a user-writable path")
        if ww:
            why.append("world-writable config")
        if not why:
            continue
        f = Finding("sudoers", str(p), i, s[:200], mt, uid, ww, why=why)
        if any("NOPASSWD access to ALL" in w or "spawn a shell" in w
               for w in why):
            f.verdict = "high"
        else:
            f.verdict = _verdict(why, ww)
        res.findings.append(f)
