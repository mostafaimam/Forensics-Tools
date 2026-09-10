"""Parse the dslocal user / group plists."""

from __future__ import annotations

import datetime as _dt
import plistlib
from dataclasses import dataclass, field
from pathlib import Path

from macos_dslocal import flags as _flags


def _first(d: dict, key: str, default: str = "") -> str:
    v = d.get(key)
    if isinstance(v, list) and v:
        return str(v[0])
    if v is None:
        return default
    return str(v)


def _iso(v) -> str:
    if isinstance(v, _dt.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=_dt.timezone.utc)
        return v.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ""


@dataclass
class User:
    name: str
    uid: int
    gid: int
    realname: str
    home: str
    shell: str
    generateduid: str
    hint: str
    auth_mechanisms: list
    pbkdf2_iterations: int
    created: str
    last_login: str
    last_failed_login: str
    failed_count: int
    password_last_set: str
    groups: list = field(default_factory=list)
    is_admin: bool = False
    source: str = ""
    notable: list = field(default_factory=list)

    def row(self) -> dict:
        return {
            "name": self.name, "uid": self.uid, "gid": self.gid,
            "realname": self.realname, "home": self.home, "shell": self.shell,
            "generateduid": self.generateduid, "hint": self.hint,
            "auth": ",".join(self.auth_mechanisms),
            "pbkdf2_iterations": self.pbkdf2_iterations or "",
            "created": self.created, "last_login": self.last_login,
            "last_failed_login": self.last_failed_login,
            "failed_count": self.failed_count or "",
            "password_last_set": self.password_last_set,
            "groups": ",".join(self.groups),
            "is_admin": "yes" if self.is_admin else "",
            "source": self.source, "notable": ";".join(self.notable),
        }


def _auth_mechs(d: dict) -> tuple[list[str], int]:
    mechs: list[str] = []
    aa = d.get("authentication_authority") or []
    aa = aa if isinstance(aa, list) else [aa]
    text = " ".join(str(x) for x in aa)
    if "ShadowHash" in text:
        mechs.append("ShadowHash")
    if "Kerberos" in text or "KerberosKeys" in d:
        mechs.append("Kerberos")
    if "SecureToken" in text:
        mechs.append("SecureToken")
    if ";SRP;" in text or "HeimdalSRPKey" in d:
        mechs.append("SRP")
    if ";DisabledUser;" in text:
        mechs.append("DISABLED")
    passwd = _first(d, "passwd")
    if passwd and passwd not in ("*", "********", ""):
        mechs.append("crypt-hash")
    if not mechs and not passwd:
        mechs.append("none")

    iters = 0
    shd = d.get("ShadowHashData")
    blob = shd[0] if isinstance(shd, list) and shd else shd
    if isinstance(blob, (bytes, bytearray)):
        try:
            inner = plistlib.loads(bytes(blob))
            entry = inner.get("SALTED-SHA512-PBKDF2") or {}
            iters = int(entry.get("iterations", 0) or 0)
        except Exception:                        # noqa: BLE001
            pass
    return mechs, iters


def _account_policy(d: dict) -> dict:
    apd = d.get("accountPolicyData")
    blob = apd[0] if isinstance(apd, list) and apd else apd
    if not isinstance(blob, (bytes, bytearray)):
        return {}
    try:
        p = plistlib.loads(bytes(blob))
    except Exception:                            # noqa: BLE001
        return {}

    def when(key):
        v = p.get(key)
        try:
            if v:
                return _dt.datetime.fromtimestamp(
                    float(v), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OverflowError, OSError):
            pass
        return ""
    return {
        "created": when("creationTime"),
        "last_login": when("lastLoginTimestamp"),
        "last_failed_login": when("failedLoginTimestamp"),
        "failed_count": int(p.get("failedLoginCount", 0) or 0),
        "password_last_set": when("passwordLastSetTime"),
    }


def parse_user(data: bytes, source: str) -> User | None:
    try:
        d = plistlib.loads(data)
    except Exception:                            # noqa: BLE001
        return None
    if not isinstance(d, dict) or "name" not in d:
        return None
    mechs, iters = _auth_mechs(d)
    ap = _account_policy(d)
    try:
        uid = int(_first(d, "uid", "-1"))
    except ValueError:
        uid = -1
    try:
        gid = int(_first(d, "gid", "-1"))
    except ValueError:
        gid = -1
    return User(
        name=_first(d, "name"), uid=uid, gid=gid,
        realname=_first(d, "realname"), home=_first(d, "home"),
        shell=_first(d, "shell"), generateduid=_first(d, "generateduid"),
        hint=_first(d, "hint"), auth_mechanisms=mechs,
        pbkdf2_iterations=iters,
        created=ap.get("created", ""), last_login=ap.get("last_login", ""),
        last_failed_login=ap.get("last_failed_login", ""),
        failed_count=ap.get("failed_count", 0),
        password_last_set=ap.get("password_last_set", ""),
        source=source)


@dataclass
class Group:
    name: str
    gid: int
    members: list
    realname: str


def parse_group(data: bytes) -> Group | None:
    try:
        d = plistlib.loads(data)
    except Exception:                            # noqa: BLE001
        return None
    if not isinstance(d, dict) or "name" not in d:
        return None
    members = [str(m) for m in (d.get("users") or [])]
    try:
        gid = int(_first(d, "gid", "-1"))
    except ValueError:
        gid = -1
    return Group(name=_first(d, "name"), gid=gid, members=members,
                 realname=_first(d, "realname"))


@dataclass
class Result:
    users: list = field(default_factory=list)
    groups: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def collect(root: str) -> Result:
    res = Result()
    base = Path(root)
    if base.is_file():
        u = parse_user(base.read_bytes(), str(base))
        if u:
            res.users.append(u)
        return _finish(res)

    node = None
    for rel in ("private/var/db/dslocal/nodes/Default",
                "var/db/dslocal/nodes/Default", "nodes/Default", "Default"):
        p = base / rel
        if p.is_dir():
            node = p
            break
    if node is None and (base / "users").is_dir():
        node = base

    if node is None:
        res.errors.append("no dslocal node (nodes/Default) found")
        return res

    for p in sorted((node / "users").glob("*.plist")) \
            if (node / "users").is_dir() else []:
        try:
            u = parse_user(p.read_bytes(), str(p))
        except OSError as e:
            res.errors.append(f"{p}: {e}")
            continue
        if u:
            res.users.append(u)
    for p in sorted((node / "groups").glob("*.plist")) \
            if (node / "groups").is_dir() else []:
        try:
            g = parse_group(p.read_bytes())
        except OSError:
            continue
        if g:
            res.groups.append(g)
    return _finish(res)


def _finish(res: Result) -> Result:
    admin_members: set[str] = set()
    member_map: dict[str, list[str]] = {}
    for g in res.groups:
        for m in g.members:
            member_map.setdefault(m, []).append(g.name)
        if g.name == "admin" or g.gid == 80:
            admin_members.update(g.members)
    for u in res.users:
        u.groups = sorted(member_map.get(u.name, []))
        u.is_admin = u.name in admin_members
        u.notable = _flags.flag(u)
    res.users.sort(key=lambda u: u.uid)
    return res
