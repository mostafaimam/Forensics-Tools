"""Discover cron / at / systemd-timer sources under a filesystem root."""

from __future__ import annotations

from pathlib import Path

from linux_cron.atjobs import parse as parse_at
from linux_cron.crontab import parse as parse_crontab
from linux_cron.scan import Job
from linux_cron.systemd import build_timer_job

_RUN_PARTS = {
    "cron.hourly": "hourly (run-parts)",
    "cron.daily": "daily (run-parts)",
    "cron.weekly": "weekly (run-parts)",
    "cron.monthly": "monthly (run-parts)",
}

_TIMER_DIRS = [
    "etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system",
    "lib/systemd/system", "etc/systemd/user", "usr/lib/systemd/user",
]

_AT_SPOOL = ["var/spool/cron/atjobs", "var/spool/at", "var/spool/atjobs"]
_AT_SKIP = {".SEQ", ".lockfile", "spool", ".", ".."}


def _read(p: Path) -> str | None:
    try:
        return p.read_text("utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _env_path(env: dict) -> str:
    return env.get("PATH", "")


def _from_crontab(text, *, with_user, source, default_user, file):
    for e in parse_crontab(text, with_user, is_anacron=source == "anacron"):
        j = Job(source=source, run_as=e.run_as or default_user,
                schedule_raw=e.schedule_raw, schedule_desc=e.description,
                command=e.command, env_path=_env_path(e.env),
                reboot=e.reboot, file=str(file), line_no=e.line_no,
                error=e.parse_error)
        j.flag()
        yield j


def collect_root(root: Path):
    """Yield :class:`Job` for every schedule found beneath *root*."""
    jobs: list[Job] = []

    # -- system crontab ------------------------------------------------
    sc = root / "etc/crontab"
    if sc.is_file():
        t = _read(sc)
        if t is not None:
            jobs += _from_crontab(t, with_user=True, source="system-crontab",
                                  default_user="root", file=sc)

    # -- /etc/cron.d -------------------------------------------------
    crond = root / "etc/cron.d"
    if crond.is_dir():
        for f in sorted(crond.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                t = _read(f)
                if t is not None:
                    jobs += _from_crontab(t, with_user=True, source="cron.d",
                                          default_user="root", file=f)

    # -- per-user spool crontabs -----------------------------------
    for spool in ("var/spool/cron/crontabs", "var/spool/cron"):
        d = root / spool
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if f.is_dir() or f.name.startswith("."):
                continue
            t = _read(f)
            if t is not None:
                jobs += _from_crontab(t, with_user=False, source="user-crontab",
                                      default_user=f.name, file=f)

    # -- run-parts script directories --------------------------------
    for name, desc in _RUN_PARTS.items():
        d = root / "etc" / name
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file() or f.name.startswith(".") or f.name == "0anacron":
                continue
            j = Job(source="run-parts", run_as="root", schedule_raw=name,
                    schedule_desc=desc, command=f"/etc/{name}/{f.name}",
                    file=str(f))
            j.flag()
            jobs.append(j)

    # -- anacrontab -------------------------------------------------
    ana = root / "etc/anacrontab"
    if ana.is_file():
        t = _read(ana)
        if t is not None:
            jobs += _from_crontab(t, with_user=False, source="anacron",
                                  default_user="root", file=ana)

    # -- at / batch spool ------------------------------------------
    for spool in _AT_SPOOL:
        d = root / spool
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file() or f.name in _AT_SKIP:
                continue
            t = _read(f)
            if t is None:
                continue
            a = parse_at(f.name, t)
            j = Job(source="at", run_as=(a.uid and f"uid {a.uid}") or "",
                    schedule_raw=f"run once @ {a.run_at_utc}" if a.run_at_utc
                    else a.name,
                    schedule_desc=("batch job" if a.is_batch else "one-shot at job")
                    + (f", queued for {a.run_at_utc}" if a.run_at_utc else ""),
                    command=a.command, file=str(f))
            j.flag()
            jobs.append(j)

    # -- systemd timers ------------------------------------------
    jobs += list(_collect_timers(root))

    return jobs


def _collect_timers(root: Path):
    seen: set[str] = set()
    wants = _timer_wants(root)
    for rel in _TIMER_DIRS:
        d = root / rel
        if not d.is_dir():
            continue
        for f in sorted(d.glob("*.timer")):
            if f.name in seen or not f.is_file():
                continue
            seen.add(f.name)
            text = _read(f)
            if text is None:
                continue

            def resolve(unit_name, _root=root):
                for cand_rel in _TIMER_DIRS:
                    c = _root / cand_rel / unit_name
                    if c.is_file():
                        return _read(c), str(c)
                return None, ""

            tj = build_timer_job(text, f.name, resolve)
            tj.timer_file = str(f)
            enabled = "enabled" if f.name in wants else (
                "disabled" if (root / "etc/systemd/system").exists() else "")
            j = Job(source="systemd-timer", run_as=tj.run_as,
                    schedule_raw=tj.schedule_raw, schedule_desc=tj.description,
                    command=tj.command or f"(triggers {tj.triggers_unit})",
                    enabled=enabled, reboot="Boot" in tj.schedule_raw,
                    file=str(f), error=tj.parse_error)
            j.flag()
            yield j


def _timer_wants(root: Path) -> set[str]:
    out: set[str] = set()
    for base in ("etc/systemd/system", "usr/lib/systemd/system",
                 "lib/systemd/system"):
        d = root / base
        if not d.is_dir():
            continue
        for wd in d.glob("*.wants"):
            if wd.is_dir():
                for link in wd.iterdir():
                    if link.name.endswith(".timer"):
                        out.add(link.name)
    return out


def collect_file(path: Path, kind: str):
    """Parse one explicitly-supplied file. *kind* is one of
    crontab / cron.d / user-crontab / anacrontab / at / timer.
    """
    text = _read(path)
    if text is None:
        return []
    if kind in ("crontab", "cron.d"):
        return list(_from_crontab(text, with_user=True, source=kind or "cron.d",
                                  default_user="root", file=path))
    if kind == "user-crontab":
        return list(_from_crontab(text, with_user=False, source="user-crontab",
                                  default_user=path.name, file=path))
    if kind == "anacrontab":
        return list(_from_crontab(text, with_user=False, source="anacron",
                                  default_user="root", file=path))
    if kind == "at":
        a = parse_at(path.name, text)
        j = Job(source="at", run_as=(a.uid and f"uid {a.uid}") or "",
                schedule_raw=f"run once @ {a.run_at_utc}" if a.run_at_utc
                else a.name, command=a.command, file=str(path))
        j.flag()
        return [j]
    if kind == "timer":
        tj = build_timer_job(text, path.name, lambda _u: (None, ""))
        j = Job(source="systemd-timer", run_as=tj.run_as,
                schedule_raw=tj.schedule_raw, schedule_desc=tj.description,
                command=tj.command or f"(triggers {tj.triggers_unit})",
                file=str(path), error=tj.parse_error)
        j.flag()
        return [j]
    return []


def guess_kind(path: Path) -> str:
    n = path.name.lower()
    parent = path.parent.name.lower()
    if n.endswith(".timer"):
        return "timer"
    if n == "anacrontab":
        return "anacrontab"
    if n == "crontab" or parent == "cron.d":
        return "crontab"
    if parent in ("crontabs", "cron") and "spool" in str(path).lower():
        return "user-crontab"
    if parent in ("atjobs", "at"):
        return "at"
    return "crontab"
